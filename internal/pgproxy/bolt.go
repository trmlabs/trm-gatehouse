package pgproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Infisical/agent-vault/internal/auditchain"
	"github.com/Infisical/agent-vault/internal/bolt"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/runtimestatus"
)

// This file is the broker's Bolt path, for graph databases such as Memgraph.
// It shares the PostgreSQL listener: a connection whose first bytes after the
// sidecar's preamble are Bolt's magic is served here, so Bolt needs no port,
// Service or network policy of its own. Admission is the PostgreSQL path's:
// the same identity check, catalog grant and tier decision, caps, session
// ledger and audit trail. The sidecar sends the catalog entry's name as the
// Bolt principal and the worker's identity proof as the credential; the
// worker itself only ever sends a placeholder.

// GraphService is a graph database an agent may reach over Bolt.
type GraphService struct {
	Name       string // catalog entry name
	Addr       string // upstream host:port
	ServerName string // the name verified on the server certificate; empty means the host
	CA         string // PEM certificates trusted alone for the server; empty uses the system roots
	// Plaintext dials without TLS. The catalog allows it only for a
	// cluster-local host in a test deployment.
	Plaintext bool
	MaxConns  int // per-database connection budget (0 = the broker's default)
	// KeyMount and KeyPath name the KV secret holding the broker's login,
	// fields username and password.
	KeyMount, KeyPath string
	// Procedures and Functions are the procedures and module functions a
	// query may call; every other one is refused.
	Procedures []string
	Functions  []string
	// Write is the entry's write access: graph writes run and commit. The
	// rest of the guard still holds (no file loads, no commits of their own,
	// only the listed procedures and functions, no system queries). Without
	// it every transaction is a read the broker rolls back.
	Write bool
}

func sameGraph(a, b GraphService) bool {
	return a.Name == b.Name && a.Addr == b.Addr && a.ServerName == b.ServerName && a.CA == b.CA && a.Plaintext == b.Plaintext &&
		a.KeyMount == b.KeyMount && a.KeyPath == b.KeyPath && slices.Equal(a.Procedures, b.Procedures) && slices.Equal(a.Functions, b.Functions) &&
		a.Write == b.Write
}

// GraphResolver selects the graph database an authorized agent asks for by
// name, as DatabaseResolver does for PostgreSQL. A *RefusedError is the
// authorization model's refusal; any other error means no such entry.
type GraphResolver interface {
	ResolveGraph(ctx context.Context, scope AgentScope, name string) (*GraphService, error)
}

// GraphLogin is the login the broker uses for a graph database. It never
// reaches an agent and is never logged.
type GraphLogin struct{ Username, Password string }

// GraphLogins reads a graph database's login, from Vault in production.
type GraphLogins interface {
	GraphLogin(ctx context.Context, svc *GraphService) (*GraphLogin, error)
}

// defaultMaxBoltMessageBytes bounds one Bolt message in either direction,
// such as a RUN with a large parameter list or one large record
// (AGENT_VAULT_BOLT_MAX_MESSAGE_BYTES).
const defaultMaxBoltMessageBytes = 64 << 20

// boltUserAgent names the broker to the database.
const boltUserAgent = "gatehouse-broker/1"

// boltServerAgent is what the broker tells a client it is talking to.
const boltServerAgent = "Neo4j/5.2.0 compatible graph database server - Memgraph through Gatehouse"

// boltRefusal is a FAILURE the broker authors. The code's second part is the
// driver's classification: TransientError is retried, ClientError is not.
type boltRefusal struct{ code, reason, message string }

var (
	boltAuthentication = boltRefusal{"Gatehouse.ClientError.Security.Unauthorized", "authentication", "Gatehouse could not verify this worker"}
	boltBusy           = boltRefusal{"Gatehouse.TransientError.General.Busy", "admission_timeout", "Gatehouse is at capacity; retry shortly"}
	boltCapacity       = boltRefusal{"Gatehouse.TransientError.General.Busy", "capacity", "Gatehouse is at capacity; retry shortly"}
	boltActorLimit     = boltRefusal{"Gatehouse.TransientError.General.SessionCap", "actor_limit", "this worker reached its session cap"}
	boltDatabaseLimit  = boltRefusal{"Gatehouse.TransientError.General.DatabaseBudget", "database_limit", "the database's Gatehouse connection budget is full; retry shortly"}
	boltLedger         = boltRefusal{"Gatehouse.TransientError.General.Unavailable", "ledger_unavailable", "Gatehouse session accounting is unavailable; retry shortly"}
	boltAudit          = boltRefusal{"Gatehouse.TransientError.General.AuditUnavailable", "audit_unavailable", "Gatehouse's audit trail is unavailable; retry shortly"}
	boltNoDatabase     = boltRefusal{"Gatehouse.ClientError.Database.DatabaseNotFound", "no_database", "this database isn't in the Gatehouse catalog for your pool"}
	boltCredential     = boltRefusal{"Gatehouse.TransientError.General.CredentialUnavailable", "credential", "Gatehouse could not get a database credential; retry shortly"}
	boltUpstream       = boltRefusal{"Gatehouse.TransientError.General.DatabaseUnavailable", "upstream", "Gatehouse could not reach the database; retry"}
	boltReauth         = boltRefusal{"Gatehouse.ClientError.Security.Unauthorized", "reauthentication", "Gatehouse does not support signing in again on an open connection; open a new one"}
	boltProtocol       = boltRefusal{"Gatehouse.ClientError.Request.Invalid", "protocol", "Gatehouse could not follow this request"}
)

func (r boltRefusal) frame() []byte { return bolt.Failure(r.code, "Gatehouse: "+r.message) }

// boltForbidden is the tier check's refusal; outcome names the decision.
func boltForbidden(outcome string) boltRefusal {
	return boltRefusal{"Gatehouse.ClientError.Security.Forbidden", outcome, "this session's person is not authorized for this database (" + outcome + ")"}
}

// boltReadOnly refuses one query on a read-only connection.
func boltReadOnly(detail string) boltRefusal {
	return boltRefusal{"Gatehouse.ClientError.Statement.AccessMode", "read_only",
		"this database is read-only; only queries that read the graph run here (refused: " + detail + ")"}
}

// boltGuarded refuses one query on a write connection: a file load, a commit
// of its own, or a procedure or function the entry does not list.
func boltGuarded(detail string) boltRefusal {
	return boltRefusal{"Gatehouse.ClientError.Statement.AccessMode", "query_refused",
		"only queries that read or change the graph run here (refused: " + detail + ")"}
}

// guarded is the guard's refusal for this session's access.
func (s *boltSession) guarded(detail string) boltRefusal {
	if s.svc.Write {
		return boltGuarded(detail)
	}
	return boltReadOnly(detail)
}

// boltPeer is one side of a Bolt session: buffered, with a bound on each
// message read.
type boltPeer struct {
	conn net.Conn
	r    io.Reader
	w    *bufio.Writer
	max  int
}

func newBoltPeer(conn net.Conn, r io.Reader, max int) *boltPeer {
	if r == nil {
		r = conn
	}
	return &boltPeer{conn: conn, r: bufio.NewReaderSize(r, 64<<10), w: bufio.NewWriterSize(conn, 64<<10), max: max}
}

func (p *boltPeer) read() ([]byte, error) { return bolt.ReadRaw(p.r, p.max) }

func (p *boltPeer) queue(msg []byte) error {
	_, err := p.w.Write(bolt.Frame(msg))
	return err
}

func (p *boltPeer) send(msgs ...[]byte) error {
	for _, m := range msgs {
		if err := p.queue(m); err != nil {
			return err
		}
	}
	return p.w.Flush()
}

// readMessage reads and decodes one message.
func (p *boltPeer) readMessage() (*bolt.Structure, []byte, error) {
	raw, err := p.read()
	if err != nil {
		return nil, nil, err
	}
	msg, err := bolt.Decode(raw)
	return msg, raw, err
}

func (b *Broker) maxBoltMessage() int {
	if b.opts.MaxBoltMessageBytes > 0 {
		return b.opts.MaxBoltMessageBytes
	}
	return defaultMaxBoltMessageBytes
}

// boltAuth reads the client's HELLO, and LOGON on 5.1 and later, and returns
// the principal (the catalog entry) and credential (the worker's proof) they
// carry. HELLO on 5.1 and later gets its SUCCESS here, as it must before
// LOGON.
func boltAuth(client *boltPeer, v bolt.Version) (principal, credential, routingAddr string, err error) {
	hello, _, err := client.readMessage()
	if err != nil || hello.Tag != bolt.TagHello {
		return "", "", "", errors.New("bolt: expected HELLO")
	}
	extra, err := hello.Map(0)
	if err != nil {
		return "", "", "", err
	}
	if routing, ok := extra["routing"].(map[string]any); ok {
		routingAddr, _ = routing["address"].(string)
	}
	auth := extra
	if v.AtLeast(5, 1) {
		if _, has := extra["credentials"]; has {
			return "", "", "", errors.New("bolt: credentials in HELLO on 5.1 or later")
		}
		if err := client.send(bolt.Success(map[string]any{"server": boltServerAgent, "connection_id": "gatehouse"})); err != nil {
			return "", "", "", err
		}
		logon, _, err := client.readMessage()
		if err != nil || logon.Tag != bolt.TagLogon {
			return "", "", "", errors.New("bolt: expected LOGON")
		}
		if auth, err = logon.Map(0); err != nil {
			return "", "", "", err
		}
	}
	scheme, _ := auth["scheme"].(string)
	principal, _ = auth["principal"].(string)
	credential, _ = auth["credentials"].(string)
	if scheme != "basic" || principal == "" || credential == "" {
		return "", "", "", errMissingToken
	}
	return principal, credential, routingAddr, nil
}

// handleBolt runs one Bolt connection; handleConn hands it over after reading
// Bolt's magic. stream yields the rest of the client's bytes.
func (b *Broker) handleBolt(conn net.Conn, stream io.Reader, session, attestation string, peer netip.Addr) {
	baseCtx := brokercore.WithAttestation(b.ctx, attestation)
	_ = conn.SetDeadline(time.Now().Add(b.opts.StartupTimeout))
	hs, err := bolt.ReadHandshake(stream, true)
	if err != nil {
		return
	}
	version, ok := hs.Choose(bolt.Supported)
	if !ok {
		_, _ = conn.Write([]byte{0, 0, 0, 0})
		return
	}
	answer := version.Bytes()
	if _, err := conn.Write(answer[:]); err != nil {
		return
	}
	client := newBoltPeer(conn, stream, b.maxBoltMessage())
	graphName, token, routingAddr, err := boltAuth(client, version)
	if err != nil {
		if errors.Is(err, errMissingToken) {
			_ = client.send(boltAuthentication.frame())
		}
		return
	}

	// From here admission follows handleConn's PostgreSQL path step for step.
	releaseAdmission := func() {}
	defer func() { releaseAdmission() }()
	var scope *AgentScope
	if m, ok := b.decoys().Password(token); ok {
		b.logger.Warn("pgproxy: decoy credential presented on Bolt; refusing session")
		if b.decoyDenied.allow(time.Now(), b.logger) {
			b.auditDenied(auditchain.Event{Binding: "decoy/" + m.Label, Decision: m.Surface, Database: auditchain.DatabaseField(graphName), Operation: "bolt.session"}, outcomeDecoy)
		}
		_ = client.send(boltAuthentication.frame())
		return
	}
	release, ok := b.acquireAdmission(baseCtx)
	if !ok {
		if b.ctx.Err() == nil {
			_ = conn.SetWriteDeadline(time.Now().Add(noticeWriteTimeout))
			_ = client.send(boltBusy.frame())
		}
		return
	}
	releaseAdmission = release
	_ = conn.SetDeadline(time.Now().Add(b.opts.StartupTimeout))
	authCtx, authCancel := context.WithTimeout(baseCtx, b.opts.StartupTimeout)
	scope, err = b.authenticator(peer).Authenticate(authCtx, token, "")
	authCancel()
	releaseAdmission()
	if err == nil && scope != nil && !brokercore.KindAdmitted(brokercore.ConnKinds(conn), scope.IdentityKind) {
		err, scope = fmt.Errorf("identity kind not admitted on this listener"), nil
	}
	if err != nil || scope == nil || scope.VaultID == "" || scope.ActorID == "" {
		if err == nil {
			err = fmt.Errorf("incomplete agent scope")
		}
		b.logger.Warn("pgproxy: Bolt agent authentication failed", slog.String("error", err.Error()))
		if b.denied.allow(time.Now(), b.logger) {
			event := auditchain.Event{Operation: "bolt.session"}
			if reason := brokercore.DenialReason(err); reason != "" {
				event.Decision = "identity_" + reason
			}
			if key := brokercore.DenialKey(err); key != nil {
				event.Kid, event.KidSHA256, event.Peer = key.Kid, key.KidSHA256, key.Peer
			}
			b.auditDenied(event, "authentication")
		}
		_ = client.send(boltAuthentication.frame())
		return
	}
	event := auditchain.Event{Pool: scope.Pool, Agent: scope.ActorID, PodUID: scope.WorkloadID, Session: newSessionID(), Operation: "bolt.session"}
	authenticated := time.Now()
	connCtx := WithSession(baseCtx, session)
	denied := func() auditchain.Event {
		e := event
		if e.Binding == "" {
			e.Database = auditchain.DatabaseField(graphName)
		}
		return e
	}
	refuse := func(r boltRefusal) {
		b.auditDenied(denied(), r.reason)
		_ = conn.SetWriteDeadline(time.Now().Add(noticeWriteTimeout))
		_ = client.send(r.frame())
	}
	if err := b.auditAdmit(); err != nil {
		b.logger.Error("pgproxy: audit trail unavailable; refusing Bolt session", slog.String("error", err.Error()))
		refuse(boltAudit)
		return
	}
	b.attribute(conn, runtimestatus.Attribution{ActorID: scope.ActorID, WorkloadID: scope.WorkloadID})

	hsCtx, cancel := context.WithTimeout(connCtx, b.opts.HandshakeTimeout)
	defer cancel()
	_ = conn.SetDeadline(time.Now().Add(b.opts.HandshakeTimeout))
	admissionCtx, admissionCancel := context.WithTimeout(hsCtx, b.opts.AdmissionTimeout)
	defer admissionCancel()
	capKey := scope.ActorID
	if scope.WorkloadID != "" {
		capKey = "workload:" + scope.WorkloadID
	}
	if !b.acquireLeaseSlot(admissionCtx, capKey, b.opts.MaxLeasesPerActor) {
		refuse(boltActorLimit)
		return
	}
	defer b.releaseLeaseSlot(capKey)
	if scope.WorkloadID != "" {
		agentKey := "agent:" + scope.ActorID
		if !b.acquireLeaseSlot(admissionCtx, agentKey, b.opts.MaxLeasesPerAgent) {
			refuse(boltActorLimit)
			return
		}
		defer b.releaseLeaseSlot(agentKey)
	}
	admissionLeft := time.Duration(0)
	if deadline, ok := admissionCtx.Deadline(); ok {
		admissionLeft = time.Until(deadline)
	}
	if b.opts.Sessions != nil && scope.WorkloadID != "" {
		id := newSessionID()
		sessionID := "ledger-" + id
		err := errors.New("session ID unavailable")
		if id != "" {
			release, ok := b.acquireAdmission(hsCtx)
			if !ok {
				refuse(boltBusy)
				return
			}
			ledgerCtx, ledgerCancel := context.WithTimeout(hsCtx, b.opts.LedgerTimeout)
			err = b.opts.Sessions.Add(ledgerCtx, sessionID, scope.WorkloadID, b.opts.MaxLeasesPerActor)
			ledgerCancel()
			release()
		}
		if errors.Is(err, ErrSessionLimit) {
			refuse(boltActorLimit)
			return
		}
		if err != nil {
			b.logger.Error("pgproxy: session ledger unavailable; refusing Bolt session", slog.String("error", err.Error()))
			refuse(boltLedger)
			return
		}
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), b.removalTimeout())
			defer cancel()
			if err := b.opts.Sessions.Remove(ctx, sessionID); err != nil {
				b.logger.Warn("pgproxy: session ledger removal failed", slog.String("error", err.Error()))
			}
		}()
	}
	expired := admissionLeft <= 0
	serveCtx, serveCancel := context.WithTimeout(hsCtx, admissionLeft)
	admitted := !expired && b.acquireServeSlot(serveCtx)
	serveCancel()
	admissionCancel()
	if expired {
		refuse(boltBusy)
		return
	}
	if !admitted {
		refuse(boltCapacity)
		return
	}
	defer b.releaseServeSlot()

	// Recheck the proof, then resolve the graph, as handleConn does.
	releaseStore, ok := b.acquireAdmission(hsCtx)
	if !ok {
		refuse(boltBusy)
		return
	}
	defer releaseStore()
	checkCtx, checkCancel := context.WithTimeout(hsCtx, b.opts.AuthorizationTimeout)
	current, checkErr := b.authenticator(peer).Authenticate(checkCtx, token, "")
	valid := checkErr == nil && checkCtx.Err() == nil && current != nil &&
		current.ActorID == scope.ActorID && current.VaultID == scope.VaultID && current.WorkloadID == scope.WorkloadID
	checkCancel()
	if !valid {
		refuse(boltAuthentication)
		return
	}
	var who Requester
	svc, err := b.opts.Graphs.ResolveGraph(WithRequesterRecord(hsCtx, &who), *scope, graphName)
	releaseStore()
	event.RequesterKind, event.TokenSHA256, event.RequesterOID = who.Kind, who.TokenSHA256, who.ObjectID
	event.Tier, event.Decision, event.Groups, event.CacheAgeSec = who.Tier, who.Decision, who.Groups, who.CacheAgeSec
	event.RequesterDepartment = auditchain.DepartmentField(who.Department)
	event.Source, event.Automation, event.AutomationName, event.AutomationOwner = who.Source, who.Automation, who.AutomationName, who.AutomationOwner
	if who.Kind == "person" || who.Kind == "agent" || who.Kind == "automation" {
		event.Requester = who.Subject
	}
	var refused *RefusedError
	if errors.As(err, &refused) {
		event.Binding = scope.VaultID + "/" + graphName
		refuse(boltForbidden(refused.Outcome))
		return
	}
	if err != nil || svc == nil {
		refuse(boltNoDatabase)
		return
	}
	event.Binding = scope.VaultID + "/" + svc.Name
	budget := &DatabaseService{Addr: svc.Addr, MaxConns: svc.MaxConns}
	if !b.acquireUpstreamSlot(budget) {
		refuse(boltDatabaseLimit)
		return
	}
	defer b.releaseUpstreamSlot(budget)
	if b.opts.GraphLogins == nil {
		refuse(boltCredential)
		return
	}
	login, err := b.opts.GraphLogins.GraphLogin(hsCtx, svc)
	if err != nil || login == nil || login.Username == "" || login.Password == "" {
		if err == nil {
			err = errors.New("empty login")
		}
		b.logger.Error("pgproxy: graph login unavailable", slog.String("service", svc.Name), slog.String("error", err.Error()))
		refuse(boltCredential)
		return
	}
	upstream, err := dialBolt(hsCtx, b.opts.Dialer, svc, version, login, b.maxBoltMessage())
	login = nil
	if err != nil {
		b.logger.Error("pgproxy: Bolt upstream connection failed", slog.String("service", svc.Name), slog.String("upstream", svc.Addr), slog.String("error", err.Error()))
		refuse(boltUpstream)
		return
	}
	defer func() { _ = upstream.conn.Close() }()

	opened := event
	opened.Event, opened.Outcome = auditchain.EventSessionOpen, "admitted"
	opened.Duration = time.Since(authenticated).Milliseconds()
	if err := b.auditRecord(opened); err != nil {
		b.logger.Error("pgproxy: audit trail unavailable; refusing Bolt session", slog.String("error", err.Error()))
		_ = client.send(boltAudit.frame())
		return
	}
	s := &boltSession{b: b, client: client, upstream: upstream, version: version, svc: svc, event: event, routingAddr: routingAddr}
	defer func() {
		closed := event
		closed.Event, closed.Outcome = auditchain.EventSessionClose, "closed"
		closed.Duration = time.Since(authenticated).Milliseconds()
		if s.refusals > 0 {
			closed.Decision = fmt.Sprintf("refused_%d", s.refusals)
		}
		_ = b.auditRecord(closed)
	}()
	// The client's authentication completes now that the database accepted
	// the broker's login: HELLO's SUCCESS before 5.1, LOGON's after.
	welcome := map[string]any{}
	if !version.AtLeast(5, 1) {
		welcome = map[string]any{"server": boltServerAgent, "connection_id": "gatehouse"}
	}
	if err := client.send(bolt.Success(welcome)); err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})
	_ = upstream.conn.SetDeadline(time.Time{})
	cancel()
	b.logger.Info("pgproxy: Bolt session established", slog.String("vault", scope.VaultID), slog.String("actor", scope.ActorID),
		slog.String("workload", scope.WorkloadID), slog.String("service", svc.Name), slog.String("upstream", svc.Addr), slog.String("version", version.String()))

	relayCtx, relayCancel := context.WithCancel(connCtx)
	defer relayCancel()
	var endOnce sync.Once
	endWith := func(n *closeNotice) {
		endOnce.Do(func() {
			if n != nil {
				b.logSessionEnd(svc.Name, *n, false)
			}
			_ = upstream.conn.Close()
			_ = conn.Close()
		})
	}
	// Bolt has no unsolicited error, so a session the broker ends is closed;
	// drivers treat that as a lost connection and retry on a new one.
	defer b.registerCloser(conn, func(n closeNotice) { go endWith(&n) })()
	authorizationDone := make(chan struct{})
	go func() {
		defer close(authorizationDone)
		b.authorizationLoopWith(relayCtx, token, "", *scope, svc.Name, func(ctx context.Context, current AgentScope) bool {
			next, err := b.opts.Graphs.ResolveGraph(ctx, current, graphName)
			return err == nil && next != nil && sameGraph(*svc, *next)
		}, func() { endWith(&noticeAuthorization) }, peer)
	}()
	defer func() { relayCancel(); <-authorizationDone }()
	if !scope.NotAfter.IsZero() {
		deadline := time.AfterFunc(time.Until(scope.NotAfter), func() { endWith(&noticeDeadline) })
		defer deadline.Stop()
	}
	s.serve()
	endWith(nil)
}

// dialBolt connects to the graph database, negotiates exactly version v and
// signs in with the broker's login.
func dialBolt(ctx context.Context, dial DialFunc, svc *GraphService, v bolt.Version, login *GraphLogin, max int) (*boltPeer, error) {
	raw, err := dial(ctx, "tcp", svc.Addr)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}
	conn := raw
	ok := false
	defer func() {
		if !ok {
			_ = conn.Close()
		}
	}()
	if deadline, has := ctx.Deadline(); has {
		_ = raw.SetDeadline(deadline)
	}
	if svc.Plaintext {
		if !privatePeer(raw) {
			return nil, errors.New("plaintext refused: the database is not on a private address")
		}
	} else {
		host, _, err := net.SplitHostPort(svc.Addr)
		if err != nil {
			host = svc.Addr
		}
		if svc.ServerName != "" {
			host = svc.ServerName
		}
		conf := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
		if svc.CA != "" {
			pins, err := parsePinnedCA(svc.CA)
			if err != nil {
				return nil, err
			}
			conf.InsecureSkipVerify = true //nolint:gosec // verified by verifyPinned against the pinned CA alone
			conf.VerifyConnection = verifyPinned(pins, host)
		}
		secure := tls.Client(raw, conf)
		if err := secure.HandshakeContext(ctx); err != nil {
			return nil, fmt.Errorf("TLS handshake: %w", err)
		}
		conn = secure
	}
	if _, err := conn.Write(bolt.ClientHandshake(v)); err != nil {
		return nil, fmt.Errorf("handshake: %w", err)
	}
	got, err := bolt.ReadVersion(conn)
	if err != nil {
		return nil, fmt.Errorf("handshake: %w", err)
	}
	if got != v {
		return nil, fmt.Errorf("the database did not accept Bolt %s", v)
	}
	peer := newBoltPeer(conn, nil, max)
	auth := map[string]any{"scheme": "basic", "principal": login.Username, "credentials": login.Password}
	hello := map[string]any{"user_agent": boltUserAgent}
	var msgs [][]byte
	if v.AtLeast(5, 1) {
		h, _ := bolt.Encode(bolt.TagHello, hello)
		l, err := bolt.Encode(bolt.TagLogon, auth)
		if err != nil {
			return nil, err
		}
		msgs = [][]byte{h, l}
	} else {
		for k, value := range auth {
			hello[k] = value
		}
		h, err := bolt.Encode(bolt.TagHello, hello)
		if err != nil {
			return nil, err
		}
		msgs = [][]byte{h}
	}
	if err := peer.send(msgs...); err != nil {
		return nil, fmt.Errorf("sign in: %w", err)
	}
	for range msgs {
		msg, _, err := peer.readMessage()
		if err != nil {
			return nil, fmt.Errorf("sign in: %w", err)
		}
		if msg.Tag != bolt.TagSuccess {
			// The database's words can name the user; keep only that it refused.
			return nil, errors.New("the database refused the broker's login")
		}
	}
	ok = true
	return peer, nil
}

// boltSession relays one signed-in Bolt session, one request at a time, and
// holds it to reads.
type boltSession struct {
	b                *Broker
	client, upstream *boltPeer
	version          bolt.Version
	svc              *GraphService
	event            auditchain.Event
	routingAddr      string

	failed   bool // the client was sent FAILURE; requests are IGNORED until RESET
	explicit bool // the client's own transaction (BEGIN) is open
	implicit bool // the broker opened a transaction for an auto-commit query
	// empty is the result of a BEGIN, COMMIT or ROLLBACK statement the broker
	// carried out itself, whose PULL or DISCARD it also answers.
	empty    bool
	refusals int
}

var errBoltProtocol = errors.New("bolt: protocol violation")

// serve runs requests until the client leaves or either side fails. Every
// request gets its answer before the next is read, which keeps the broker's
// own messages (EXPLAIN, BEGIN, ROLLBACK) out of the client's stream.
func (s *boltSession) serve() {
	for {
		raw, err := s.client.read()
		if err != nil {
			return
		}
		msg, err := bolt.Decode(raw)
		if err != nil {
			_ = s.client.send(boltProtocol.frame())
			return
		}
		if err := s.handle(msg, raw); err != nil {
			if errors.Is(err, errBoltProtocol) {
				_ = s.client.send(boltProtocol.frame())
			}
			return
		}
	}
}

func (s *boltSession) handle(msg *bolt.Structure, raw []byte) error {
	switch msg.Tag {
	case bolt.TagGoodbye:
		_ = s.upstream.send(raw)
		return io.EOF
	case bolt.TagReset:
		s.failed, s.explicit, s.implicit, s.empty = false, false, false, false
		return s.forward(raw)
	}
	if s.failed {
		return s.client.send(bolt.Ignored())
	}
	if s.empty {
		s.empty = false
		if msg.Tag == bolt.TagPull || msg.Tag == bolt.TagDiscard {
			return s.client.send(bolt.Success(map[string]any{"has_more": false}))
		}
	}
	switch msg.Tag {
	case bolt.TagHello, bolt.TagLogon, bolt.TagLogoff:
		_ = s.client.send(boltReauth.frame())
		return io.EOF
	case bolt.TagTelemetry:
		return s.client.send(bolt.Success(nil))
	case bolt.TagRoute:
		return s.route(msg)
	case bolt.TagBegin:
		extra, err := msg.Map(0)
		if err != nil {
			return errBoltProtocol
		}
		return s.begin(extra, false)
	case bolt.TagRun:
		return s.run(msg)
	case bolt.TagPull, bolt.TagDiscard:
		return s.stream(raw)
	case bolt.TagCommit:
		return s.end(true, false)
	case bolt.TagRollback:
		return s.end(false, false)
	}
	return errBoltProtocol
}

// begin opens the client's own transaction, for a BEGIN message or, with
// statement true, a RUN of the statement BEGIN.
func (s *boltSession) begin(extra map[string]any, statement bool) error {
	if s.explicit || s.implicit {
		return s.refuse(boltRefusal{"Gatehouse.ClientError.Transaction.Invalid", "protocol", "a transaction is already open"}, "")
	}
	begin, refusal := s.transactionExtra(extra)
	if refusal != "" {
		return s.refuse(s.guarded(refusal), "request:"+strings.ReplaceAll(refusal, " ", "_"))
	}
	if !statement {
		ok, err := s.call(mustEncode(bolt.TagBegin, begin))
		s.explicit = ok
		return err
	}
	ok, err := s.callQuiet(mustEncode(bolt.TagBegin, begin))
	if err != nil || !ok {
		return err
	}
	s.explicit = true
	return s.statementDone()
}

// end closes the client's own transaction, for a COMMIT (commit true) or
// ROLLBACK message or, with statement true, a RUN of that statement. A read
// entry's transaction has nothing to commit: COMMIT rolls it back, so nothing
// it might have changed can persist.
func (s *boltSession) end(commit, statement bool) error {
	if !s.explicit {
		return s.refuse(boltRefusal{"Gatehouse.ClientError.Transaction.Invalid", "protocol", "no transaction is open"}, "")
	}
	s.explicit = false
	tag := bolt.TagRollback
	if commit && s.svc.Write {
		tag = bolt.TagCommit
	}
	if !statement && commit == (tag == bolt.TagCommit) {
		// The database's own answer: COMMIT's carries its bookmark.
		_, err := s.call(mustEncode(tag))
		return err
	}
	ok, err := s.callQuiet(mustEncode(tag))
	if err != nil {
		return err
	}
	if !ok {
		s.failed = true
		return nil
	}
	if statement {
		return s.statementDone()
	}
	return s.client.send(bolt.Success(nil))
}

// statementDone answers a RUN of BEGIN, COMMIT or ROLLBACK the broker carried
// out itself: an empty result, whose PULL or DISCARD the broker answers too.
func (s *boltSession) statementDone() error {
	s.empty = true
	return s.client.send(bolt.Success(map[string]any{"fields": []any{}}))
}

// transactionStatement recognizes a query that is only BEGIN, COMMIT or
// ROLLBACK, which some drivers (pymgclient without autocommit) send in place
// of the Bolt messages. Memgraph cannot plan them, so the broker carries them
// out as the messages they stand for. Anything more than the bare word,
// even a comment, is a query like any other.
func transactionStatement(query string) byte {
	word := strings.TrimSpace(query)
	word = strings.TrimSpace(strings.TrimSuffix(word, ";"))
	switch {
	case strings.EqualFold(word, "BEGIN"):
		return bolt.TagBegin
	case strings.EqualFold(word, "COMMIT"):
		return bolt.TagCommit
	case strings.EqualFold(word, "ROLLBACK"):
		return bolt.TagRollback
	}
	return 0
}

func mustEncode(tag byte, fields ...any) []byte {
	b, err := bolt.Encode(tag, fields...)
	if err != nil {
		panic(err) // only fixed, broker-built values reach here
	}
	return b
}

// refuse answers the current request with r and records the refusal. The
// client must RESET before its next request, as after any FAILURE.
func (s *boltSession) refuse(r boltRefusal, decision string) error {
	s.failed = true
	if r.reason == "read_only" || r.reason == "query_refused" {
		s.refusals++
		e := s.event
		e.Operation, e.Decision = "bolt.query", decision
		s.b.auditDenied(e, r.reason)
		s.b.logger.Warn("pgproxy: Bolt query refused by the query guard", slog.String("service", s.svc.Name), slog.String("actor", s.event.Agent), slog.String("step", decision))
	}
	return s.client.send(r.frame())
}

// forward sends a request upstream and relays its one summary.
func (s *boltSession) forward(raw []byte) error {
	_, err := s.call(raw)
	return err
}

// call sends one request upstream and relays its summary to the client. ok
// is true for SUCCESS.
func (s *boltSession) call(raw []byte) (bool, error) {
	if err := s.upstream.send(raw); err != nil {
		return false, err
	}
	reply, err := s.upstream.read()
	if err != nil {
		return false, err
	}
	tag, err := bolt.Tag(reply)
	if err != nil || tag == bolt.TagRecord {
		return false, errBoltProtocol
	}
	if tag == bolt.TagFailure {
		s.failed = true
	}
	return tag == bolt.TagSuccess, s.client.send(reply)
}

// callQuiet sends one request upstream and relays its summary only when it
// is not SUCCESS.
func (s *boltSession) callQuiet(raw []byte) (bool, error) {
	if err := s.upstream.send(raw); err != nil {
		return false, err
	}
	reply, err := s.upstream.read()
	if err != nil {
		return false, err
	}
	tag, err := bolt.Tag(reply)
	if err != nil || tag == bolt.TagRecord {
		return false, errBoltProtocol
	}
	if tag == bolt.TagSuccess {
		return true, nil
	}
	if tag == bolt.TagFailure {
		s.failed = true
	}
	return false, s.client.send(reply)
}

// transactionExtra builds the BEGIN extra the broker sends from the client's
// RUN or BEGIN extra: the entry's mode (read unless the entry writes), never
// the client's, the client's timeout, metadata and bookmarks kept, and no
// other database or impersonated user.
func (s *boltSession) transactionExtra(extra map[string]any) (map[string]any, string) {
	out := map[string]any{"mode": "r"}
	if s.svc.Write {
		out["mode"] = "w"
	}
	for k, v := range extra {
		switch k {
		case "db":
			if name, _ := v.(string); name != "" && name != "memgraph" {
				return nil, "another database"
			}
		case "imp_user":
			if v != nil {
				return nil, "impersonation"
			}
		case "mode":
			// The entry's, never the client's.
		case "tx_timeout", "tx_metadata", "bookmarks":
			out[k] = v
		}
	}
	return out, ""
}

func (s *boltSession) run(msg *bolt.Structure) error {
	if len(msg.Fields) < 1 {
		return errBoltProtocol
	}
	if s.implicit {
		return s.refuse(boltRefusal{"Gatehouse.ClientError.Request.Invalid", "protocol", "the previous result is still open; pull or discard it first"}, "")
	}
	query, ok := msg.Fields[0].(string)
	if !ok {
		return errBoltProtocol
	}
	params := map[string]any{}
	if len(msg.Fields) > 1 && msg.Fields[1] != nil {
		p, ok := msg.Fields[1].(map[string]any)
		if !ok {
			return errBoltProtocol
		}
		params = p
	}
	extra, err := msg.Map(2)
	if err != nil {
		return errBoltProtocol
	}
	switch transactionStatement(query) {
	case bolt.TagBegin:
		return s.begin(extra, true)
	case bolt.TagCommit:
		return s.end(true, true)
	case bolt.TagRollback:
		return s.end(false, true)
	}
	begin, refusal := s.transactionExtra(extra)
	if refusal != "" {
		return s.refuse(s.guarded(refusal), "request:"+strings.ReplaceAll(refusal, " ", "_"))
	}
	if name := refusedFunction(query, s.svc.Functions); name != "" {
		return s.refuse(s.guarded("function "+name), "function:"+auditToken(name))
	}
	verdict, failure, err := s.plan(query, params)
	if err != nil {
		return err
	}
	if failure != nil {
		// Memgraph could not plan it: its own error, with the client's
		// request failed as the database would have failed it.
		s.failed = true
		return s.client.send(failure)
	}
	if verdict != "" {
		decision := "step:" + auditToken(strings.ReplaceAll(verdict, " ", "_"))
		if name, ok := strings.CutPrefix(verdict, "CALL "); ok {
			decision = "procedure:" + auditToken(name)
		}
		return s.refuse(s.guarded(verdict), decision)
	}
	if !s.explicit {
		// An auto-commit query runs in a transaction the broker opens and,
		// once its result has been read, commits for a write entry or rolls
		// back for a read entry.
		ok, err := s.callQuiet(mustEncode(bolt.TagBegin, begin))
		if err != nil || !ok {
			return err
		}
		s.implicit = true
	}
	_, err = s.call(mustEncode(bolt.TagRun, query, params, map[string]any{}))
	return err
}

// plan asks the database for query's plan and checks it. It returns the
// first step that does not read (or "" when all do), or the database's
// FAILURE when it could not plan the query, which leaves the upstream to be
// RESET by the client's next RESET.
func (s *boltSession) plan(query string, params map[string]any) (string, []byte, error) {
	if err := s.upstream.send(mustEncodeRun("EXPLAIN "+query, params), mustEncode(bolt.TagPull, map[string]any{"n": int64(-1)})); err != nil {
		return "", nil, err
	}
	reply, err := s.upstream.read()
	if err != nil {
		return "", nil, err
	}
	tag, err := bolt.Tag(reply)
	if err != nil {
		return "", nil, errBoltProtocol
	}
	if tag != bolt.TagSuccess {
		// The PULL behind a failed RUN is IGNORED.
		if _, err := s.upstream.read(); err != nil {
			return "", nil, err
		}
		if tag != bolt.TagFailure {
			return "", nil, errBoltProtocol
		}
		return "", reply, nil
	}
	var lines []string
	size := 0
	for {
		raw, err := s.upstream.read()
		if err != nil {
			return "", nil, err
		}
		msg, err := bolt.Decode(raw)
		if err != nil {
			return "", nil, errBoltProtocol
		}
		switch msg.Tag {
		case bolt.TagRecord:
			row, ok := msg.Fields[0].([]any)
			if len(msg.Fields) != 1 || !ok || len(row) != 1 {
				return "", nil, errBoltProtocol
			}
			line, ok := row[0].(string)
			if !ok {
				return "", nil, errBoltProtocol
			}
			size += len(line)
			if size > s.client.max {
				return "", nil, errBoltProtocol
			}
			lines = append(lines, line)
			continue
		case bolt.TagSuccess:
			return planVerdict(lines, s.svc.Procedures, s.svc.Write), nil, nil
		case bolt.TagFailure:
			return "", raw, nil
		}
		return "", nil, errBoltProtocol
	}
}

// mustEncodeRun builds a RUN with no extra: inside a transaction, which is
// where the broker runs every client query, Bolt allows none.
func mustEncodeRun(query string, params map[string]any) []byte {
	b, err := bolt.Encode(bolt.TagRun, query, params, map[string]any{})
	if err != nil {
		panic(err)
	}
	return b
}

// stream relays a PULL or DISCARD: records as they come, then the summary.
// The last batch of an auto-commit query's result ends the broker's
// transaction (a commit for a write entry, else a rollback) before the client
// sees the summary.
func (s *boltSession) stream(raw []byte) error {
	if err := s.upstream.send(raw); err != nil {
		return err
	}
	for {
		reply, err := s.upstream.read()
		if err != nil {
			return err
		}
		tag, err := bolt.Tag(reply)
		if err != nil {
			return errBoltProtocol
		}
		switch tag {
		case bolt.TagRecord:
			if err := s.client.queue(reply); err != nil {
				return err
			}
			continue
		case bolt.TagFailure:
			s.failed = true
		case bolt.TagSuccess:
			if s.implicit {
				msg, err := bolt.Decode(reply)
				if err != nil {
					return errBoltProtocol
				}
				meta, err := msg.Map(0)
				if err != nil {
					return errBoltProtocol
				}
				if more, _ := meta["has_more"].(bool); !more {
					end := bolt.TagRollback
					if s.svc.Write {
						end = bolt.TagCommit
					}
					ok, err := s.callQuiet(mustEncode(end))
					if err != nil {
						return err
					}
					s.implicit = false
					if !ok {
						return s.client.w.Flush()
					}
				}
			}
		case bolt.TagIgnored:
		default:
			return errBoltProtocol
		}
		return s.client.send(reply)
	}
}

// route answers ROUTE itself: the one server is the address the client
// dialed (the sidecar's), for every role, so a neo4j:// URI works against a
// single database.
func (s *boltSession) route(msg *bolt.Structure) error {
	addr := s.routingAddr
	if ctx, err := msg.Map(0); err == nil {
		if a, ok := ctx["address"].(string); ok && a != "" {
			addr = a
		}
	}
	if host, port, err := net.SplitHostPort(addr); err != nil || host == "" || port == "" || strings.ContainsAny(addr, " /\\@") {
		return s.refuse(boltRefusal{"Gatehouse.ClientError.Request.Invalid", "protocol", "use a bolt:// URI, or neo4j:// with the sidecar's address"}, "")
	}
	servers := []any{
		map[string]any{"addresses": []any{addr}, "role": "ROUTE"},
		map[string]any{"addresses": []any{addr}, "role": "READ"},
		map[string]any{"addresses": []any{addr}, "role": "WRITE"},
	}
	return s.client.send(bolt.Success(map[string]any{"rt": map[string]any{"ttl": int64(300), "db": "memgraph", "servers": servers}}))
}

// auditToken keeps a name the client influenced safe for an audit row.
func auditToken(s string) string {
	if len(s) > 128 {
		return "invalid"
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= ' ' || s[i] > '~' || s[i] == '"' || s[i] == '\\' {
			return "invalid"
		}
	}
	return s
}
