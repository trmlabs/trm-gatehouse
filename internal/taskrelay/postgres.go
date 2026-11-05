package taskrelay

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/Infisical/agent-vault/internal/brokercore"
)

const (
	cancelCode     = 80877102
	sslRequestCode = 80877103
	gssRequestCode = 80877104
)

type cancelTarget struct {
	mu      sync.Mutex
	active  bool
	address string
	packet  []byte
	expiry  time.Time
	binding string
}

// PostgreSQL uses outer TLS; only the fixed database/user and a public placeholder are accepted, and the relay substitutes the proof.
// Admission runs only after peer, TLS, startup and placeholder validate, so earlier failures cost no API request.
func (r *relay) postgres(conn net.Conn, binding PostgresConfig, route func(database string) bool) {
	_ = conn.SetDeadline(minTime(r.config.Deadline, time.Now().Add(r.handshake())))
	peer := conn.RemoteAddr().String()
	// The listener hands over the connection before TLS, so a foreign address is refused unread.
	// Only the first is journaled: a network neighbour must not drive one fsync per connect.
	if !r.pair.peerMatches(peer) {
		if r.foreignPeer.CompareAndSwap(false, true) {
			_ = r.record("postgres", "denied:peer")
		}
		return
	}
	packet, e := readStartupPacket(conn)
	if e != nil {
		if !errors.Is(e, io.EOF) {
			_ = r.record("postgres", "denied:bad-startup")
		}
		return
	}
	// With a broker-issued certificate GSS is declined, an SSLRequest gets 'S' and plaintext (cancellation included) is refused; the next packet inside TLS must be startup or cancellation.
	if r.pgTLS != nil {
		if len(packet) == 8 && binary.BigEndian.Uint32(packet[4:8]) == gssRequestCode {
			if _, e = conn.Write([]byte{'N'}); e != nil {
				return
			}
			if packet, e = readStartupPacket(conn); e != nil {
				_ = r.record("postgres", "denied:bad-startup")
				return
			}
		}
		if len(packet) != 8 || binary.BigEndian.Uint32(packet[4:8]) != sslRequestCode {
			_ = r.record("postgres", "denied:plaintext")
			_, _ = conn.Write(errorFrame("28000", plaintextRefusedMessage))
			return
		}
		if _, e = conn.Write([]byte{'S'}); e != nil {
			return
		}
		secure := tls.Server(conn, r.pgTLS)
		if secure.HandshakeContext(r.ctx) != nil {
			_ = r.record("postgres", "denied:tls")
			return
		}
		conn = secure
		if packet, e = readStartupPacket(conn); e != nil || len(packet) == 8 {
			_ = r.record("postgres", "denied:bad-startup")
			return
		}
	}
	// Plaintext listeners decline TLS and GSS, so sslmode=prefer goes on in plaintext and a client that requires TLS stops.
	plaintext := r.config.Self || (r.config.Shared != nil && r.config.TLSCertFile == "")
	if code := binary.BigEndian.Uint32(packet[4:8]); r.pgTLS == nil && plaintext && len(packet) == 8 && (code == sslRequestCode || code == gssRequestCode) {
		if _, e = conn.Write([]byte{'N'}); e != nil {
			return
		}
		if packet, e = readStartupPacket(conn); e != nil || len(packet) == 8 {
			_ = r.record("postgres", "denied:bad-startup")
			return
		}
	}
	if binary.BigEndian.Uint32(packet[4:8]) == cancelCode {
		r.cancelPostgres(peer, packet, binding)
		return
	}
	var startup pgproto3.StartupMessage
	c := &binding
	decoded := startup.Decode(packet[4:]) == nil && startup.ProtocolVersion == pgproto3.ProtocolVersionNumber
	if decoded && route != nil {
		if !route(startup.Parameters["database"]) {
			_ = r.record("postgres", "denied:no-database")
			refusal := refusalsByReason["no_database"]
			_, _ = conn.Write(errorFrame(refusal.code, refusal.message))
			return
		}
		c.Database = startup.Parameters["database"]
	}
	if !decoded || !validStartup(startup.Parameters, c) {
		_ = r.record("postgres", "denied:bad-startup")
		_, _ = conn.Write(errorFrame("08004", "Gatehouse: connection refused: use this binding's database and user, and only the "+
			startupParameterList+" startup parameters, with bounded values (set others with SET after connecting)"))
		return
	}
	// Never forward arbitrary backend options; connection authority is fixed to the operator's database and user.
	parameters := map[string]string{"user": c.User, "database": c.Database}
	for key, value := range startup.Parameters {
		if name, v, valid := brokercore.StartupParameter(key, value); valid {
			parameters[name] = v
		}
	}
	packet, e = (&pgproto3.StartupMessage{ProtocolVersion: pgproto3.ProtocolVersionNumber, Parameters: parameters}).Encode(nil)
	if e != nil {
		return
	}
	backend := pgproto3.NewBackend(conn, conn)
	backend.Send(&pgproto3.AuthenticationCleartextPassword{})
	if backend.Flush() != nil {
		return
	}
	typ, password, e := readPGFrame(conn, 1024)
	if e != nil {
		if !errors.Is(e, io.EOF) {
			_ = r.record("postgres", "denied:bad-startup")
		}
		return
	}
	if typ != 'p' || string(password) != c.Placeholder+"\x00" {
		_ = r.record("postgres", "denied:placeholder")
		_, _ = conn.Write(errorFrame("28P01", "Gatehouse: wrong placeholder password for this binding"))
		return
	}
	// Admit (live pair check, then the durable "admitted" row) before any proof is read.
	if r.admit(r.ctx, peer, "postgres") != nil {
		return
	}
	defer func() { _ = r.record("postgres", "terminal") }()
	// From here the worker is always told why, in fixed words; only a withdrawn task closes silently.
	tell := func(frame []byte) { _, _ = conn.Write(frame) }
	refused := func() { tell(errorFrame("08004", genericRefusalMessage)) }
	if !r.config.Deadline.After(time.Now()) {
		tell(errorFrame("08006", sessionEndedMessage))
		return
	}
	proof, expiry, e := readProof(c.Upstream, r.config.Deadline)
	if e != nil {
		tell(errorFrame("28000", notVerifiedMessage))
		return
	}
	if r.pair.check(r.ctx, peer) != nil {
		return
	}
	dialCtx, cancelDial := context.WithTimeout(r.ctx, r.handshake())
	up, e := dialUpstream(dialCtx, c.Upstream)
	cancelDial()
	r.upstreams.dialed(r.log, c.Upstream.Address, e)
	if e != nil {
		tell(errorFrame("08001", unreachableMessage))
		return
	}
	defer func() { _ = up.Close() }()
	stop := context.AfterFunc(r.ctx, func() { _ = up.Close() })
	defer stop()
	_ = up.SetDeadline(minTime(expiry, time.Now().Add(r.handshake())))
	attestation, agent, e := r.attest(peer)
	if e != nil {
		return
	}
	if attestation != "" {
		if _, e = io.WriteString(up, "GHATTS1 "+attestation+"\n"); e != nil {
			tell(errorFrame("08001", unreachableMessage))
			return
		}
	}
	end := &ending{}
	stopWatch := r.watchPeer(peer, agent, func() { end.set(endWithdrawn); _ = conn.Close(); _ = up.Close() })
	defer stopWatch()
	// The session rides the broker-side stream ahead of the startup this sidecar authors; the worker's bytes never carry it.
	if session := readSession(r.log, c.Upstream); session != "" {
		if _, e = io.WriteString(up, "GHSESS1 "+session+"\n"); e != nil {
			tell(errorFrame("08001", unreachableMessage))
			return
		}
	}
	if _, e = up.Write(packet); e != nil {
		tell(errorFrame("08001", unreachableMessage))
		return
	}
	typ, body, e := readPGFrame(up, 8192)
	if e == nil && typ == 'E' {
		_ = r.record("postgres", "refused:"+refusalReason(body))
		tell(refusalFrame(body))
		return
	}
	if e != nil || typ != 'R' || len(body) != 4 || binary.BigEndian.Uint32(body) != 3 {
		refused()
		return
	}
	if r.pair.check(r.ctx, peer) != nil {
		return
	}
	if !time.Now().Before(expiry) {
		tell(errorFrame("08006", sessionEndedMessage))
		return
	}
	authPacket, e := (&pgproto3.PasswordMessage{Password: proof}).Encode(nil)
	if e != nil {
		refused()
		return
	}
	if _, e = up.Write(authPacket); e != nil {
		tell(errorFrame("08001", unreachableMessage))
		return
	}
	// Accumulate the bounded response before disclosing anything; broker refusals are rewritten in fixed words, never relayed.
	var response []byte
	var remove func()
	defer func() {
		if remove != nil {
			remove()
		}
	}()
	authenticated := false
	for len(response) < 65536 {
		typ, body, e = readPGFrame(up, 8192)
		if e != nil {
			refused()
			return
		}
		switch typ {
		case 'R':
			if authenticated || len(body) != 4 || binary.BigEndian.Uint32(body) != 0 {
				refused()
				return
			}
			authenticated = true
		case 'S':
			if !authenticated {
				refused()
				return
			}
		case 'K':
			if !authenticated || len(body) != 8 || remove != nil {
				refused()
				return
			}
			var local []byte
			local, remove, e = r.registerCancel(body, up.RemoteAddr().String(), expiry, binding.Listen)
			if e != nil {
				refused()
				return
			}
			body = local
		case 'Z':
			if !authenticated || len(body) != 1 {
				refused()
				return
			}
		case 'E':
			_ = r.record("postgres", "refused:"+refusalReason(body))
			tell(refusalFrame(body))
			return
		default:
			refused()
			return
		}
		response = append(response, encodePGFrame(typ, body)...)
		if typ == 'Z' {
			break
		}
	}
	if typ != 'Z' {
		refused()
		return
	}
	if r.pair.check(r.ctx, peer) != nil || r.record("postgres", "established") != nil {
		return
	}
	_ = conn.SetDeadline(expiry)
	_ = up.SetDeadline(expiry)
	if _, e = conn.Write(response); e != nil {
		return
	}
	started := time.Now()
	defer func() { r.logClose("postgres", peer, agent, c.Upstream.Address, c.Database, started, end) }()
	copyPostgres(r.ctx, conn, up, expiry, end)
}

// validStartup fixes database and user and allows only the parameters brokercore.StartupValue accepts, so a client passing here is never refused there.
func validStartup(parameters map[string]string, c *PostgresConfig) bool {
	if parameters["database"] != c.Database || parameters["user"] != c.User {
		return false
	}
	for key, value := range parameters {
		if key == "database" || key == "user" {
			continue
		}
		if _, _, ok := brokercore.StartupParameter(key, value); !ok {
			return false
		}
	}
	return true
}

var startupParameterList = strings.Join(brokercore.StartupParameters[:len(brokercore.StartupParameters)-1], ", ") +
	" and " + brokercore.StartupParameters[len(brokercore.StartupParameters)-1]

func readStartupPacket(reader io.Reader) ([]byte, error) {
	var length [4]byte
	if _, e := io.ReadFull(reader, length[:]); e != nil {
		return nil, e
	}
	n := binary.BigEndian.Uint32(length[:])
	if n < 8 || n > 8192 {
		return nil, errDenied
	}
	b := make([]byte, int(n))
	copy(b, length[:])
	_, e := io.ReadFull(reader, b[4:])
	return b, e
}
func readPGFrame(reader io.Reader, max uint32) (byte, []byte, error) {
	var header [5]byte
	if _, e := io.ReadFull(reader, header[:]); e != nil {
		return 0, nil, e
	}
	n := binary.BigEndian.Uint32(header[1:])
	if n < 4 || n > max {
		return 0, nil, errDenied
	}
	b := make([]byte, int(n)-4)
	_, e := io.ReadFull(reader, b)
	return header[0], b, e
}
func encodePGFrame(typ byte, body []byte) []byte {
	out := []byte{typ}
	out = binary.BigEndian.AppendUint32(out, uint32(len(body)+4))
	return append(out, body...)
}

func (r *relay) registerCancel(coreKey []byte, address string, expiry time.Time, binding string) ([]byte, func(), error) {
	r.cancelMu.Lock()
	defer r.cancelMu.Unlock()
	if r.cancellations == nil {
		r.cancellations = make(map[string]*cancelTarget)
	}
	for {
		local := make([]byte, 8)
		if _, e := rand.Read(local); e != nil {
			return nil, nil, errDenied
		}
		if _, exists := r.cancellations[string(local)]; exists {
			continue
		}
		packet := binary.BigEndian.AppendUint32(nil, 16)
		packet = binary.BigEndian.AppendUint32(packet, cancelCode)
		packet = append(packet, coreKey...)
		target := &cancelTarget{active: true, address: address, packet: packet, expiry: expiry, binding: binding}
		key := string(local)
		r.cancellations[key] = target
		return local, func() {
			r.cancelMu.Lock()
			delete(r.cancellations, key)
			r.cancelMu.Unlock()
			target.mu.Lock()
			target.active = false
			target.mu.Unlock()
		}, nil
	}
}

// cancelPostgres is reached without admission: it needs a key matching an established session, and journals its own outcome.
func (r *relay) cancelPostgres(peer string, packet []byte, binding PostgresConfig) {
	if len(packet) != 16 {
		_ = r.record("postgres", "denied:cancel")
		return
	}
	r.cancelMu.Lock()
	target := r.cancellations[string(packet[8:])]
	r.cancelMu.Unlock()
	if target == nil || !target.mu.TryLock() {
		_ = r.record("postgres", "denied:cancel")
		return
	}
	defer target.mu.Unlock()
	if target.binding != binding.Listen || !target.active || !time.Now().Before(target.expiry) || r.pair.check(r.ctx, peer) != nil {
		_ = r.record("postgres", "denied:cancel")
		return
	}
	if r.record("postgres", "cancel") != nil {
		return
	}
	// Pin to the established broker socket, not a newly selected service replica.
	c := binding.Upstream
	c.Address = target.address
	ctx, cancel := context.WithDeadline(r.ctx, minTime(target.expiry, time.Now().Add(r.handshake())))
	defer cancel()
	up, e := dialUpstream(ctx, c)
	if e != nil {
		return
	}
	defer func() { _ = up.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = up.Close() })
	defer stop()
	if !time.Now().Before(target.expiry) || r.pair.check(ctx, peer) != nil {
		return
	}
	if _, e = up.Write(target.packet); e == nil {
		_, _ = io.Copy(io.Discard, up)
	}
}

func errorField(body []byte, want byte) string {
	for len(body) > 0 && body[0] != 0 {
		field := body[0]
		end := bytes.IndexByte(body[1:], 0)
		if end < 0 {
			return ""
		}
		if field == want {
			return string(body[1 : 1+end])
		}
		body = body[2+end:]
	}
	return ""
}

func sqlState(body []byte) string { return errorField(body, 'C') }

const (
	sessionEndedMessage   = "Gatehouse ended the session (deadline or revocation)"
	unreachableMessage    = "cannot reach Gatehouse"
	notVerifiedMessage    = "Gatehouse could not verify this worker"
	workerCapMessage      = "this worker reached its session cap"
	databaseBudgetMessage = "the database's Gatehouse connection budget is full; retry shortly"
	genericRefusalMessage = "Gatehouse: the broker refused this connection"
	// A PostgreSQL error field is plain text, readable even to a client that sent no SSLRequest.
	plaintextRefusedMessage = "Gatehouse requires TLS on this port: connect with sslmode=require or stricter"
)

type refusal struct{ code, message string }

// refusalsByReason maps the broker's reason code to the relay's fixed words; broker message text is never forwarded.
var refusalsByReason = map[string]refusal{
	"actor_limit":              {"53300", workerCapMessage},
	"database_limit":           {"53300", databaseBudgetMessage},
	"pool_budget":              {"53300", databaseBudgetMessage},
	"capacity":                 {"53300", "Gatehouse is at capacity; retry shortly"},
	"pinned_share":             {"53300", "no session-mode database connection is free for session state (SET, temp tables, LISTEN, advisory locks); retry shortly"},
	"not_ready":                {"57P03", "Gatehouse is starting; retry in a few seconds"},
	"no_database":              {"3D000", "this database isn't in the Gatehouse catalog for your pool"},
	"authentication":           {"28000", notVerifiedMessage},
	"upstream":                 {"08006", "Gatehouse could not reach the database; retry"},
	"credential":               {"08006", "Gatehouse could not get a database credential; retry shortly"},
	"restarting":               {"57P01", "Gatehouse is restarting; reconnect"},
	"restart_cut":              {"08006", "Gatehouse restarted while a transaction was open; it was rolled back, reconnect and retry"},
	"authorization_ended":      {"08006", "Gatehouse ended the session: access was revoked or could not be confirmed"},
	"deadline":                 {"08006", "Gatehouse ended the session: this worker reached its deadline"},
	"credential_expired":       {"08006", "Gatehouse ended the session: its database credential expired; reconnect"},
	"role_change":              {"42501", "Gatehouse refuses ALTER ROLE, ALTER USER and ALTER DATABASE on a shared database connection"},
	"read_only":                {"25006", "this database login is read-only: Gatehouse allows only reads, transaction control and a few settings such as search_path, and refuses temporary tables"},
	"encoding_change":          {"42501", "Gatehouse refuses changing standard_conforming_strings or client_encoding mid-session; only on and UTF8 at connect"},
	"pipelined_escape":         {"0A000", "Gatehouse refuses a statement with a backslash after an Execute in the same batch; send Sync first"},
	"statement_limit":          {"54000", "this session holds too many prepared statements; deallocate some"},
	"audit_unavailable":        {"08004", "Gatehouse could not write its audit record, so it refused the connection; retry shortly"},
	"ledger_unavailable":       {"08004", "Gatehouse could not record the session in its accounting, so it refused the connection; retry shortly"},
	"pool_external":            {"42501", "Gatehouse: this pool may reach only external destinations, not this database"},
	"pool_ceiling":             {"42501", "Gatehouse: this database is above your pool's tier ceiling"},
	"entitlement_config":       {"42501", "Gatehouse: this database's entitlement settings are incomplete; tell the Gatehouse owners"},
	"workload_not_entitled":    {"42501", "Gatehouse: this workload is not entitled to this database"},
	"no_identity":              {"42501", "Gatehouse: this pool has no identity that can be authorized for this database"},
	"no_person":                {"42501", "Gatehouse: no person could be named for this session"},
	"entitlement_rate_limited": {"42501", "Gatehouse could not check entitlements just now (rate limited); retry shortly"},
	"entitlement_unavailable":  {"42501", "Gatehouse could not check entitlements just now; retry shortly"},
	"account_disabled":         {"42501", "Gatehouse: this person's account is disabled"},
	"not_entitled":             {"42501", "Gatehouse: this person is not entitled to this database"},
	"not_in_directory":         {"42501", "Gatehouse: the directory has no account for this person; tell the Gatehouse owners"},
	"session_unexpected":       {"42501", "Gatehouse: this pool takes no runner session, but one was sent"},
	"session_missing":          {"42501", "Gatehouse: this pool needs the person behind the run, but no run token was sent; retry shortly"},
	"session_unverifiable":     {"42501", "Gatehouse could not verify this runner session"},
	"session_token":            {"42501", "Gatehouse: this runner session's token was refused"},
	"session_pool":             {"42501", "Gatehouse: this runner session belongs to another pool"},
	"session_unbindable":       {"42501", "Gatehouse could not bind this runner session to its Pod; retry shortly"},
	"session_pod_mismatch":     {"42501", "Gatehouse: this runner session is already bound to another Pod"},
	"requester_unverifiable":   {"42501", "Gatehouse could not verify the person behind this session"},
}

// brokerReason is a fixed-identifier shape, safe to log and to name to the client.
var brokerReason = regexp.MustCompile(`^[a-z][a-z_]{0,47}$`)

func refusalReason(body []byte) string {
	if reason := errorField(body, brokercore.RefusalReasonField); brokerReason.MatchString(reason) {
		return reason
	}
	if code := sqlState(body); sqlStateShape.MatchString(code) {
		return "sqlstate_" + code
	}
	return "unknown"
}

var sqlStateShape = regexp.MustCompile(`^[0-9A-Z]{5}$`)

// refusalsByCode covers a refusal whose reason has no entry: every authorization decision is a 42501.
var refusalsByCode = map[string]string{
	"42501": "Gatehouse: this session's person is not authorized for this database",
	"53300": workerCapMessage,
	"57P03": refusalsByReason["not_ready"].message,
	"3D000": refusalsByReason["no_database"].message,
	"28000": notVerifiedMessage,
}

// brokerRefusal rewrites a broker ErrorResponse in fixed words, keeping its severity; anything unknown is one generic refusal.
func brokerRefusal(severity string, body []byte) []byte {
	if s := errorField(body, 'S'); s == "ERROR" {
		severity = s
	}
	if r, ok := refusalsByReason[errorField(body, brokercore.RefusalReasonField)]; ok {
		return severityFrame(severity, r.code, r.message)
	}
	// A reason with no words still reaches the client by name.
	named := ""
	if reason := errorField(body, brokercore.RefusalReasonField); brokerReason.MatchString(reason) {
		named = " (" + reason + ")"
	}
	code := sqlState(body)
	if message, ok := refusalsByCode[code]; ok {
		return severityFrame(severity, code, message+named)
	}
	return severityFrame(severity, "08004", genericRefusalMessage+named)
}

func refusalFrame(body []byte) []byte { return brokerRefusal("FATAL", body) }

// copyPostgres relays frames whole, so when the broker ends the session at a frame boundary the worker gets one relay-authored FATAL instead of a silent close.
func copyPostgres(ctx context.Context, client, up net.Conn, deadline time.Time, end *ending) {
	_ = client.SetDeadline(deadline)
	_ = up.SetDeadline(deadline)
	// At the task deadline the worker is told; a withdrawn task closes both sides at once.
	stop := context.AfterFunc(ctx, func() {
		end.set(stopCause(ctx))
		if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
			_ = client.Close()
		}
		_ = up.Close()
	})
	defer stop()
	var quiet atomic.Bool
	done := make(chan struct{}, 1)
	go func() {
		// The worker closing, or the relay closing it, ends quietly; a deadline or broker close ends with the relay's frame.
		if _, e := io.Copy(up, watch(client, false, end)); e == nil || errors.Is(e, net.ErrClosed) {
			quiet.Store(true)
		}
		_ = up.Close()
		done <- struct{}{}
	}()
	boundary := relayFrames(client, bufio.NewReaderSize(watch(up, true, end), 32<<10))
	// A relay that is itself stopping (task withdrawn) closes without a frame.
	withdrawn := ctx.Err() != nil && !errors.Is(ctx.Err(), context.DeadlineExceeded)
	if boundary && !quiet.Load() && !withdrawn {
		_ = client.SetWriteDeadline(time.Now().Add(time.Second))
		_, _ = client.Write(errorFrame("08006", sessionEndedMessage))
	}
	_ = client.Close()
	_ = up.Close()
	<-done
}

// maxBrokerErrorBytes bounds an ErrorResponse the relay inspects; larger errors come from the database.
const maxBrokerErrorBytes = 16 << 10

// relayFrames returns true when src ended between frames, the only point the relay may add a frame, and no FATAL was already relayed.
func relayFrames(dst io.Writer, src *bufio.Reader) bool {
	w := bufio.NewWriterSize(dst, 32<<10)
	var head [5]byte
	told := false
	for {
		if src.Buffered() == 0 && w.Flush() != nil {
			return false
		}
		if n, e := io.ReadFull(src, head[:]); e != nil {
			return n == 0 && w.Flush() == nil && !told
		}
		told = false
		length := binary.BigEndian.Uint32(head[1:])
		if length < 4 {
			return false
		}
		if head[0] == 'E' && length <= maxBrokerErrorBytes {
			// A database server error passes unchanged; one the broker authored is replaced with fixed words.
			body := make([]byte, length-4)
			if _, e := io.ReadFull(src, body); e != nil {
				return false
			}
			frame := append(append([]byte(nil), head[:]...), body...)
			if errorField(body, brokercore.RefusalReasonField) != "" {
				frame = brokerRefusal("FATAL", body)
			}
			told = errorField(frame[5:], 'S') == "FATAL"
			if _, e := w.Write(frame); e != nil {
				return false
			}
			continue
		}
		if _, e := w.Write(head[:]); e != nil {
			return false
		}
		if _, e := io.CopyN(w, src, int64(length-4)); e != nil {
			return false
		}
	}
}

func errorFrame(code, message string) []byte { return severityFrame("FATAL", code, message) }

func severityFrame(severity, code, message string) []byte {
	var body []byte
	for _, f := range []struct {
		t byte
		v string
	}{{'S', severity}, {'V', severity}, {'C', code}, {'M', message}} {
		body = append(append(append(body, f.t), f.v...), 0)
	}
	return encodePGFrame('E', append(body, 0))
}

// brokerRouteDatabase accepts 1 to 63 printable ASCII bytes with no space; the broker's catalog decides the rest.
func brokerRouteDatabase(name string) bool {
	if len(name) == 0 || len(name) > 63 {
		return false
	}
	for i := 0; i < len(name); i++ {
		if name[i] < 0x21 || name[i] > 0x7e {
			return false
		}
	}
	return true
}
