package pgproxy

import (
	"errors"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/auditchain"
	"github.com/Infisical/agent-vault/internal/bolt"
)

var testPlans = map[string][]string{
	"MATCH (n) RETURN n":        {" * Produce {n}", " * ScanAll (n)", " * Once"},
	"MATCH (n) RETURN n.x AS x": {" * Produce {x}", " * ScanAll (n)", " * Once"},
	"CREATE (:X)":               {" * EmptyResult", " * CreateNode", " * Once"},
	"MATCH (n) SET n.x = 1":     {" * EmptyResult", " * SetProperty", " * ScanAll (n)", " * Once"},
	"CALL periodic.iterate('MATCH (n) RETURN n', 'SET n.x = 1', {batch_size: 1}) YIELD success RETURN success": {
		" * Produce {success}", " * CallProcedure<periodic.iterate> {success}", " * Once"},
	"CALL schema.node_type_properties() YIELD nodeType RETURN nodeType": {
		" * Produce {nodeType}", " * CallProcedure<schema.node_type_properties> {nodeType}", " * Once"},
	"LOAD CSV FROM '/etc/passwd' NO HEADER AS row RETURN row": {" * Produce {row}", " * LoadCsv {row}", " * Once"},
	"MATCH (n) RETURN date.add(n.d, 1, 'day') AS d":           {" * Produce {d}", " * ScanAll (n)", " * Once"},
}

type boltFixture struct {
	upstream *fakeMemgraph
	audit    *recordingAudit
	auth     *fakeAuth
	graphs   *fakeGraphs
	addr     string
}

func startBoltFixture(t *testing.T, change func(*Options)) *boltFixture {
	t.Helper()
	f := &boltFixture{
		upstream: startFakeMemgraph(t, "gatehouse_reader", "broker-held-secret", testPlans),
		audit:    &recordingAudit{},
		auth:     &fakeAuth{scope: &AgentScope{VaultID: "vault-1", ActorID: "agent-1", WorkloadID: "pod-1", Pool: "cursor-agents"}},
	}
	f.graphs = &fakeGraphs{svc: &GraphService{Name: "app-graph", Addr: f.upstream.addr(), Plaintext: true,
		Procedures: []string{"schema.node_type_properties"}, Functions: []string{"date.add"}}}
	opts := Options{
		Auth:        f.auth,
		Databases:   &fakeResolver{err: errors.New("no postgres here")},
		Leases:      &fakeMinter{lease: newLease()},
		Graphs:      f.graphs,
		GraphLogins: fakeLogins{login: &GraphLogin{Username: "gatehouse_reader", Password: "broker-held-secret"}},
		Audit:       f.audit,
	}
	if change != nil {
		change(&opts)
	}
	_, f.addr = startBroker(t, opts)
	return f
}

var bolt52 = proposals([3]byte{5, 8, 8}, [3]byte{4, 4, 2})

func signedIn(t *testing.T, f *boltFixture) *boltTestClient {
	t.Helper()
	c, reply := dialBoltTest(t, f.addr, bolt52, "app-graph", "agent-proof-token")
	if reply == nil || reply.Tag != bolt.TagSuccess {
		t.Fatalf("sign-in answered %+v", reply)
	}
	return c
}

func TestBolt_ReadsRunInARolledBackReadTransaction(t *testing.T) {
	f := startBoltFixture(t, nil)
	c := signedIn(t, f)
	if c.v != (bolt.Version{Major: 5, Minor: 2}) {
		t.Fatalf("negotiated %v", c.v)
	}
	if got := f.auth.gotToken; got != "agent-proof-token" {
		t.Fatalf("broker authenticated %q", got)
	}
	res := c.query("MATCH (n) RETURN n", nil, map[string]any{"mode": "w", "tx_metadata": map[string]any{"app": "test"}})
	if res.code != "" || len(res.records) != 2 {
		t.Fatalf("read: %+v", res)
	}
	want := []string{"LOGIN gatehouse_reader", "EXPLAIN MATCH (n) RETURN n", "BEGIN mode=r", "RUN MATCH (n) RETURN n tx=true", "ROLLBACK"}
	if got := f.upstream.entries(); !slices.Equal(got, want) {
		t.Fatalf("upstream saw %q, want %q", got, want)
	}
}

func TestBolt_RefusesWritesBeforeTheyReachTheDatabase(t *testing.T) {
	f := startBoltFixture(t, nil)
	c := signedIn(t, f)
	for query, step := range map[string]string{
		"CREATE (:X)":           "CreateNode",
		"MATCH (n) SET n.x = 1": "SetProperty",
		"CALL periodic.iterate('MATCH (n) RETURN n', 'SET n.x = 1', {batch_size: 1}) YIELD success RETURN success": "CALL periodic.iterate",
		"LOAD CSV FROM '/etc/passwd' NO HEADER AS row RETURN row":                                                  "LoadCsv",
		"RETURN llm.complete('hello') AS a":                                                                        "function llm.complete",
	} {
		res := c.query(query, nil, nil)
		if res.code != "Gatehouse.ClientError.Statement.AccessMode" || !strings.Contains(res.message, step) {
			t.Fatalf("%q: %+v", query, res)
		}
		// After a refusal every request is IGNORED until RESET, as after
		// any failure.
		if again := c.query("MATCH (n) RETURN n", nil, nil); !again.ignored {
			t.Fatalf("request after a refusal: %+v", again)
		}
		c.reset()
	}
	for _, entry := range f.upstream.entries() {
		if strings.HasPrefix(entry, "RUN ") || entry == "COMMIT" || strings.HasPrefix(entry, "BEGIN") {
			t.Fatalf("a refused query reached the database: %q", entry)
		}
	}
	// Each refusal is audited with what was refused, never the query.
	var decisions []string
	for _, e := range f.audit.recorded() {
		if e.Event == auditchain.EventDenied && e.Outcome == "read_only" && e.Operation == "bolt.query" && e.Agent == "agent-1" {
			decisions = append(decisions, e.Decision)
		}
	}
	slices.Sort(decisions)
	if want := []string{"function:llm.complete", "procedure:periodic.iterate", "step:CreateNode", "step:LoadCsv", "step:SetProperty"}; !slices.Equal(decisions, want) {
		t.Fatalf("audited refusals %q, want %q", decisions, want)
	}
}

func TestBolt_ListedProceduresAndFunctionsRun(t *testing.T) {
	f := startBoltFixture(t, nil)
	c := signedIn(t, f)
	for _, query := range []string{"CALL schema.node_type_properties() YIELD nodeType RETURN nodeType", "MATCH (n) RETURN date.add(n.d, 1, 'day') AS d"} {
		if res := c.query(query, nil, nil); res.code != "" {
			t.Fatalf("%q refused: %+v", query, res)
		}
	}
}

func TestBolt_ExplicitTransactionCommitsNothing(t *testing.T) {
	f := startBoltFixture(t, nil)
	c := signedIn(t, f)
	if reply := c.call(bolt.TagBegin, map[string]any{"mode": "w", "db": "memgraph"}); reply.Tag != bolt.TagSuccess {
		t.Fatalf("BEGIN: %+v", reply)
	}
	if res := c.query("MATCH (n) RETURN n.x AS x", nil, nil); res.code != "" || len(res.records) != 2 {
		t.Fatalf("read in transaction: %+v", res)
	}
	if reply := c.call(bolt.TagCommit); reply.Tag != bolt.TagSuccess {
		t.Fatalf("COMMIT: %+v", reply)
	}
	want := []string{"LOGIN gatehouse_reader", "BEGIN mode=r", "EXPLAIN MATCH (n) RETURN n.x AS x", "RUN MATCH (n) RETURN n.x AS x tx=true", "ROLLBACK"}
	if got := f.upstream.entries(); !slices.Equal(got, want) {
		t.Fatalf("upstream saw %q, want %q", got, want)
	}
	// Another database or an impersonated user is refused.
	for _, extra := range []map[string]any{{"db": "other"}, {"imp_user": "admin"}} {
		if reply := c.call(bolt.TagBegin, extra); reply.Tag != bolt.TagFailure {
			t.Fatalf("BEGIN %v: %+v", extra, reply)
		}
		c.reset()
	}
}

func TestBolt_UnplannableQueryReturnsTheDatabaseError(t *testing.T) {
	f := startBoltFixture(t, nil)
	c := signedIn(t, f)
	res := c.query("SHOW USERS", nil, nil)
	if !strings.HasPrefix(res.code, "Memgraph.") || !strings.Contains(res.message, "parsing error") {
		t.Fatalf("unplannable query: %+v", res)
	}
	c.reset()
	if res := c.query("MATCH (n) RETURN n", nil, nil); res.code != "" {
		t.Fatalf("read after RESET: %+v", res)
	}
}

func TestBolt_SignInRefusals(t *testing.T) {
	t.Run("bad proof", func(t *testing.T) {
		f := startBoltFixture(t, nil)
		f.auth.err = errors.New("token rejected")
		_, reply := dialBoltTest(t, f.addr, bolt52, "app-graph", "forged")
		if reply == nil || reply.Tag != bolt.TagFailure {
			t.Fatalf("sign-in with a bad proof: %+v", reply)
		}
		if meta, _ := reply.Map(0); meta["code"] != "Gatehouse.ClientError.Security.Unauthorized" {
			t.Fatalf("code %v", meta["code"])
		}
	})
	t.Run("unknown graph", func(t *testing.T) {
		f := startBoltFixture(t, nil)
		_, reply := dialBoltTest(t, f.addr, bolt52, "not-in-catalog", "agent-proof-token")
		if meta, _ := reply.Map(0); reply.Tag != bolt.TagFailure || meta["code"] != "Gatehouse.ClientError.Database.DatabaseNotFound" {
			t.Fatalf("unknown graph: %+v", reply)
		}
	})
	t.Run("tier refusal", func(t *testing.T) {
		f := startBoltFixture(t, nil)
		f.graphs.err = &RefusedError{Outcome: "no_person"}
		_, reply := dialBoltTest(t, f.addr, bolt52, "app-graph", "agent-proof-token")
		if meta, _ := reply.Map(0); reply.Tag != bolt.TagFailure || meta["code"] != "Gatehouse.ClientError.Security.Forbidden" {
			t.Fatalf("tier refusal: %+v", reply)
		}
	})
	t.Run("database refuses the broker's login", func(t *testing.T) {
		f := startBoltFixture(t, func(o *Options) {
			o.GraphLogins = fakeLogins{login: &GraphLogin{Username: "gatehouse_reader", Password: "rotated-away"}}
		})
		_, reply := dialBoltTest(t, f.addr, bolt52, "app-graph", "agent-proof-token")
		meta, _ := reply.Map(0)
		if reply.Tag != bolt.TagFailure || meta["code"] != "Gatehouse.TransientError.General.DatabaseUnavailable" {
			t.Fatalf("refused login: %+v", reply)
		}
		if msg, _ := meta["message"].(string); strings.Contains(msg, "rotated-away") || strings.Contains(msg, "gatehouse_reader") {
			t.Fatalf("the refusal disclosed the login: %q", msg)
		}
	})
	t.Run("no login in Vault", func(t *testing.T) {
		f := startBoltFixture(t, func(o *Options) { o.GraphLogins = fakeLogins{err: errors.New("deleted")} })
		_, reply := dialBoltTest(t, f.addr, bolt52, "app-graph", "agent-proof-token")
		if meta, _ := reply.Map(0); reply.Tag != bolt.TagFailure || meta["code"] != "Gatehouse.TransientError.General.CredentialUnavailable" {
			t.Fatalf("missing login: %+v", reply)
		}
	})
	t.Run("no common version", func(t *testing.T) {
		f := startBoltFixture(t, nil)
		c, _ := dialBoltTest(t, f.addr, proposals([3]byte{5, 8, 2}), "app-graph", "agent-proof-token")
		if c.v != (bolt.Version{}) {
			t.Fatalf("negotiated %v with 5.8 to 5.6 only", c.v)
		}
	})
	t.Run("graphs not configured", func(t *testing.T) {
		f := startBoltFixture(t, func(o *Options) { o.Graphs = nil })
		conn, err := net.DialTimeout("tcp", f.addr, 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := conn.Write(append(bolt.Magic[:], bolt52...)); err != nil {
			t.Fatal(err)
		}
		if n, err := conn.Read(make([]byte, 4)); err == nil || n > 0 {
			t.Fatal("a Bolt connection was answered with no graphs configured")
		}
	})
}

func TestBolt_Version43SignsInThroughHello(t *testing.T) {
	f := startBoltFixture(t, nil)
	c, reply := dialBoltTest(t, f.addr, proposals([3]byte{4, 4, 2}), "app-graph", "agent-proof-token")
	if c.v != (bolt.Version{Major: 4, Minor: 3}) || reply.Tag != bolt.TagSuccess {
		t.Fatalf("4.3 sign-in: %v %+v", c.v, reply)
	}
	if res := c.query("MATCH (n) RETURN n", nil, nil); res.code != "" || len(res.records) != 2 {
		t.Fatalf("read over 4.3: %+v", res)
	}
}

func TestBolt_SessionRulesAfterSignIn(t *testing.T) {
	f := startBoltFixture(t, nil)
	c := signedIn(t, f)
	// ROUTE is answered by the broker with the address the client dialed.
	reply := c.call(bolt.TagRoute, map[string]any{"address": "127.0.0.1:15100"}, []any{}, map[string]any{})
	meta, _ := reply.Map(0)
	rt, _ := meta["rt"].(map[string]any)
	if reply.Tag != bolt.TagSuccess || rt == nil || len(rt["servers"].([]any)) != 3 {
		t.Fatalf("ROUTE: %+v", reply)
	}
	// Signing in again on an open connection ends it.
	reply = c.call(bolt.TagLogon, map[string]any{"scheme": "basic", "principal": "admin", "credentials": "x"})
	if reply.Tag != bolt.TagFailure {
		t.Fatalf("LOGON after sign-in: %+v", reply)
	}
	if _, err := c.tryRead(); err == nil {
		t.Fatal("connection stayed open after a second LOGON")
	}
	var opened, closed int
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		opened, closed = 0, 0
		for _, e := range f.audit.recorded() {
			if e.Operation != "bolt.session" {
				continue
			}
			switch e.Event {
			case auditchain.EventSessionOpen:
				opened++
				if e.Binding != "vault-1/app-graph" || e.Pool != "cursor-agents" || e.PodUID != "pod-1" {
					t.Fatalf("session row: %+v", e)
				}
			case auditchain.EventSessionClose:
				closed++
			}
		}
		if closed == 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if opened != 1 || closed != 1 {
		t.Fatalf("audit rows: %d opened, %d closed", opened, closed)
	}
}

func TestBolt_RecheckEndsARevokedSession(t *testing.T) {
	f := startBoltFixture(t, func(o *Options) { o.AuthorizationInterval = 50 * time.Millisecond })
	c := signedIn(t, f)
	f.graphs.mu.Lock()
	f.graphs.err = &RefusedError{Outcome: "not_in_group"}
	f.graphs.mu.Unlock()
	_ = c.conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.tryRead(); err == nil {
		t.Fatal("a revoked session stayed open")
	}
}

func TestBolt_PostgresStillServedOnTheSameListener(t *testing.T) {
	// The magic sniff must hand every non-Bolt stream back unchanged.
	lease := newLease()
	upstream := startFakeUpstream(t, authTrust, "")
	_, addr := startBroker(t, Options{
		Auth:      &fakeAuth{scope: &AgentScope{VaultID: "vault-1", VaultName: "demo", ActorID: "agent-7"}},
		Databases: &fakeResolver{svc: &DatabaseService{Name: "analytics", Addr: upstream.addr(), Mount: "database", Role: "readonly", SSLMode: "disable"}},
		Leases:    &fakeMinter{lease: lease},
		Graphs:    &fakeGraphs{},
	})
	session := openAgentSession(t, addr, "agent-token", "analytics")
	if _, err := session.query("SELECT 1"); err != nil {
		t.Fatalf("PostgreSQL on the shared listener: %v", err)
	}
}
