//go:build realmemgraph

package pgproxy

// The Bolt path against a real Memgraph. Requires a disposable Memgraph
// serving Bolt over TLS, with a login the broker uses and a small graph:
//
//	AV_TEST_MEMGRAPH_ADDR         host:port
//	AV_TEST_MEMGRAPH_SERVER_NAME  the name on its certificate
//	AV_TEST_MEMGRAPH_CA_FILE      its self-signed certificate (PEM), pinned
//	AV_TEST_MEMGRAPH_USER, AV_TEST_MEMGRAPH_PASSWORD
//
// AV_TEST_BOLT_DRIVER_CHECK, when set, is a command run with the broker's
// address as its last argument, such as a stock driver's check script; it
// must exit 0.

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/pem"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/bolt"
	"github.com/Infisical/agent-vault/internal/taskrelay"
)

func TestRealMemgraph_ReadOnlyThroughTheBroker(t *testing.T) {
	addr := os.Getenv("AV_TEST_MEMGRAPH_ADDR")
	if addr == "" {
		t.Skip("set AV_TEST_MEMGRAPH_ADDR")
	}
	ca, err := os.ReadFile(os.Getenv("AV_TEST_MEMGRAPH_CA_FILE"))
	if err != nil {
		t.Fatal(err)
	}
	login := &GraphLogin{Username: os.Getenv("AV_TEST_MEMGRAPH_USER"), Password: os.Getenv("AV_TEST_MEMGRAPH_PASSWORD")}
	svc := &GraphService{Name: "app-graph", Addr: addr, ServerName: os.Getenv("AV_TEST_MEMGRAPH_SERVER_NAME"), CA: string(ca),
		Procedures: []string{"schema.node_type_properties"}, Functions: []string{"date.add"}}
	audit := &recordingAudit{}
	auth := &fakeAuth{scope: &AgentScope{VaultID: "vault-1", ActorID: "agent-1", WorkloadID: "pod-1", Pool: "cursor-agents"}}
	_, broker := startBroker(t, Options{
		Auth:        auth,
		Databases:   &fakeResolver{},
		Leases:      &fakeMinter{lease: newLease()},
		Graphs:      &fakeGraphs{svc: svc},
		GraphLogins: fakeLogins{login: login},
		Audit:       audit,
	})

	// The graph as Memgraph holds it, read directly with the broker's login.
	nodes := func() int64 {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		direct, err := dialBolt(ctx, (&net.Dialer{}).DialContext, svc, bolt.Version{Major: 5, Minor: 2}, login, 1<<20)
		if err != nil {
			t.Fatalf("direct: %v", err)
		}
		defer func() { _ = direct.conn.Close() }()
		run, _ := bolt.Encode(bolt.TagRun, "MATCH (n) RETURN count(n) AS c", map[string]any{}, map[string]any{})
		pull, _ := bolt.Encode(bolt.TagPull, map[string]any{"n": int64(-1)})
		if err := direct.send(run, pull); err != nil {
			t.Fatal(err)
		}
		var count int64 = -1
		for {
			msg, _, err := direct.readMessage()
			if err != nil {
				t.Fatal(err)
			}
			if msg.Tag == bolt.TagRecord {
				count = msg.Fields[0].([]any)[0].(int64)
				continue
			}
			if msg.Tag == bolt.TagSuccess && count >= 0 {
				return count
			}
			if msg.Tag != bolt.TagSuccess {
				t.Fatalf("direct count: 0x%02X", msg.Tag)
			}
		}
	}
	before := nodes()

	for _, version := range [][]byte{bolt52, proposals([3]byte{4, 4, 2})} {
		c, reply := dialBoltTest(t, broker, version, "app-graph", "agent-proof-token")
		if reply == nil || reply.Tag != bolt.TagSuccess {
			t.Fatalf("sign-in: %+v", reply)
		}
		t.Logf("negotiated Bolt %v", c.v)
		reads := map[string]int{
			"MATCH (n:Person) RETURN n.name AS name ORDER BY name":                       3,
			"MATCH (a)-[r:KNOWS]->(b) RETURN a, r, b":                                    1,
			"MATCH p=(a)-[*1..2]->(b) RETURN p":                                          1,
			"MATCH (n) WHERE n.n > $min RETURN count(n) AS c":                            1,
			"CALL schema.node_type_properties() YIELD nodeType RETURN DISTINCT nodeType": 1,
			"RETURN date.add(100, 'ms', 5, 'ms') AS d":                                   1,
		}
		for query, rows := range reads {
			res := c.query(query, map[string]any{"min": int64(1)}, nil)
			if res.code != "" || len(res.records) != rows {
				t.Fatalf("%q: %+v", query, res)
			}
		}
		refused := map[string]string{
			"CREATE (:Probe)":                       "CreateNode",
			"MATCH (n) SET n.touched = true":        "SetProperty",
			"MATCH (n) DETACH DELETE n":             "Delete",
			"MERGE (n:Person {name: 'z'}) RETURN n": "Merge",
			"CALL periodic.iterate('UNWIND range(1, 3) AS x RETURN x', 'CREATE (:Escape {x: x})', {batch_size: 1}) YIELD success RETURN success": "CALL periodic.iterate",
			"USING PERIODIC COMMIT 1 UNWIND range(1, 3) AS x CREATE (:Escape {x: x})":                                                            "PeriodicCommit",
			"CALL export_util.json('/var/lib/memgraph/escape.json') YIELD path RETURN path":                                                      "CALL export_util.json",
			"LOAD CSV FROM '/etc/passwd' NO HEADER AS row RETURN row":                                                                            "LoadCsv",
			"RETURN llm.complete('hello') AS answer":                                                                                             "function llm.complete",
		}
		for query, step := range refused {
			res := c.query(query, nil, nil)
			if res.code != "Gatehouse.ClientError.Statement.AccessMode" || !strings.Contains(res.message, step) {
				t.Fatalf("%q: %+v", query, res)
			}
			c.reset()
		}
		// Statements Memgraph will not plan never run: its own error comes back.
		for _, query := range []string{"CREATE INDEX ON :Person(name)", "CREATE USER intruder IDENTIFIED BY 'x'", "SHOW USERS", "DROP GRAPH", "STORAGE MODE IN_MEMORY_ANALYTICAL"} {
			if res := c.query(query, nil, nil); res.code == "" {
				t.Fatalf("%q ran: %+v", query, res)
			}
			c.reset()
		}
		// An explicit transaction reads, and its COMMIT persists nothing.
		if reply := c.call(bolt.TagBegin, map[string]any{"mode": "w"}); reply.Tag != bolt.TagSuccess {
			t.Fatalf("BEGIN: %+v", reply)
		}
		if res := c.query("MATCH (n) RETURN n", nil, nil); res.code != "" || len(res.records) == 0 {
			t.Fatalf("read in transaction: %+v", res)
		}
		if reply := c.call(bolt.TagCommit); reply.Tag != bolt.TagSuccess {
			t.Fatalf("COMMIT: %+v", reply)
		}
		c.send(bolt.TagGoodbye)
	}

	if after := nodes(); after != before {
		t.Fatalf("the graph changed through the broker: %d nodes before, %d after", before, after)
	}
	if cmd := os.Getenv("AV_TEST_BOLT_DRIVER_CHECK"); cmd != "" {
		args := strings.Fields(cmd)
		out, err := exec.Command(args[0], append(args[1:], broker)...).CombinedOutput() // #nosec G204 -- test-only command from the test's own environment
		t.Logf("driver check:\n%s", out)
		if err != nil {
			t.Fatalf("driver check failed: %v", err)
		}
		if after := nodes(); after != before {
			t.Fatalf("the graph changed through the stock driver: %d nodes before, %d after", before, after)
		}

		// The whole path a worker uses: the stock driver signs in to its
		// sidecar with the placeholder, the sidecar reaches the broker over
		// TLS (here a terminator standing in for the broker Pod's) with the
		// worker's proof, and the broker reaches Memgraph with its login.
		relay := startBoltSidecar(t, broker)
		out, err = exec.Command(args[0], append(args[1:], "gatehouse", "gatehouse-relay-placeholder", relay)...).CombinedOutput() // #nosec G204 -- test-only command from the test's own environment
		t.Logf("driver check through the sidecar:\n%s", out)
		if err != nil {
			t.Fatalf("driver check through the sidecar failed: %v", err)
		}
		if got := auth.token(); got != relayProof {
			t.Fatalf("the broker authenticated %q, not the sidecar's proof", got)
		}
		if after := nodes(); after != before {
			t.Fatalf("the graph changed through the sidecar: %d nodes before, %d after", before, after)
		}
	}
	t.Logf("audit rows: %d", len(audit.recorded()))
}

// relayProof is the synthetic identity proof the sidecar presents.
var relayProof = "e30." + base64.RawURLEncoding.EncodeToString([]byte(`{"exp":4102444800,"aud":["gatehouse"]}`)) + ".synthetic"

// startBoltSidecar runs a worker sidecar with one Bolt binding, reaching the
// broker through a TLS terminator, and returns the sidecar's local address.
func startBoltSidecar(t *testing.T, broker string) string {
	t.Helper()
	cfg := selfSignedTLSConfig(t)
	terminator, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = terminator.Close() })
	go func() {
		for {
			c, err := terminator.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				up, err := net.Dial("tcp", broker)
				if err != nil {
					return
				}
				defer func() { _ = up.Close() }()
				go func() { _, _ = io.Copy(up, c); _ = up.Close() }()
				_, _ = io.Copy(c, up)
			}()
		}
	}()
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	proof := filepath.Join(dir, "proof")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cfg.Certificates[0].Certificate[0]}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(proof, []byte(relayProof), 0o600); err != nil {
		t.Fatal(err)
	}
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listen := probe.Addr().String()
	_ = probe.Close()
	c := taskrelay.FixedConfig{TaskID: "pool-worker", Deadline: time.Now().Add(time.Hour), AuditFile: filepath.Join(dir, "audit.jsonl"), Self: true,
		BoltBindings: []taskrelay.BoltConfig{{Listen: listen, Database: "app-graph", User: "gatehouse", Placeholder: "gatehouse-relay-placeholder",
			Upstream: taskrelay.UpstreamConfig{Address: terminator.Addr().String(), ServerName: "127.0.0.1", CAFile: ca, ProofFile: proof, Audience: "gatehouse"}}}}
	if err := c.Validate(time.Now()); err != nil {
		t.Fatal(err)
	}
	go func() { _ = taskrelay.Run(t.Context(), c) }()
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		if conn, err := net.Dial("tcp", listen); err == nil {
			_ = conn.Close()
			return listen
		}
		if time.Now().After(deadline) {
			t.Fatal("the sidecar never listened")
		}
	}
}

func (f *fakeAuth) token() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.gotToken
}
