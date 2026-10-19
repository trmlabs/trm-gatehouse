package taskrelay

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
)

// selfListenerConfig is a sidecar with one routed port per broker lane: one
// routed by the broker's catalog, one by a fixed list, each on its own
// upstream.
func selfListenerConfig() FixedConfig {
	c := selfConfig()
	lane := func(address, audience string) UpstreamConfig {
		return UpstreamConfig{Address: address, ServerName: "broker.example.internal", CAFile: "/ca", ProofFile: "/proofs/" + audience, Audience: audience}
	}
	other := lane("other-broker.example.internal:15443", "other-lane")
	other.SessionSocketDir, other.SessionAudience = "/data/identity", "other-lane-session"
	c.PostgresListeners = []PostgresListenerConfig{
		{Listen: "127.0.0.1:15432", Upstream: lane("broker.example.internal:15443", "lane"), Routes: routesBroker, User: "workload", Placeholder: "gatehouse-relay-placeholder"},
		{Listen: "127.0.0.1:15433", Upstream: other, Databases: []string{"reports", "orders"}, User: "workload", Placeholder: "gatehouse-relay-placeholder"},
	}
	return c
}

func TestSelfModeRoutedListenersValidation(t *testing.T) {
	if err := selfListenerConfig().Validate(time.Now()); err != nil {
		t.Fatalf("two routed ports refused: %v", err)
	}
	only := selfListenerConfig()
	only.PostgresBindings = nil
	if err := only.Validate(time.Now()); err != nil {
		t.Fatalf("routed ports without fixed bindings refused: %v", err)
	}
	for name, mutate := range map[string]func(*FixedConfig){
		"listener off loopback":  func(c *FixedConfig) { c.PostgresListeners[0].Listen = "0.0.0.0:15432" },
		"listen shared by ports": func(c *FixedConfig) { c.PostgresListeners[1].Listen = c.PostgresListeners[0].Listen },
		"listen shared by a binding": func(c *FixedConfig) {
			c.PostgresListeners[0].Listen = c.PostgresBindings[0].Listen
		},
		"routes and a list":        func(c *FixedConfig) { c.PostgresListeners[0].Databases = []string{"reports"} },
		"neither routes nor list":  func(c *FixedConfig) { c.PostgresListeners[1].Databases = nil },
		"unknown routes":           func(c *FixedConfig) { c.PostgresListeners[0].Routes = "Broker" },
		"repeated database":        func(c *FixedConfig) { c.PostgresListeners[1].Databases = []string{"reports", "reports"} },
		"malformed database":       func(c *FixedConfig) { c.PostgresListeners[1].Databases = []string{"a b"} },
		"session file and socket":  func(c *FixedConfig) { c.PostgresListeners[1].Upstream.SessionFile = "/data/session" },
		"socket without audience":  func(c *FixedConfig) { c.PostgresListeners[1].Upstream.SessionAudience = "" },
		"relative session file":    func(c *FixedConfig) { c.PostgresListeners[0].Upstream.SessionFile = "session" },
		"no proof":                 func(c *FixedConfig) { c.PostgresListeners[0].Upstream.ProofFile = "" },
		"no audience":              func(c *FixedConfig) { c.PostgresListeners[0].Upstream.Audience = "" },
		"malformed user":           func(c *FixedConfig) { c.PostgresListeners[0].User = "a b" },
		"malformed placeholder":    func(c *FixedConfig) { c.PostgresListeners[0].Placeholder = "" },
		"single shared-mode field": func(c *FixedConfig) { c.PostgresListener = &c.PostgresListeners[0] },
		"more than four": func(c *FixedConfig) {
			for port := 15434; len(c.PostgresListeners) < 5; port++ {
				l := c.PostgresListeners[0]
				l.Listen = net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
				c.PostgresListeners = append(c.PostgresListeners, l)
			}
		},
	} {
		c := selfListenerConfig()
		mutate(&c)
		if c.Validate(time.Now()) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Outside a sidecar the field does not exist.
	f := newRelayFixture(t)
	paired := f.c
	paired.PostgresListeners = []PostgresListenerConfig{{Listen: "127.0.0.1:15432", Upstream: f.upstream(t, "broker.internal:15443"),
		Routes: routesBroker, User: "workload", Placeholder: "placeholder"}}
	if paired.Validate(time.Now()) == nil {
		t.Error("routed ports on a paired relay accepted")
	}
	shared := f.c
	shared.Sandbox, shared.Shared = SandboxConfig{}, sharedConfig()
	shared.Connect = &ConnectConfig{Listen: "0.0.0.0:3128", Upstream: f.upstream(t, "broker.internal:443"), Routes: routesBroker}
	if shared.Validate(time.Now()) != nil {
		t.Fatal("shared base refused")
	}
	shared.PostgresListeners = paired.PostgresListeners
	if shared.Validate(time.Now()) == nil {
		t.Error("sidecar routed ports on a shared proxy accepted")
	}
}

// laneBroker is a fake broker that records what one routed port sends it: the
// session line, the startup's database and the proof the relay presents as
// its password.
type laneBroker struct {
	address string
	seen    chan laneArrival
}

type laneArrival struct {
	session, database, proof string
}

func newLaneBroker(t *testing.T, cert tls.Certificate) *laneBroker {
	t.Helper()
	l, e := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = l.Close() })
	b := &laneBroker{address: l.Addr().String(), seen: make(chan laneArrival, 4)}
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				r := bufio.NewReader(c)
				var a laneArrival
				if head, _ := r.Peek(8); string(head) == "GHSESS1 " {
					line, _ := r.ReadString('\n')
					a.session = line[len("GHSESS1 ") : len(line)-1]
				}
				packet, e := readStartupPacket(r)
				if e != nil {
					return
				}
				var m pgproto3.StartupMessage
				if m.Decode(packet[4:]) != nil {
					return
				}
				a.database = m.Parameters["database"]
				ask, _ := (&pgproto3.AuthenticationCleartextPassword{}).Encode(nil)
				if _, e = c.Write(ask); e != nil {
					return
				}
				typ, body, e := readPGFrame(r, 32<<10)
				if e != nil || typ != 'p' || len(body) == 0 {
					return
				}
				a.proof = string(body[:len(body)-1])
				b.seen <- a
			}(c)
		}
	}()
	return b
}

// Each routed port forwards the worker's database name to its own broker,
// with that broker's proof and that lane's session token; the other broker
// hears nothing of it. A name outside a listed port's databases is refused
// before any broker is dialed.
func TestSelfModeRoutedListenersReachTheirOwnBroker(t *testing.T) {
	f := newRelayFixture(t)
	lanes := map[string]*laneBroker{"lane": newLaneBroker(t, f.cert), "other-lane": newLaneBroker(t, f.cert)}
	dir := t.TempDir()
	upstream := func(audience string) UpstreamConfig {
		up := f.upstream(t, lanes[audience].address)
		up.Audience = audience
		writeTestFile(t, up.ProofFile, []byte(testProof(time.Now().Add(time.Hour), audience)))
		up.SessionFile = filepath.Join(dir, audience+"-session")
		writeTestFile(t, up.SessionFile, []byte(sessionFor(audience)+"\n"))
		return up
	}
	c := FixedConfig{TaskID: "pool-worker", Deadline: time.Now().Add(time.Hour), AuditFile: filepath.Join(dir, "audit.jsonl"), Self: true,
		PostgresListeners: []PostgresListenerConfig{
			{Listen: freeAddress(t), Upstream: upstream("lane"), Routes: routesBroker, User: "workload", Placeholder: "gatehouse-relay-placeholder"},
			{Listen: freeAddress(t), Upstream: upstream("other-lane"), Databases: []string{"reports"}, User: "workload", Placeholder: "gatehouse-relay-placeholder"},
		}}
	if e := c.Validate(time.Now()); e != nil {
		t.Fatalf("config refused: %v", e)
	}
	go func() { _ = Run(t.Context(), c) }()
	startup := func(listen, database string) (byte, []byte) {
		var conn net.Conn
		var e error
		for deadline := time.Now().Add(3 * time.Second); ; time.Sleep(20 * time.Millisecond) {
			if conn, e = net.Dial("tcp", listen); e == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("relay never listened")
			}
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		b, _ := (&pgproto3.StartupMessage{ProtocolVersion: pgproto3.ProtocolVersionNumber, Parameters: map[string]string{"user": "workload", "database": database}}).Encode(nil)
		_, _ = conn.Write(b)
		typ, body, e := readPGFrame(conn, 8192)
		if e != nil {
			t.Fatalf("%s: %v", database, e)
		}
		if typ == 'R' && binary.BigEndian.Uint32(body) == 3 {
			_, _ = conn.Write(encodePGFrame('p', []byte("gatehouse-relay-placeholder\x00")))
			// The fake broker stops after the proof; the relay then ends the
			// session, so there is nothing more to read.
		}
		return typ, body
	}
	expect := func(audience, database string) {
		t.Helper()
		select {
		case a := <-lanes[audience].seen:
			if a.database != database || a.session != sessionFor(audience) || claimAudience(t, a.proof) != audience {
				t.Fatalf("%s saw %+v", audience, a)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("nothing reached %s", audience)
		}
	}
	quiet := func(audience string) {
		t.Helper()
		select {
		case a := <-lanes[audience].seen:
			t.Fatalf("%s heard another port's session: %+v", audience, a)
		case <-time.After(200 * time.Millisecond):
		}
	}
	startup(c.PostgresListeners[0].Listen, "any-catalog-name")
	expect("lane", "any-catalog-name")
	quiet("other-lane")
	startup(c.PostgresListeners[1].Listen, "reports")
	expect("other-lane", "reports")
	quiet("lane")
	if typ, body := startup(c.PostgresListeners[1].Listen, "not-listed"); typ != 'E' || sqlState(body) != "3D000" {
		t.Fatalf("an unlisted name: %c %s", typ, sqlState(body))
	}
	quiet("lane")
	quiet("other-lane")
}

func sessionFor(audience string) string {
	return "e30.e30." + audience
}

// claimAudience is the single audience a test proof names.
func claimAudience(t *testing.T, proof string) string {
	t.Helper()
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		return ""
	}
	payload, e := base64.RawURLEncoding.DecodeString(parts[1])
	var claims struct {
		Aud []string `json:"aud"`
	}
	if e != nil || json.Unmarshal(payload, &claims) != nil || len(claims.Aud) != 1 {
		return ""
	}
	return claims.Aud[0]
}
