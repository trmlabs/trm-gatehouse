package taskrelay

import (
	"bufio"
	"crypto/tls"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/bolt"
)

// brokerSaw is what the fake broker read from the relay.
type brokerSaw struct {
	preamble string
	version  bolt.Version
	hello    map[string]any
	auth     map[string]any
	echoed   bool
}

// startFakeBoltBroker accepts one relay connection over TLS and answers its
// sign-in with refuse (a FAILURE) or SUCCESS, then echoes one request.
func startFakeBoltBroker(t *testing.T, f *relayFixture, refuse []byte) (string, chan brokerSaw) {
	t.Helper()
	l, e := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{f.cert}})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = l.Close() })
	got := make(chan brokerSaw, 1)
	go func() {
		c, e := l.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		r := bufio.NewReader(c)
		var s brokerSaw
		for {
			head, _ := r.Peek(8)
			if string(head) != "GHSESS1 " && string(head) != "GHATTS1 " {
				break
			}
			line, _ := r.ReadString('\n')
			s.preamble += line
		}
		hs, e := bolt.ReadHandshake(r, false)
		if e != nil {
			got <- s
			return
		}
		s.version, _ = hs.Choose(bolt.Supported)
		answer := s.version.Bytes()
		_, _ = c.Write(answer[:])
		read := func() *bolt.Structure {
			raw, e := bolt.ReadRaw(r, 1<<20)
			if e != nil {
				return nil
			}
			m, _ := bolt.Decode(raw)
			return m
		}
		hello := read()
		if hello == nil {
			got <- s
			return
		}
		s.hello, _ = hello.Map(0)
		s.auth = s.hello
		if s.version.AtLeast(5, 1) {
			_ = bolt.WriteRaw(c, bolt.Success(map[string]any{"server": "broker"}))
			logon := read()
			if logon == nil {
				got <- s
				return
			}
			s.auth, _ = logon.Map(0)
		}
		if refuse != nil {
			_ = bolt.WriteRaw(c, refuse)
			got <- s
			return
		}
		_ = bolt.WriteRaw(c, bolt.Success(nil))
		if m := read(); m != nil && m.Tag == bolt.TagReset {
			_ = bolt.WriteRaw(c, bolt.Success(map[string]any{"echo": true}))
			s.echoed = true
		}
		got <- s
	}()
	return l.Addr().String(), got
}

func startBoltRelay(t *testing.T, up UpstreamConfig) string {
	t.Helper()
	listen := freeAddress(t)
	c := FixedConfig{TaskID: "pool-worker", Deadline: time.Now().Add(time.Hour), AuditFile: filepath.Join(t.TempDir(), "audit.jsonl"), Self: true,
		BoltBindings: []BoltConfig{{Listen: listen, Upstream: up, Database: "orion-graph", User: "gatehouse", Placeholder: "gatehouse-relay-placeholder"}}}
	if e := c.Validate(time.Now()); e != nil {
		t.Fatalf("config refused: %v", e)
	}
	go func() { _ = Run(t.Context(), c) }()
	for deadline := time.Now().Add(3 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		if conn, e := net.Dial("tcp", listen); e == nil {
			_ = conn.Close()
			return listen
		}
		if time.Now().After(deadline) {
			t.Fatal("relay never listened")
		}
	}
}

// boltWorker signs in to the relay as a stock driver does.
func boltWorker(t *testing.T, addr string, slots []byte, user, password string) (net.Conn, *bufio.Reader, bolt.Version, *bolt.Structure) {
	t.Helper()
	conn, e := net.Dial("tcp", addr)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = conn.Write(append(append([]byte(nil), bolt.Magic[:]...), slots...))
	r := bufio.NewReader(conn)
	v, e := bolt.ReadVersion(r)
	if e != nil || v == (bolt.Version{}) {
		return conn, r, v, nil
	}
	read := func() *bolt.Structure {
		raw, e := bolt.ReadRaw(r, 1<<20)
		if e != nil {
			return nil
		}
		m, _ := bolt.Decode(raw)
		return m
	}
	auth := map[string]any{"scheme": "basic", "principal": user, "credentials": password}
	hello := map[string]any{"user_agent": "neo4j-python/6.2.0", "routing": map[string]any{"address": addr}}
	if v.AtLeast(5, 1) {
		m, _ := bolt.Encode(bolt.TagHello, hello)
		_ = bolt.WriteRaw(conn, m)
		if reply := read(); reply == nil || reply.Tag != bolt.TagSuccess {
			return conn, r, v, reply
		}
		m, _ = bolt.Encode(bolt.TagLogon, auth)
		_ = bolt.WriteRaw(conn, m)
		return conn, r, v, read()
	}
	for k, val := range auth {
		hello[k] = val
	}
	m, _ := bolt.Encode(bolt.TagHello, hello)
	_ = bolt.WriteRaw(conn, m)
	return conn, r, v, read()
}

func slots(versions ...[3]byte) []byte {
	out := make([]byte, 16)
	for i, s := range versions {
		copy(out[4*i:], []byte{0, s[2], s[1], s[0]})
	}
	return out
}

func TestBoltBindingSignsInWithTheProofNotThePlaceholder(t *testing.T) {
	t.Parallel()
	for name, offer := range map[string][]byte{"5.2": slots([3]byte{5, 8, 8}, [3]byte{4, 4, 2}), "4.3": slots([3]byte{4, 4, 2})} {
		t.Run(name, func(t *testing.T) {
			f := newRelayFixture(t)
			brokerAddr, saw := startFakeBoltBroker(t, f, nil)
			up := f.upstream(t, brokerAddr)
			up.SessionFile = filepath.Join(t.TempDir(), "token")
			writeTestFile(t, up.SessionFile, []byte("eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ1c2VyXzEifQ.c2ln\n"))
			proof, _ := os.ReadFile(up.ProofFile)
			relay := startBoltRelay(t, up)
			conn, r, v, reply := boltWorker(t, relay, offer, "gatehouse", "gatehouse-relay-placeholder")
			if reply == nil || reply.Tag != bolt.TagSuccess {
				t.Fatalf("sign-in answered %+v", reply)
			}
			// After sign-in the relay copies bytes both ways.
			m, _ := bolt.Encode(bolt.TagReset)
			_ = bolt.WriteRaw(conn, m)
			raw, e := bolt.ReadRaw(r, 1<<20)
			if e != nil {
				t.Fatal(e)
			}
			echo, _ := bolt.Decode(raw)
			if meta, _ := echo.Map(0); meta["echo"] != true {
				t.Fatalf("echo %+v", echo)
			}
			s := <-saw
			if s.version != v || s.auth["principal"] != "orion-graph" || s.auth["credentials"] != strings.TrimSpace(string(proof)) || s.auth["scheme"] != "basic" {
				t.Fatalf("broker saw version %v auth %v", s.version, s.auth)
			}
			if !strings.HasPrefix(s.preamble, "GHSESS1 eyJ") || !s.echoed {
				t.Fatalf("broker saw preamble %q echoed %v", s.preamble, s.echoed)
			}
			routing, _ := s.hello["routing"].(map[string]any)
			if routing["address"] != relay || s.hello["user_agent"] != "neo4j-python/6.2.0" {
				t.Fatalf("broker HELLO %v", s.hello)
			}
			for _, leaked := range []string{"gatehouse-relay-placeholder"} {
				for _, field := range []any{s.auth["credentials"], s.auth["principal"]} {
					if field == leaked {
						t.Fatal("the placeholder reached the broker")
					}
				}
			}
		})
	}
}

func TestBoltBindingRefusals(t *testing.T) {
	t.Parallel()
	t.Run("wrong placeholder never reaches the broker", func(t *testing.T) {
		f := newRelayFixture(t)
		brokerAddr, saw := startFakeBoltBroker(t, f, nil)
		relay := startBoltRelay(t, f.upstream(t, brokerAddr))
		_, _, _, reply := boltWorker(t, relay, slots([3]byte{5, 8, 8}), "gatehouse", "a-real-password")
		if reply == nil || reply.Tag != bolt.TagFailure {
			t.Fatalf("wrong placeholder answered %+v", reply)
		}
		select {
		case s := <-saw:
			t.Fatalf("the broker was dialed: %+v", s)
		case <-time.After(300 * time.Millisecond):
		}
	})
	t.Run("no common version", func(t *testing.T) {
		f := newRelayFixture(t)
		brokerAddr, _ := startFakeBoltBroker(t, f, nil)
		relay := startBoltRelay(t, f.upstream(t, brokerAddr))
		_, _, v, _ := boltWorker(t, relay, slots([3]byte{5, 8, 2}), "gatehouse", "gatehouse-relay-placeholder")
		if v != (bolt.Version{}) {
			t.Fatalf("negotiated %v", v)
		}
	})
	t.Run("broker refusal passes through", func(t *testing.T) {
		f := newRelayFixture(t)
		refusal := bolt.Failure("Gatehouse.ClientError.Database.DatabaseNotFound", "Gatehouse: this database isn't in the Gatehouse catalog for your pool")
		brokerAddr, _ := startFakeBoltBroker(t, f, refusal)
		relay := startBoltRelay(t, f.upstream(t, brokerAddr))
		_, _, _, reply := boltWorker(t, relay, slots([3]byte{5, 8, 8}), "gatehouse", "gatehouse-relay-placeholder")
		if meta, _ := reply.Map(0); reply.Tag != bolt.TagFailure || meta["code"] != "Gatehouse.ClientError.Database.DatabaseNotFound" {
			t.Fatalf("refusal %+v", reply)
		}
	})
	t.Run("broker unreachable", func(t *testing.T) {
		f := newRelayFixture(t)
		relay := startBoltRelay(t, f.upstream(t, freeAddress(t)))
		_, _, _, reply := boltWorker(t, relay, slots([3]byte{5, 8, 8}), "gatehouse", "gatehouse-relay-placeholder")
		if meta, _ := reply.Map(0); reply.Tag != bolt.TagFailure || meta["code"] != "Gatehouse.TransientError.General.Unavailable" {
			t.Fatalf("unreachable %+v", reply)
		}
	})
}

func TestBoltBindingConfig(t *testing.T) {
	up := UpstreamConfig{Address: "gatehouse.gatehouse.svc:15443", ServerName: "gatehouse.gatehouse.svc", CAFile: "/ca", ProofFile: "/proof", Audience: "gatehouse"}
	base := func() FixedConfig {
		return FixedConfig{TaskID: "pool-worker", Deadline: time.Now().Add(time.Hour), AuditFile: "/data/audit.jsonl", Self: true,
			BoltBindings: []BoltConfig{{Listen: "127.0.0.1:15100", Upstream: up, Database: "orion-graph", User: "gatehouse", Placeholder: "gatehouse-relay-placeholder"}}}
	}
	if e := base().Validate(time.Now()); e != nil {
		t.Fatalf("valid Bolt sidecar refused: %v", e)
	}
	for name, mutate := range map[string]func(*FixedConfig){
		"off loopback":      func(c *FixedConfig) { c.BoltBindings[0].Listen = "0.0.0.0:15100" },
		"bad database name": func(c *FixedConfig) { c.BoltBindings[0].Database = "orion graph" },
		"no placeholder":    func(c *FixedConfig) { c.BoltBindings[0].Placeholder = "" },
		"shared listen": func(c *FixedConfig) {
			c.PostgresBindings = []PostgresConfig{{Listen: "127.0.0.1:15100", Upstream: up, Database: "core", User: "w", Placeholder: "p"}}
		},
		"shared proxy": func(c *FixedConfig) { c.Self = false; c.Shared = &SharedConfig{} },
	} {
		c := base()
		c.BoltBindings = append([]BoltConfig(nil), c.BoltBindings...)
		mutate(&c)
		if c.Validate(time.Now()) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
