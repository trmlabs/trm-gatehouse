package taskrelay

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/bolt"
)

const (
	boltPlaceholder = "gatehouse-relay-placeholder"
	boltSession     = "e30.e30.bolt-session"
)

func selfBoltConfig() FixedConfig {
	c := selfConfig()
	up := c.PostgresBindings[0].Upstream
	c.BoltListeners = []BoltListenerConfig{
		{Listen: "127.0.0.1:17687", Upstream: up, Routes: routesBroker, Placeholder: boltPlaceholder},
		{Listen: "127.0.0.1:17688", Upstream: up, Entries: []string{"graph-reports", "graph-orders"}, Placeholder: boltPlaceholder},
	}
	return c
}

func TestBoltListenersValidation(t *testing.T) {
	if err := selfBoltConfig().Validate(time.Now()); err != nil {
		t.Fatalf("two Bolt ports refused: %v", err)
	}
	only := selfBoltConfig()
	only.PostgresBindings = nil
	if err := only.Validate(time.Now()); err != nil {
		t.Fatalf("Bolt ports without PostgreSQL refused: %v", err)
	}
	for name, mutate := range map[string]func(*FixedConfig){
		"listener off loopback":     func(c *FixedConfig) { c.BoltListeners[0].Listen = "0.0.0.0:17687" },
		"listen shared by ports":    func(c *FixedConfig) { c.BoltListeners[1].Listen = c.BoltListeners[0].Listen },
		"listen shared by postgres": func(c *FixedConfig) { c.BoltListeners[0].Listen = c.PostgresBindings[0].Listen },
		"routes and a list":         func(c *FixedConfig) { c.BoltListeners[0].Entries = []string{"graph-reports"} },
		"neither routes nor list":   func(c *FixedConfig) { c.BoltListeners[1].Entries = nil },
		"unknown routes":            func(c *FixedConfig) { c.BoltListeners[0].Routes = "Broker" },
		"repeated entry":            func(c *FixedConfig) { c.BoltListeners[1].Entries = []string{"graph", "graph"} },
		"malformed entry":           func(c *FixedConfig) { c.BoltListeners[1].Entries = []string{"a b"} },
		"no placeholder":            func(c *FixedConfig) { c.BoltListeners[0].Placeholder = "" },
		"no proof":                  func(c *FixedConfig) { c.BoltListeners[0].Upstream.ProofFile = "" },
		"no audience":               func(c *FixedConfig) { c.BoltListeners[0].Upstream.Audience = "" },
		"relative session file":     func(c *FixedConfig) { c.BoltListeners[0].Upstream.SessionFile = "session" },
		"session file and socket": func(c *FixedConfig) {
			c.BoltListeners[0].Upstream.SessionFile, c.BoltListeners[0].Upstream.SessionSocketDir = "/s", "/d"
		},
		"socket without an audience": func(c *FixedConfig) { c.BoltListeners[0].Upstream.SessionSocketDir = "/data/identity" },
		"more than four": func(c *FixedConfig) {
			for port := 17689; len(c.BoltListeners) < 5; port++ {
				l := c.BoltListeners[0]
				l.Listen = net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
				c.BoltListeners = append(c.BoltListeners, l)
			}
		},
	} {
		c := selfBoltConfig()
		c.BoltListeners = append([]BoltListenerConfig(nil), c.BoltListeners...)
		mutate(&c)
		if c.Validate(time.Now()) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A paired relay or a shared proxy has no Bolt ports.
	f := newRelayFixture(t)
	paired := f.c
	paired.BoltListeners = []BoltListenerConfig{{Listen: "127.0.0.1:17687", Upstream: f.upstream(t, "broker.internal:15443"), Routes: routesBroker, Placeholder: boltPlaceholder}}
	if paired.Validate(time.Now()) == nil {
		t.Error("Bolt ports on a paired relay accepted")
	}
	shared := f.c
	shared.Sandbox, shared.Shared = SandboxConfig{}, sharedConfig()
	shared.Connect = &ConnectConfig{Listen: "0.0.0.0:3128", Upstream: f.upstream(t, "broker.internal:443"), Routes: routesBroker}
	if shared.Validate(time.Now()) != nil {
		t.Fatal("shared base refused")
	}
	shared.BoltListeners = paired.BoltListeners
	if shared.Validate(time.Now()) == nil {
		t.Error("Bolt ports on a shared proxy accepted")
	}
}

// boltArrival is what the fake broker saw on one connection.
type boltArrival struct {
	session   string
	handshake []byte
	opening   []*bolt.Structure
}

// boltBroker is a fake broker's Bolt side: it reads the session line and the
// handshake, answers a version, reads the opening messages and answers each,
// then answers every RUN with one record holding the RUN's query and a
// SUCCESS.
type boltBroker struct {
	address string
	seen    chan boltArrival
	// version, if set, is the answer to every handshake in place of the
	// client's choice; failure, if set, refuses the login with this reason.
	version *bolt.Version
	failure string
}

func newBoltBroker(t *testing.T, cert tls.Certificate, configure func(*boltBroker)) *boltBroker {
	t.Helper()
	l, e := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = l.Close() })
	b := &boltBroker{address: l.Addr().String(), seen: make(chan boltArrival, 8)}
	if configure != nil {
		configure(b)
	}
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			go b.serve(c)
		}
	}()
	return b
}

func (b *boltBroker) serve(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	r := bufio.NewReader(c)
	var a boltArrival
	if head, _ := r.Peek(8); string(head) == "GHSESS1 " {
		line, _ := r.ReadString('\n')
		a.session = line[len("GHSESS1 ") : len(line)-1]
	}
	h, e := bolt.ReadHandshake(r, false)
	if e != nil {
		return
	}
	a.handshake = append([]byte(nil), h[:]...)
	v, _ := h.Choose(bolt.Supported)
	if b.version != nil {
		v = *b.version
	}
	answer := v.Bytes()
	if _, e = c.Write(answer[:]); e != nil {
		return
	}
	count := 1
	if v.AtLeast(5, 1) {
		count = 2
	}
	for range count {
		raw, e := bolt.ReadRaw(r, 64<<10)
		if e != nil {
			return
		}
		m, e := bolt.Decode(raw)
		if e != nil {
			return
		}
		a.opening = append(a.opening, m)
	}
	b.seen <- a
	for i := range count {
		answer := bolt.Success(map[string]any{"server": "Memgraph/test", "connection_id": "bolt-" + strconv.Itoa(i)})
		if b.failure != "" && i == count-1 {
			answer, _ = bolt.Encode(bolt.TagFailure, map[string]any{"code": "Gatehouse.ClientError.Security.Refused", "message": "refused", boltReasonKey: b.failure})
		}
		if bolt.WriteRaw(c, answer) != nil || b.failure != "" && i == count-1 {
			return
		}
	}
	for {
		raw, e := bolt.ReadRaw(r, 64<<10)
		if e != nil {
			return
		}
		m, e := bolt.Decode(raw)
		if e != nil || m.Tag != bolt.TagRun {
			return
		}
		record, _ := bolt.Encode(bolt.TagRecord, []any{m.Fields[0]})
		if bolt.WriteRaw(c, record) != nil || bolt.WriteRaw(c, bolt.Success(nil)) != nil {
			return
		}
	}
}

type boltFixture struct {
	broker *boltBroker
	c      FixedConfig
	proof  string
}

// startBolt runs a sidecar with one Bolt port routed by the broker and one
// with a fixed entry list, both to one fake broker set up by configure.
func startBolt(t *testing.T, configure func(*boltBroker)) *boltFixture {
	t.Helper()
	f := newRelayFixture(t)
	b := newBoltBroker(t, f.cert, configure)
	dir := t.TempDir()
	up := f.upstream(t, b.address)
	up.SessionFile = filepath.Join(dir, "session")
	writeTestFile(t, up.SessionFile, []byte(boltSession+"\n"))
	proof := testProof(time.Now().Add(time.Hour), "gatehouse")
	writeTestFile(t, up.ProofFile, []byte(proof))
	c := FixedConfig{TaskID: "pool-worker", Deadline: time.Now().Add(time.Hour), AuditFile: filepath.Join(dir, "audit.jsonl"), Self: true,
		BoltListeners: []BoltListenerConfig{
			{Listen: freeAddress(t), Upstream: up, Routes: routesBroker, Placeholder: boltPlaceholder},
			{Listen: freeAddress(t), Upstream: up, Entries: []string{"graph-reports"}, Placeholder: boltPlaceholder},
		}}
	if e := c.Validate(time.Now()); e != nil {
		t.Fatalf("config refused: %v", e)
	}
	done := make(chan struct{})
	go func() { _ = runReserved(t.Context(), c); close(done) }()
	t.Cleanup(func() {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("relay did not stop")
		}
	})
	return &boltFixture{broker: b, c: c, proof: proof}
}

func (bf *boltFixture) dial(t *testing.T, listen string) net.Conn {
	t.Helper()
	mustBeBound(t, listen)
	for deadline := time.Now().Add(3 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		conn, e := net.Dial("tcp", listen)
		if e == nil {
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			t.Cleanup(func() { _ = conn.Close() })
			return conn
		}
		if time.Now().After(deadline) {
			t.Fatal("relay never listened")
		}
	}
}

// proposals is a handshake proposing each version in order, no ranges.
func proposals(versions ...bolt.Version) []byte {
	out := append([]byte(nil), bolt.Magic[:]...)
	for i := range 4 {
		if i < len(versions) {
			out = append(out, 0, 0, versions[i].Minor, versions[i].Major)
		} else {
			out = append(out, 0, 0, 0, 0)
		}
	}
	return out
}

// login opens a connection the way a driver does for version: HELLO with
// basic auth below 5.1, HELLO then LOGON from 5.1, sent together.
func login(t *testing.T, conn net.Conn, handshake []byte, user, password string) (bolt.Version, *bufio.Reader) {
	t.Helper()
	if _, e := conn.Write(handshake); e != nil {
		t.Fatal(e)
	}
	r := bufio.NewReader(conn)
	v, e := bolt.ReadVersion(r)
	if e != nil {
		t.Fatalf("version: %v", e)
	}
	if v == (bolt.Version{}) {
		return v, r
	}
	auth := map[string]any{"scheme": "basic", "principal": user, "credentials": password}
	hello := map[string]any{"user_agent": "test/1.0", "routing": map[string]any{"address": conn.RemoteAddr().String()}}
	var out []byte
	if v.AtLeast(5, 1) {
		h, _ := bolt.Encode(bolt.TagHello, hello)
		l, _ := bolt.Encode(bolt.TagLogon, auth)
		out = append(bolt.Frame(h), bolt.Frame(l)...)
	} else {
		for k, value := range auth {
			hello[k] = value
		}
		h, _ := bolt.Encode(bolt.TagHello, hello)
		out = bolt.Frame(h)
	}
	if _, e := conn.Write(out); e != nil {
		t.Fatal(e)
	}
	return v, r
}

func readMessage(t *testing.T, r io.Reader) *bolt.Structure {
	t.Helper()
	raw, e := bolt.ReadRaw(r, 1<<20)
	if e != nil {
		t.Fatalf("read: %v", e)
	}
	m, e := bolt.Decode(raw)
	if e != nil {
		t.Fatalf("decode: %v", e)
	}
	return m
}

func failureCode(t *testing.T, m *bolt.Structure) string {
	t.Helper()
	if m.Tag != bolt.TagFailure {
		t.Fatalf("got message 0x%02X, want FAILURE", m.Tag)
	}
	metadata, _ := m.Map(0)
	code, _ := metadata["code"].(string)
	return code
}

// The relay answers the handshake, swaps the placeholder for the proof in
// the login the client sent (HELLO below 5.1, LOGON from 5.1), forwards the
// client's own handshake bytes after the session line, and then relays the
// session both ways.
func TestBoltLoginCarriesTheProofNotThePlaceholder(t *testing.T) {
	bf := startBolt(t, nil)
	for _, v := range []bolt.Version{{Major: 5, Minor: 2}, {Major: 4, Minor: 3}} {
		t.Run(v.String(), func(t *testing.T) {
			conn := bf.dial(t, bf.c.BoltListeners[0].Listen)
			handshake := proposals(bolt.Version{Major: 6}, v)
			got, r := login(t, conn, handshake, "graph-orders", boltPlaceholder)
			if got != v {
				t.Fatalf("agreed %s, want %s", got, v)
			}
			var a boltArrival
			select {
			case a = <-bf.broker.seen:
			case <-time.After(5 * time.Second):
				t.Fatal("nothing reached the broker")
			}
			if a.session != boltSession || !bytes.Equal(a.handshake, handshake) {
				t.Fatalf("broker saw session %q and handshake %x", a.session, a.handshake)
			}
			loginAt := 0
			if v.AtLeast(5, 1) {
				if len(a.opening) != 2 || a.opening[0].Tag != bolt.TagHello || a.opening[1].Tag != bolt.TagLogon {
					t.Fatalf("broker saw %d opening messages", len(a.opening))
				}
				hello, _ := a.opening[0].Map(0)
				if _, ok := hello["credentials"]; ok || hello["user_agent"] != "test/1.0" {
					t.Fatalf("HELLO changed: %v", hello)
				}
				loginAt = 1
			}
			auth, _ := a.opening[loginAt].Map(0)
			if auth["scheme"] != "basic" || auth["principal"] != "graph-orders" || auth["credentials"] != bf.proof {
				t.Fatalf("login reached the broker as scheme %v, user %v, proof matches %v", auth["scheme"], auth["principal"], auth["credentials"] == bf.proof)
			}
			if !v.AtLeast(5, 1) && auth["user_agent"] != "test/1.0" {
				t.Fatalf("HELLO lost the client's keys: %v", auth)
			}
			for range a.opening {
				if m := readMessage(t, r); m.Tag != bolt.TagSuccess {
					t.Fatalf("opening answered 0x%02X", m.Tag)
				}
			}
			run, _ := bolt.Encode(bolt.TagRun, "RETURN 1", map[string]any{}, map[string]any{})
			if _, e := conn.Write(bolt.Frame(run)); e != nil {
				t.Fatal(e)
			}
			record := readMessage(t, r)
			if fields, _ := record.Fields[0].([]any); record.Tag != bolt.TagRecord || len(fields) != 1 || fields[0] != "RETURN 1" {
				t.Fatalf("record %v", record)
			}
			if m := readMessage(t, r); m.Tag != bolt.TagSuccess {
				t.Fatalf("RUN answered 0x%02X", m.Tag)
			}
		})
	}
}

// A login the relay cannot vouch for is refused in fixed words before the
// broker is dialed, so the proof is never read for it.
func TestBoltRefusesBeforeTheBroker(t *testing.T) {
	bf := startBolt(t, nil)
	routed, listed := bf.c.BoltListeners[0].Listen, bf.c.BoltListeners[1].Listen
	for name, tc := range map[string]struct {
		listen, user, password string
		code                   string
	}{
		"wrong placeholder":   {routed, "graph-orders", "a-real-password", boltUnauthorized},
		"empty user":          {routed, "", boltPlaceholder, boltUnauthorized},
		"user with a space":   {routed, "graph orders", boltPlaceholder, boltUnauthorized},
		"entry not listed":    {listed, "graph-orders", boltPlaceholder, boltUnauthorized},
		"listed, wrong value": {listed, "graph-reports", "", boltUnauthorized},
	} {
		for _, v := range []bolt.Version{{Major: 5, Minor: 2}, {Major: 4, Minor: 3}} {
			conn := bf.dial(t, tc.listen)
			got, r := login(t, conn, proposals(v), tc.user, tc.password)
			helloAnswered(t, got, r)
			if code := failureCode(t, readMessage(t, r)); code != tc.code {
				t.Errorf("%s at %s: code %q", name, v, code)
			}
		}
	}
	// From 5.1 a HELLO that carries a login is refused, not forwarded.
	conn := bf.dial(t, routed)
	if _, e := conn.Write(proposals(bolt.Version{Major: 5, Minor: 2})); e != nil {
		t.Fatal(e)
	}
	r := bufio.NewReader(conn)
	if v, _ := bolt.ReadVersion(r); v != (bolt.Version{Major: 5, Minor: 2}) {
		t.Fatalf("agreed %s", v)
	}
	h, _ := bolt.Encode(bolt.TagHello, map[string]any{"user_agent": "x", "scheme": "basic", "principal": "graph-orders", "credentials": boltPlaceholder})
	l, _ := bolt.Encode(bolt.TagLogon, map[string]any{"scheme": "basic", "principal": "graph-orders", "credentials": boltPlaceholder})
	_, _ = conn.Write(append(bolt.Frame(h), bolt.Frame(l)...))
	if code := failureCode(t, readMessage(t, r)); code != boltProtocol {
		t.Errorf("HELLO with a login at 5.2: code %q", code)
	}
	// A client that speaks none of the broker's versions is told so.
	for _, v := range []bolt.Version{{Major: 3}, {Major: 4, Minor: 1}, {Major: 5, Minor: 1}} {
		conn = bf.dial(t, routed)
		if got, _ := login(t, conn, proposals(v), "graph-orders", boltPlaceholder); got != (bolt.Version{}) {
			t.Errorf("agreed %s with a client offering only %s", got, v)
		}
	}
	// Not Bolt at all.
	conn = bf.dial(t, routed)
	_, _ = conn.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	if n, _ := conn.Read(make([]byte, 16)); n != 0 {
		t.Error("an HTTP request was answered")
	}
	select {
	case a := <-bf.broker.seen:
		t.Fatalf("the broker heard a refused login: %+v", a)
	case <-time.After(200 * time.Millisecond):
	}
}

// A broker refusal reaches the client as the broker worded it and is
// journaled with its reason; a broker that answers another version than the
// one the relay agreed ends the connection.
func TestBoltBrokerRefusalAndVersionMismatch(t *testing.T) {
	bf := startBolt(t, func(b *boltBroker) { b.failure = "not_entitled" })
	conn := bf.dial(t, bf.c.BoltListeners[0].Listen)
	_, r := login(t, conn, proposals(bolt.Version{Major: 5, Minor: 2}), "graph-orders", boltPlaceholder)
	<-bf.broker.seen
	if m := readMessage(t, r); m.Tag != bolt.TagSuccess {
		t.Fatalf("HELLO answered 0x%02X", m.Tag)
	}
	if code := failureCode(t, readMessage(t, r)); code != "Gatehouse.ClientError.Security.Refused" {
		t.Fatalf("refusal code %q", code)
	}
	if _, e := readMessageErr(r); e == nil {
		t.Fatal("session stayed open after a refusal")
	}
	mismatch := startBolt(t, func(b *boltBroker) { b.version = &bolt.Version{Major: 4, Minor: 3} })
	conn = mismatch.dial(t, mismatch.c.BoltListeners[0].Listen)
	v, r := login(t, conn, proposals(bolt.Version{Major: 5, Minor: 2}), "graph-orders", boltPlaceholder)
	helloAnswered(t, v, r)
	if code := failureCode(t, readMessage(t, r)); code != boltUnavailable {
		t.Fatalf("version mismatch code %q", code)
	}
	for audit, want := range map[string]string{bf.c.AuditFile: `"refused:not_entitled"`, mismatch.c.AuditFile: `"refused:version"`} {
		b, e := os.ReadFile(audit)
		if e != nil || !strings.Contains(string(b), want) {
			t.Errorf("audit has no %s:\n%s", want, b)
		}
	}
}

// helloAnswered reads the relay's own answer to HELLO from Bolt 5.1.
func helloAnswered(t *testing.T, v bolt.Version, r io.Reader) {
	t.Helper()
	if !v.AtLeast(5, 1) {
		return
	}
	m := readMessage(t, r)
	metadata, _ := m.Map(0)
	if m.Tag != bolt.TagSuccess || !strings.HasPrefix(fmt.Sprint(metadata["server"]), "Neo4j/5.2.0 compatible") {
		t.Fatalf("HELLO answered 0x%02X %v", m.Tag, metadata)
	}
}

// A Bolt 5.1 client may wait for HELLO's answer before it sends LOGON: the
// relay answers HELLO itself, and the client sees one answer per message.
func TestBoltClientThatWaitsForHello(t *testing.T) {
	bf := startBolt(t, nil)
	conn := bf.dial(t, bf.c.BoltListeners[0].Listen)
	if _, e := conn.Write(proposals(bolt.Version{Major: 5, Minor: 2})); e != nil {
		t.Fatal(e)
	}
	r := bufio.NewReader(conn)
	v, _ := bolt.ReadVersion(r)
	h, _ := bolt.Encode(bolt.TagHello, map[string]any{"user_agent": "test/1.0"})
	if _, e := conn.Write(bolt.Frame(h)); e != nil {
		t.Fatal(e)
	}
	helloAnswered(t, v, r)
	l, _ := bolt.Encode(bolt.TagLogon, map[string]any{"scheme": "basic", "principal": "graph-orders", "credentials": boltPlaceholder})
	if _, e := conn.Write(bolt.Frame(l)); e != nil {
		t.Fatal(e)
	}
	if m := readMessage(t, r); m.Tag != bolt.TagSuccess {
		t.Fatalf("LOGON answered 0x%02X", m.Tag)
	}
	a := <-bf.broker.seen
	if auth, _ := a.opening[1].Map(0); auth["credentials"] != bf.proof {
		t.Fatal("the broker did not get the proof")
	}
	run, _ := bolt.Encode(bolt.TagRun, "RETURN 2", map[string]any{}, map[string]any{})
	if _, e := conn.Write(bolt.Frame(run)); e != nil {
		t.Fatal(e)
	}
	if m := readMessage(t, r); m.Tag != bolt.TagRecord {
		t.Fatalf("RUN answered 0x%02X; a broker answer was left behind", m.Tag)
	}
}

func readMessageErr(r io.Reader) (*bolt.Structure, error) {
	raw, e := bolt.ReadRaw(r, 1<<20)
	if e != nil {
		return nil, e
	}
	return bolt.Decode(raw)
}

// A sidecar may serve routed PostgreSQL ports and Bolt ports together, each
// on a loopback address of its own.
func TestBoltAndRoutedPostgresListenersTogether(t *testing.T) {
	together := func() FixedConfig {
		c := selfListenerConfig()
		c.BoltListeners = selfBoltConfig().BoltListeners
		return c
	}
	if err := together().Validate(time.Now()); err != nil {
		t.Fatalf("routed PostgreSQL and Bolt ports refused: %v", err)
	}
	for name, mutate := range map[string]func(*FixedConfig){
		"Bolt on a routed PostgreSQL port": func(c *FixedConfig) { c.BoltListeners[0].Listen = c.PostgresListeners[0].Listen },
		"routed PostgreSQL on a Bolt port": func(c *FixedConfig) { c.PostgresListeners[1].Listen = c.BoltListeners[1].Listen },
	} {
		c := together()
		c.BoltListeners = append([]BoltListenerConfig(nil), c.BoltListeners...)
		c.PostgresListeners = append([]PostgresListenerConfig(nil), c.PostgresListeners...)
		mutate(&c)
		if c.Validate(time.Now()) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
