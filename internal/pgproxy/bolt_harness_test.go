package pgproxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/bolt"
)

// --- a minimal Bolt client, as a driver speaks it ---

type boltTestClient struct {
	t    *testing.T
	conn net.Conn
	r    *bufio.Reader
	v    bolt.Version
}

// dialBoltTest opens a Bolt session as a driver would: handshake proposing
// versions, HELLO (with auth before 5.1) and LOGON after. It returns the
// client and the final sign-in answer.
func dialBoltTest(t *testing.T, addr string, proposals []byte, principal, credential string) (*boltTestClient, *bolt.Structure) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	c := &boltTestClient{t: t, conn: conn, r: bufio.NewReader(conn)}
	hs := append(append([]byte(nil), bolt.Magic[:]...), proposals...)
	if _, err := conn.Write(hs); err != nil {
		t.Fatal(err)
	}
	v, err := bolt.ReadVersion(c.r)
	if err != nil {
		t.Fatalf("version: %v", err)
	}
	c.v = v
	if v == (bolt.Version{}) {
		return c, nil
	}
	auth := map[string]any{"scheme": "basic", "principal": principal, "credentials": credential}
	hello := map[string]any{"user_agent": "test/1", "routing": map[string]any{"address": "127.0.0.1:7687"}}
	if v.AtLeast(5, 1) {
		c.send(bolt.TagHello, hello)
		if reply := c.read(); reply.Tag != bolt.TagSuccess {
			return c, reply
		}
		c.send(bolt.TagLogon, auth)
		return c, c.read()
	}
	for k, val := range auth {
		hello[k] = val
	}
	c.send(bolt.TagHello, hello)
	return c, c.read()
}

// proposals builds the handshake's four slots from major.minor.range triples.
func proposals(slots ...[3]byte) []byte {
	out := make([]byte, 16)
	for i, s := range slots {
		copy(out[4*i:], []byte{0, s[2], s[1], s[0]})
	}
	return out
}

func (c *boltTestClient) send(tag byte, fields ...any) {
	c.t.Helper()
	msg, err := bolt.Encode(tag, fields...)
	if err != nil {
		c.t.Fatal(err)
	}
	if err := bolt.WriteRaw(c.conn, msg); err != nil {
		c.t.Fatalf("send 0x%02X: %v", tag, err)
	}
}

func (c *boltTestClient) read() *bolt.Structure {
	c.t.Helper()
	msg, err := c.tryRead()
	if err != nil {
		c.t.Fatalf("read: %v", err)
	}
	return msg
}

func (c *boltTestClient) tryRead() (*bolt.Structure, error) {
	raw, err := bolt.ReadRaw(c.r, 64<<20)
	if err != nil {
		return nil, err
	}
	return bolt.Decode(raw)
}

// result is one query's outcome: its records' values, or the failure.
type boltResult struct {
	records [][]any
	code    string
	message string
	ignored bool
}

// query sends RUN and PULL together, as drivers pipeline them, and reads
// both answers.
func (c *boltTestClient) query(query string, params map[string]any, extra map[string]any) boltResult {
	c.t.Helper()
	if params == nil {
		params = map[string]any{}
	}
	if extra == nil {
		extra = map[string]any{}
	}
	c.send(bolt.TagRun, query, params, extra)
	c.send(bolt.TagPull, map[string]any{"n": int64(-1)})
	var res boltResult
	run := c.read()
	if run.Tag == bolt.TagFailure {
		meta, _ := run.Map(0)
		res.code, _ = meta["code"].(string)
		res.message, _ = meta["message"].(string)
		if pull := c.read(); pull.Tag != bolt.TagIgnored {
			c.t.Fatalf("PULL after a failed RUN answered 0x%02X, want IGNORED", pull.Tag)
		}
		return res
	}
	if run.Tag == bolt.TagIgnored {
		res.ignored = true
		_ = c.read()
		return res
	}
	for {
		msg := c.read()
		switch msg.Tag {
		case bolt.TagRecord:
			row, _ := msg.Fields[0].([]any)
			res.records = append(res.records, row)
			continue
		case bolt.TagFailure:
			meta, _ := msg.Map(0)
			res.code, _ = meta["code"].(string)
			res.message, _ = meta["message"].(string)
		}
		return res
	}
}

// call sends one request and returns its summary.
func (c *boltTestClient) call(tag byte, fields ...any) *bolt.Structure {
	c.t.Helper()
	c.send(tag, fields...)
	return c.read()
}

func (c *boltTestClient) reset() {
	c.t.Helper()
	if reply := c.call(bolt.TagReset); reply.Tag != bolt.TagSuccess {
		c.t.Fatalf("RESET answered 0x%02X", reply.Tag)
	}
}

// --- a scripted Memgraph: plans, results and a log of what it was asked ---

type fakeMemgraph struct {
	t        *testing.T
	ln       net.Listener
	user     string
	password string
	plans    map[string][]string // query -> EXPLAIN lines

	mu  sync.Mutex
	log []string
}

func startFakeMemgraph(t *testing.T, user, password string, plans map[string][]string) *fakeMemgraph {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeMemgraph{t: t, ln: ln, user: user, password: password, plans: plans}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(conn)
		}
	}()
	return f
}

func (f *fakeMemgraph) addr() string { return f.ln.Addr().String() }

func (f *fakeMemgraph) record(s string) {
	f.mu.Lock()
	f.log = append(f.log, s)
	f.mu.Unlock()
}

func (f *fakeMemgraph) entries() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.log...)
}

func (f *fakeMemgraph) serve(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	r := bufio.NewReader(conn)
	hs, err := bolt.ReadHandshake(r, false)
	if err != nil {
		return
	}
	v, ok := hs.Choose([]bolt.Version{{Major: 5, Minor: 2}, {Major: 4, Minor: 3}})
	if !ok {
		_, _ = conn.Write([]byte{0, 0, 0, 0})
		return
	}
	answer := v.Bytes()
	_, _ = conn.Write(answer[:])
	reply := func(msg []byte) { _ = bolt.WriteRaw(conn, msg) }
	failed := false
	var pending [][]any // the open result's rows
	inTx := false
	for {
		raw, err := bolt.ReadRaw(r, 64<<20)
		if err != nil {
			return
		}
		msg, err := bolt.Decode(raw)
		if err != nil {
			return
		}
		if failed && msg.Tag != bolt.TagReset && msg.Tag != bolt.TagGoodbye {
			reply(bolt.Ignored())
			continue
		}
		fail := func(m string) {
			failed = true
			reply(bolt.Failure("Memgraph.ClientError.MemgraphError.MemgraphError", m))
		}
		switch msg.Tag {
		case bolt.TagHello, bolt.TagLogon:
			extra, _ := msg.Map(0)
			if msg.Tag == bolt.TagHello && v.AtLeast(5, 1) {
				reply(bolt.Success(map[string]any{"server": "Neo4j/v5.11.0 compatible graph database server - Memgraph", "connection_id": "bolt-1"}))
				continue
			}
			if extra["principal"] != f.user || extra["credentials"] != f.password {
				fail("Authentication failure")
				return
			}
			f.record("LOGIN " + f.user)
			reply(bolt.Success(nil))
		case bolt.TagReset:
			failed, inTx, pending = false, false, nil
			f.record("RESET")
			reply(bolt.Success(nil))
		case bolt.TagGoodbye:
			f.record("GOODBYE")
			return
		case bolt.TagBegin:
			extra, _ := msg.Map(0)
			f.record(fmt.Sprintf("BEGIN mode=%v", extra["mode"]))
			inTx = true
			reply(bolt.Success(nil))
		case bolt.TagCommit:
			f.record("COMMIT")
			inTx = false
			reply(bolt.Success(map[string]any{"bookmark": "b1"}))
		case bolt.TagRollback:
			f.record("ROLLBACK")
			inTx = false
			reply(bolt.Success(nil))
		case bolt.TagRun:
			query, _ := msg.Fields[0].(string)
			if inner, ok := strings.CutPrefix(query, "EXPLAIN "); ok {
				lines, known := f.plans[inner]
				if !known {
					fail("Error on line 1 position 9. The underlying parsing error is mismatched input")
					continue
				}
				f.record("EXPLAIN " + inner)
				pending = nil
				for _, l := range lines {
					pending = append(pending, []any{l})
				}
				reply(bolt.Success(map[string]any{"fields": []any{"QUERY PLAN"}}))
				continue
			}
			f.record(fmt.Sprintf("RUN %s tx=%v", query, inTx))
			pending = [][]any{{int64(1)}, {int64(2)}}
			reply(bolt.Success(map[string]any{"fields": []any{"x"}}))
		case bolt.TagPull, bolt.TagDiscard:
			if msg.Tag == bolt.TagPull {
				for _, row := range pending {
					b, _ := bolt.Encode(bolt.TagRecord, row)
					reply(b)
				}
			}
			pending = nil
			reply(bolt.Success(map[string]any{"has_more": false, "type": "r"}))
		default:
			fail("unsupported")
		}
	}
}

// --- broker doubles ---

type fakeGraphs struct {
	mu  sync.Mutex
	svc *GraphService
	err error
}

func (f *fakeGraphs) ResolveGraph(_ context.Context, _ AgentScope, name string) (*GraphService, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	if f.svc == nil || name != f.svc.Name {
		return nil, errors.New("no graph")
	}
	copy := *f.svc
	return &copy, nil
}

type fakeLogins struct {
	login *GraphLogin
	err   error
}

func (f fakeLogins) GraphLogin(context.Context, *GraphService) (*GraphLogin, error) {
	if f.err != nil {
		return nil, f.err
	}
	copy := *f.login
	return &copy, nil
}
