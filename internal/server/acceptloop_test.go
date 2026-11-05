package server

import (
	"bytes"
	"errors"
	"log/slog"
	"net"
	"sync"
	"syscall"
	"testing"
	"time"
)

type scriptedListener struct {
	mu      sync.Mutex
	results []acceptResult
}

func (l *scriptedListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.results) == 0 {
		return nil, net.ErrClosed
	}
	r := l.results[0]
	l.results = l.results[1:]
	return r.conn, r.err
}
func (l *scriptedListener) Close() error   { return nil }
func (l *scriptedListener) Addr() net.Addr { return &net.TCPAddr{} }

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func TestAcceptLoopLogsAndRetriesTemporaryErrors(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	l := &scriptedListener{results: []acceptResult{
		{err: &net.OpError{Op: "accept", Err: syscall.EMFILE}},
		{err: &net.OpError{Op: "accept", Err: syscall.ECONNABORTED}},
		{conn: a},
	}}
	var logs lockedBuffer
	var handled int
	err := acceptLoop(l, "example", slog.New(slog.NewTextHandler(&logs, nil)), func(net.Conn) { handled++ })
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("the loop ended with %v, want a quiet end when the listener closes", err)
	}
	if handled != 1 {
		t.Errorf("handled %d connections after the temporary errors, want 1", handled)
	}
	if n := bytes.Count([]byte(logs.String()), []byte("accept failed; retrying")); n != 2 {
		t.Errorf("logged %d retries, want 2:\n%s", n, logs.String())
	}
}

func TestAcceptLoopReturnsAPermanentError(t *testing.T) {
	boom := errors.New("the listener is broken")
	l := &scriptedListener{results: []acceptResult{{err: boom}, {conn: nil}}}
	var logs lockedBuffer
	start := time.Now()
	err := acceptLoop(l, "example", slog.New(slog.NewTextHandler(&logs, nil)), func(net.Conn) { t.Error("handled a connection after a permanent error") })
	if !errors.Is(err, boom) {
		t.Fatalf("returned %v, want the accept error", err)
	}
	if time.Since(start) > acceptRetryMax/2 {
		t.Error("a permanent error was retried")
	}
	if !bytes.Contains([]byte(logs.String()), []byte("the listener is broken")) {
		t.Errorf("the error was not logged:\n%s", logs.String())
	}
}

func TestServeStaticTokenSurvivesTemporaryAndReturnsPermanentErrors(t *testing.T) {
	l := &scriptedListener{results: []acceptResult{{err: &net.OpError{Op: "accept", Err: syscall.ENFILE}}}}
	if err := serveStaticToken(l, nil, slog.New(slog.DiscardHandler)); !errors.Is(err, net.ErrClosed) {
		t.Errorf("a temporary error ended the loop: %v", err)
	}
	boom := errors.New("broken")
	l = &scriptedListener{results: []acceptResult{{err: boom}}}
	if err := serveStaticToken(l, nil, slog.New(slog.DiscardHandler)); !errors.Is(err, boom) {
		t.Errorf("a permanent error returned %v", err)
	}
	l = &scriptedListener{results: []acceptResult{{err: boom}}}
	if err := serveCrossCluster(l, nil, nil, nil, CrossClusterLimits{}.withDefaults(), slog.New(slog.DiscardHandler)); !errors.Is(err, boom) {
		t.Errorf("cross-cluster: a permanent error returned %v", err)
	}
}
