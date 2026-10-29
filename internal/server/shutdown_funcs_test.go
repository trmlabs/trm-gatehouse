package server

import (
	"net"
	"net/http"
	"os"
	"syscall"
	"testing"
	"time"
)

// AttachShutdown functions run once when Start fails.
func TestAttachShutdownRunsWhenStartReturnsAnError(t *testing.T) {
	s := newTestServer()
	s.EnableCredentialProxy()
	calls := 0
	s.AttachShutdown(func() { calls++ })
	if err := s.Start(); err == nil {
		t.Fatal("startup without a Vault client succeeded")
	}
	if calls != 1 {
		t.Fatalf("shutdown function ran %d times, want 1", calls)
	}
}

// AttachShutdown functions run once, in order, after a graceful stop.
func TestAttachShutdownRunsAfterAGracefulStop(t *testing.T) {
	s := newTestServer()
	held, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = held.Close() })
	addr := held.Addr().String()
	s.httpServer.Addr = addr
	s.httpListener = held
	var order []int
	s.AttachShutdown(func() { order = append(order, 1) })
	s.AttachShutdown(func() { order = append(order, 2) })
	done := make(chan error, 1)
	go func() { done <- s.Start() }()
	// Answering means the signal handler is in place; a bare connect is not enough.
	probe := &http.Client{Timeout: 200 * time.Millisecond}
	deadline := time.Now().Add(10 * time.Second)
	for {
		if resp, err := probe.Get("http://" + addr + "/"); err == nil {
			_ = resp.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("server never listened")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("graceful shutdown did not finish")
	}
	if len(order) != 2 || order[0] != 1 || order[1] != 2 {
		t.Fatalf("shutdown functions ran %v, want [1 2]", order)
	}
}
