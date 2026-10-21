package taskrelay

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"testing"
	"time"
)

// freeAddress keeps its port bound, so no other listener can be given it
// between the test choosing it and the relay binding it.
func TestAReservedAddressStaysBoundUntilTheRelayTakesIt(t *testing.T) {
	address := freeAddress(t)
	if other, e := net.Listen("tcp", address); e == nil {
		other.Close()
		t.Fatal("a reserved address was free to bind")
	}
	if awaitBound(address, closedChannel()) {
		t.Fatal("an address the relay has not taken counts as bound")
	}
	held, e := listenReserved("tcp", address)
	if e != nil {
		t.Fatal(e)
	}
	if held.Addr().String() != address {
		t.Fatalf("handed %s, want %s", held.Addr(), address)
	}
	if !awaitBound(address, nil) {
		t.Fatal("an address the relay took does not count as bound")
	}
	// The relay now owns the listener; a second bind of the address is a real one and fails.
	if other, e := listenReserved("tcp", address); e == nil {
		other.Close()
		t.Fatal("a reserved address was handed over twice")
	}
	accepted := make(chan struct{})
	go func() {
		if c, e := held.Accept(); e == nil {
			c.Close()
		}
		close(accepted)
	}()
	c, e := net.DialTimeout("tcp", address, time.Second)
	if e != nil {
		t.Fatal(e)
	}
	c.Close()
	select {
	case <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("the handed-over listener did not accept")
	}
	held.Close()
}

func closedChannel() <-chan struct{} {
	c := make(chan struct{})
	close(c)
	return c
}

// A sidecar's configured addresses must be loopback, and so must the sockets a
// caller's listen hands it: one bound on every interface is refused and closed.
func TestASidecarRefusesAListenerOffLoopback(t *testing.T) {
	f := newRelayFixture(t)
	c := FixedConfig{TaskID: "pool-worker", Deadline: time.Now().Add(time.Hour), AuditFile: filepath.Join(t.TempDir(), "audit.jsonl"), Self: true,
		PostgresBindings: []PostgresConfig{{Listen: "127.0.0.1:15000", Upstream: f.upstream(t, "broker.example.internal:15443"), Database: "core", User: "workload", Placeholder: "gatehouse-relay-placeholder"}}}
	if e := c.Validate(time.Now()); e != nil {
		t.Fatalf("config refused: %v", e)
	}
	for _, wildcard := range []string{"0.0.0.0:0", "[::]:0"} {
		wide, e := net.Listen("tcp", wildcard) // #nosec G102 -- the test hands the relay a listener on every interface to prove it is refused
		if e != nil {
			t.Logf("%s: %v", wildcard, e)
			continue
		}
		t.Cleanup(func() { _ = wide.Close() })
		var asked string
		ctx, stop := context.WithCancel(t.Context())
		stopped := make(chan error, 1)
		go func() {
			stopped <- RunWithListen(ctx, c, func(network, address string) (net.Listener, error) {
				asked = address
				return wide, nil
			})
		}()
		select {
		case e = <-stopped:
		case <-time.After(5 * time.Second):
			stop()
			t.Fatalf("%s: the relay served on a listener off loopback", wildcard)
		}
		stop()
		if e == nil {
			t.Fatalf("%s: the relay served on a listener off loopback", wildcard)
		}
		if asked != "127.0.0.1:15000" {
			t.Fatalf("%s: the relay asked for %q before it stopped", wildcard, asked)
		}
		_ = wide.(*net.TCPListener).SetDeadline(time.Now().Add(time.Second))
		if _, e := wide.Accept(); !errors.Is(e, net.ErrClosed) {
			t.Fatalf("%s: the refused listener was left open: %v", wildcard, e)
		}
	}
	loop, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = loop.Close() })
	got, e := loopbackOnly(func(string, string) (net.Listener, error) { return loop, nil })("tcp", "127.0.0.1:15000")
	if e != nil || got != loop {
		t.Fatalf("a loopback listener was refused: %v", e)
	}
}
