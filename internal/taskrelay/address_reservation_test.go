package taskrelay

import (
	"net"
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
