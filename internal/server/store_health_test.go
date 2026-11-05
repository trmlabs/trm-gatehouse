package server

import (
	"context"
	"testing"
	"time"
)

func TestStoreReachabilityFollowsTheBackgroundPing(t *testing.T) {
	srv := newTestServer()
	now := time.Now()
	if srv.storeReachable(now) {
		t.Fatal("reachable before any ping")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.watchStore(ctx)
	deadline := time.Now().Add(2 * time.Second)
	for !srv.storeReachable(time.Now()) {
		if time.Now().After(deadline) {
			t.Fatal("background ping never recorded the store as reachable")
		}
		time.Sleep(10 * time.Millisecond)
	}
	last := time.UnixMilli(srv.storeOK.Load())
	if !srv.storeReachable(last.Add(storeStaleAfter - time.Second)) {
		t.Fatal("a few missed pings made the store unreachable")
	}
	if srv.storeReachable(last.Add(storeStaleAfter + time.Second)) {
		t.Fatal("a store unreached past the limit still counts as reachable")
	}
}
