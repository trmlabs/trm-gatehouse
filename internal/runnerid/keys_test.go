package runnerid

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestKeysRefreshInBackgroundBeforeExpiry(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	var down atomic.Bool
	fetched := make(chan struct{}, 4)
	c := &jwks{maxAge: time.Hour, backoff: 30 * time.Second, fetch: func(context.Context) (map[string]crypto.PublicKey, error) {
		calls.Add(1)
		fetched <- struct{}{}
		if down.Load() {
			return nil, errors.New("down")
		}
		return map[string]crypto.PublicKey{"k1": &priv.PublicKey}, nil
	}}
	now := time.Unix(1_000_000, 0)
	clock := func() time.Time { return now }
	ctx := context.Background()
	if k, _ := c.lookup(ctx, "k1", "", nil, clock); k == nil {
		t.Fatal("first lookup found no key")
	}
	<-fetched
	now = now.Add(31 * time.Minute)
	if k, _ := c.lookup(ctx, "k1", "", nil, clock); k == nil {
		t.Fatal("known key not served past half its age")
	}
	<-fetched
	// The refresh lands and extends the set, so the key outlives the original hour.
	waitFor(t, func() bool { c.mu.Lock(); defer c.mu.Unlock(); return !c.loaded.Before(now) })
	now = now.Add(45 * time.Minute)
	down.Store(true)
	if k, _ := c.lookup(ctx, "k1", "", nil, clock); k == nil {
		t.Fatal("key refused although the earlier refresh extended it")
	}
	<-fetched
	// An unknown kid still forces a fetch and is never trusted while the issuer is down.
	now = now.Add(time.Minute)
	if k, settled := c.lookup(ctx, "nope", "", nil, clock); k != nil || settled {
		t.Fatalf("unknown kid: key=%v settled=%v", k, settled)
	}
	// Past the hour with the issuer down, nothing is served.
	now = now.Add(2 * time.Hour)
	if k, _ := c.lookup(ctx, "k1", "", nil, clock); k != nil {
		t.Fatal("expired keys served")
	}
}

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	for range 200 {
		if ok() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not reached")
}
