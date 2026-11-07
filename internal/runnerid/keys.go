package runnerid

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"sync"
	"time"
)

const (
	keysMaxAge     = time.Hour
	refetchBackoff = 30 * time.Second
	minRSABits     = 2048
)

// jwks caches one issuer's signing keys by kid for an hour, refreshing in the background after half of it. An unknown kid or stale keys refetch at most every 30 seconds, one fetch at a time; the last good set serves within its hour when a fetch fails.
type jwks struct {
	mu        sync.Mutex
	keys      map[string]crypto.PublicKey
	loaded    time.Time     // last successful fetch
	attempted time.Time     // last fetch attempt
	failed    bool          // the last fetch attempt failed
	inflight  chan struct{} // closed when the fetch in progress ends

	// The zero values keep the defaults: keysMaxAge, refetchBackoff and a fetch of the URL the caller passes.
	maxAge, backoff time.Duration
	fetch           func(ctx context.Context) (map[string]crypto.PublicKey, error)
}

func (c *jwks) age() time.Duration {
	if c.maxAge > 0 {
		return c.maxAge
	}
	return keysMaxAge
}

func (c *jwks) gap() time.Duration {
	if c.backoff > 0 {
		return c.backoff
	}
	return refetchBackoff
}

func (c *jwks) key(ctx context.Context, kid, url string, client *http.Client, now func() time.Time) crypto.PublicKey {
	k, _ := c.lookup(ctx, kid, url, client, now)
	return k
}

// lookup is key plus whether an absent kid is settled: false when the set could not be fetched or is stale, so the kid may exist.
func (c *jwks) lookup(ctx context.Context, kid, url string, client *http.Client, now func() time.Time) (crypto.PublicKey, bool) {
	c.mu.Lock()
	t := now()
	fresh := !c.loaded.IsZero() && t.Sub(c.loaded) < c.age()
	if k := c.keys[kid]; k != nil && fresh {
		// Past half its age the set refreshes in the background, so an issuer outage at rollover finds keys still being served.
		if t.Sub(c.loaded) >= c.age()/2 && c.inflight == nil && (c.attempted.IsZero() || t.Sub(c.attempted) >= c.gap()) {
			done := c.begin(t)
			go c.refresh(context.WithoutCancel(ctx), url, client, t, done)
		}
		c.mu.Unlock()
		return k, true
	}
	// One fetch at a time, outside the lock, so concurrent verifies wait instead of holding the lock across a network call.
	if wait := c.inflight; wait != nil {
		c.mu.Unlock()
		select {
		case <-wait:
		case <-ctx.Done():
			return nil, false
		}
		return c.current(kid, now)
	}
	if !c.attempted.IsZero() && t.Sub(c.attempted) < c.gap() {
		defer c.mu.Unlock()
		if fresh {
			return c.keys[kid], !c.failed
		}
		return nil, false
	}
	done := c.begin(t)
	c.mu.Unlock()
	// The caller's cancellation must not fail the refresh for everyone else.
	c.refresh(context.WithoutCancel(ctx), url, client, t, done)
	return c.current(kid, now)
}

// begin marks a fetch in progress; the caller holds the lock.
func (c *jwks) begin(t time.Time) chan struct{} {
	c.attempted = t
	done := make(chan struct{})
	c.inflight = done
	return done
}

// refresh fetches the set, stores it on success and releases the waiters.
func (c *jwks) refresh(ctx context.Context, url string, client *http.Client, t time.Time, done chan struct{}) {
	var keys map[string]crypto.PublicKey
	var err error
	if c.fetch != nil {
		keys, err = c.fetch(ctx)
	} else {
		keys, err = fetchKeys(ctx, url, client)
	}
	if err != nil {
		slog.Warn("signing key fetch failed", "url", url, "err", err)
	}
	c.mu.Lock()
	c.failed = err != nil
	if err == nil {
		c.keys, c.loaded = keys, t
	}
	c.inflight = nil
	close(done)
	c.mu.Unlock()
}

// current returns a key from the last good set while it is within its hour, and whether an absent kid is settled by a fetch that succeeded.
func (c *jwks) current(kid string, now func() time.Time) (crypto.PublicKey, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.loaded.IsZero() || now().Sub(c.loaded) >= c.age() {
		return nil, false
	}
	return c.keys[kid], !c.failed
}

// RefuseRedirects is an http.Client CheckRedirect that follows no redirect: signing keys come only from the configured https URL.
func RefuseRedirects(*http.Request, []*http.Request) error {
	return errors.New("runner JWKS redirect refused")
}

// noRedirects returns a copy of client that follows no redirect, whatever the supplied client does; nil gets a default.
func noRedirects(client *http.Client) *http.Client {
	if client == nil {
		return &http.Client{Timeout: 5 * time.Second, CheckRedirect: RefuseRedirects}
	}
	c := *client
	c.CheckRedirect = RefuseRedirects
	return &c
}

// fetchKeys reads a JWKS: P-256 keys for ES256 and RSA keys of at least 2048 bits for RS256; each verifier accepts only its own kind.
func fetchKeys(ctx context.Context, url string, client *http.Client) (map[string]crypto.PublicKey, error) {
	client = noRedirects(client)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("runner JWKS unavailable")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var set struct {
		Keys []struct{ Kty, Crv, Kid, Alg, Use, X, Y, N, E string } `json:"keys"`
	}
	if json.Unmarshal(body, &set) != nil {
		return nil, errors.New("invalid runner JWKS")
	}
	keys := map[string]crypto.PublicKey{}
	for _, k := range set.Keys {
		if k.Kid == "" || (k.Use != "" && k.Use != "sig") {
			continue
		}
		switch {
		case k.Kty == "EC" && k.Crv == "P-256" && (k.Alg == "" || k.Alg == "ES256"):
			x, ex := base64.RawURLEncoding.DecodeString(k.X)
			y, ey := base64.RawURLEncoding.DecodeString(k.Y)
			if ex != nil || ey != nil || len(x) != 32 || len(y) != 32 {
				continue
			}
			// Parsing the uncompressed point also rejects coordinates off the curve.
			pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
			if err != nil {
				continue
			}
			keys[k.Kid] = pub
		case k.Kty == "RSA" && (k.Alg == "" || k.Alg == "RS256"):
			n, en := base64.RawURLEncoding.DecodeString(k.N)
			e, ee := base64.RawURLEncoding.DecodeString(k.E)
			if en != nil || ee != nil || len(e) == 0 || len(e) > 4 {
				continue
			}
			pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
			if pub.N.BitLen() < minRSABits || pub.N.BitLen() > 8192 || pub.E < 3 || pub.E%2 == 0 {
				continue
			}
			keys[k.Kid] = pub
		}
	}
	// A set with no usable key, empty or filtered out, is a failed fetch so the last good set stays.
	if len(keys) == 0 {
		return nil, errors.New("runner JWKS has no usable key")
	}
	return keys, nil
}
