package workloadidentity

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
)

// liveIssuer is another cluster's issuer whose published key set the test
// changes, as a cluster's credential rotation does, while the broker's
// configuration stays the same.
type liveIssuer struct {
	srv   *httptest.Server
	ca    string
	set   atomic.Pointer[[]map[string]any]
	down  atomic.Bool
	hang  atomic.Pointer[chan struct{}] // when set, a fetch waits for it
	calls atomic.Int64
}

func newLiveIssuer(t *testing.T) *liveIssuer {
	t.Helper()
	li := &liveIssuer{}
	li.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		li.calls.Add(1)
		if gate := li.hang.Load(); gate != nil {
			select {
			case <-*gate:
			case <-r.Context().Done():
			}
		}
		set := li.set.Load()
		if r.URL.Path != "/jwks" || li.down.Load() || set == nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": *set})
	}))
	t.Cleanup(li.srv.Close)
	li.ca = filepath.Join(t.TempDir(), "issuer-ca.pem")
	if err := os.WriteFile(li.ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: li.srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return li
}

// publish replaces the cluster's published key set.
func (li *liveIssuer) publish(keys ...*signer) {
	set := []map[string]any{}
	for _, k := range keys {
		set = append(set, rsaJWK(k.kid, &k.key.PublicKey))
	}
	li.set.Store(&set)
}

// domain is the remote trust domain for this issuer, with an optional
// fallback set.
func (li *liveIssuer) domain(fallback ...*signer) TrustDomain {
	td := TrustDomain{Name: "agent-sandbox", Issuer: remoteIssuer, Audience: "example-edge", Keys: "remote", JWKSURL: li.srv.URL + "/jwks", CAFile: li.ca}
	if len(fallback) != 0 {
		var keys []map[string]any
		for _, k := range fallback {
			keys = append(keys, rsaJWK(k.kid, &k.key.PublicKey))
		}
		td.JWKS = pinnedSet(keys...)
	}
	return td
}

type signer struct {
	key *rsa.PrivateKey
	kid string
}

func newSigner(t *testing.T, kid string) *signer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return &signer{key: key, kid: kid}
}

// token signs claims with this key; extra header members (such as jku) are
// added as given.
func (s *signer) token(c claims, extra map[string]any) string {
	h := map[string]any{"alg": "RS256", "kid": s.kid, "typ": "JWT"}
	for k, v := range extra {
		h[k] = v
	}
	header, _ := json.Marshal(h)
	payload, _ := json.Marshal(c)
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(input))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, digest[:])
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// clock is the resolver's time, moved by the test.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

// edgeClaims is a token the remote cluster issued to its proxy at time now.
func edgeClaims(now time.Time) claims {
	var c claims
	c.Issuer, c.Subject, c.Audience = remoteIssuer, "system:serviceaccount:example-edge:example-edge", []string{"example-edge"}
	c.Issued = now.Unix() - 1
	c.Expires = c.Issued + 600
	c.Kubernetes.Namespace = "example-edge"
	c.Kubernetes.ServiceAccount.Name, c.Kubernetes.ServiceAccount.UID = "example-edge", "edge-account-uid"
	c.Kubernetes.Pod.Name, c.Kubernetes.Pod.UID = "gatehouse-edge-7d9", "edge-pod-uid"
	return c
}

// liveResolver builds a resolver with the given trust domain on a test clock,
// logging into logs.
func liveResolver(t *testing.T, td TrustDomain) (*Resolver, *clock, *lockedWriter) {
	t.Helper()
	f := setupPool(t)
	r := withDomains(t, f, td)
	clk := &clock{now: time.Now()}
	r.now = clk.Now
	logs := &lockedWriter{}
	r.SetLogger(slog.New(slog.NewTextHandler(logs, nil)))
	return r, clk, logs
}

// lockedWriter holds log output that background key fetches write.
type lockedWriter struct {
	mu sync.Mutex
	w  bytes.Buffer
}

func (l *lockedWriter) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.String()
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// waitIdle waits until no key fetch is in flight.
func waitIdle(t *testing.T, keys *signingKeys) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		keys.mu.Lock()
		idle := keys.flight == nil
		keys.mu.Unlock()
		if idle {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("key fetch still in flight")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func verifyEdge(r *Resolver, clk *clock, s *signer) error {
	_, _, err := r.verifyLocally(context.Background(), s.token(edgeClaims(clk.Now()), nil), false)
	return err
}

// A cluster key rotation needs no configuration change: a new key is picked
// up on its first token, and a key the cluster removed stops verifying once
// the cached set is refreshed. A stale fallback set in the configuration
// neither blocks the new key nor revives the removed one.
func TestRemoteKeysFollowRotationWithNoConfigChange(t *testing.T) {
	for name, withFallback := range map[string]bool{"no fallback": false, "stale fallback pins the old key": true} {
		t.Run(name, func(t *testing.T) {
			li := newLiveIssuer(t)
			oldKey, newKey := newSigner(t, "key-2026-09"), newSigner(t, "key-2026-10")
			li.publish(oldKey)
			td := li.domain()
			if withFallback {
				td = li.domain(oldKey)
			}
			r, clk, logs := liveResolver(t, td)

			if err := verifyEdge(r, clk, oldKey); err != nil {
				t.Fatalf("old key before rotation: %v", err)
			}
			// With a fallback the first token does not wait for the first
			// fetch; let it land.
			waitIdle(t, r.domains[1].keys)
			// Rotation starts: the cluster publishes the new key beside the
			// old one and signs with it.
			li.publish(oldKey, newKey)
			clk.Add(jwksRefetchBackoff)
			if err := verifyEdge(r, clk, newKey); err != nil {
				t.Fatalf("new key during rotation: %v", err)
			}
			if err := verifyEdge(r, clk, oldKey); err != nil {
				t.Fatalf("old key during rotation: %v", err)
			}
			// Rotation completes: the old key is removed. Once the cached
			// set is refreshed, the old key refuses.
			li.publish(newKey)
			clk.Add(jwksMaxAge)
			if err := verifyEdge(r, clk, newKey); err != nil {
				t.Fatalf("new key after rotation: %v", err)
			}
			waitForFetches(t, &li.calls, 3, r.domains[1].keys)
			clk.Add(jwksRefetchBackoff)
			if err := verifyEdge(r, clk, oldKey); brokercore.DenialReason(err) != "token_keys_unavailable" {
				t.Fatalf("removed key: %v", err)
			}
			if err := verifyEdge(r, clk, newKey); err != nil {
				t.Fatalf("new key: %v", err)
			}
			for _, want := range []string{`added=[key-2026-09]`, `added=[key-2026-10] removed=[]`, `added=[] removed=[key-2026-09]`} {
				if !strings.Contains(logs.String(), want) {
					t.Fatalf("log lacks %s: %s", want, logs.String())
				}
			}
		})
	}
}

// An issuer outage keeps the last good set, and a known key never waits on
// the failing refetch. Past jwksMaxStale the last good set stops verifying,
// and a configured fallback takes over. When the issuer recovers, its live
// set decides again.
func TestRemoteKeysSurviveIssuerOutage(t *testing.T) {
	li := newLiveIssuer(t)
	live, pinnedOnly := newSigner(t, "live-key"), newSigner(t, "pinned-only")
	li.publish(live)
	reset := func(t *testing.T) {
		t.Cleanup(func() { li.down.Store(false); li.hang.Store(nil); li.publish(live) })
	}

	t.Run("last good set, then refusal without a fallback", func(t *testing.T) {
		reset(t)
		r, clk, logs := liveResolver(t, li.domain())
		if err := verifyEdge(r, clk, live); err != nil {
			t.Fatal(err)
		}
		li.down.Store(true)
		defer li.down.Store(false)
		clk.Add(jwksMaxAge)
		start := time.Now()
		for i := 0; i < 5; i++ {
			if err := verifyEdge(r, clk, live); err != nil {
				t.Fatalf("known key during the outage: %v", err)
			}
			clk.Add(jwksRefetchBackoff)
		}
		if time.Since(start) > jwksFetchTimeout {
			t.Fatalf("known keys waited on the failing refetch: %v", time.Since(start))
		}
		waitIdle(t, r.domains[1].keys)
		if !strings.Contains(logs.String(), "trust domain keys refresh failed") || !strings.Contains(logs.String(), `verifying_with="last good keys"`) {
			t.Fatalf("outage not logged: %s", logs.String())
		}
		clk.Add(jwksMaxStale)
		if err := verifyEdge(r, clk, live); brokercore.DenialReason(err) != "token_keys_unavailable" {
			t.Fatalf("past jwksMaxStale with no fallback: %v", err)
		}
	})

	t.Run("fallback after the stale bound and on a cold start", func(t *testing.T) {
		reset(t)
		r, clk, logs := liveResolver(t, li.domain(live, pinnedOnly))
		if err := verifyEdge(r, clk, live); err != nil {
			t.Fatal(err)
		}
		waitIdle(t, r.domains[1].keys)
		// The live set decides while usable: a key only the fallback holds
		// refuses.
		clk.Add(jwksRefetchBackoff)
		if err := verifyEdge(r, clk, pinnedOnly); brokercore.DenialReason(err) != "token_keys_unavailable" {
			t.Fatalf("fallback-only key with a usable live set: %v", err)
		}
		li.down.Store(true)
		clk.Add(jwksMaxStale + time.Second)
		if err := verifyEdge(r, clk, live); err != nil {
			t.Fatalf("fallback past jwksMaxStale: %v", err)
		}
		waitIdle(t, r.domains[1].keys)
		if !strings.Contains(logs.String(), `verifying_with="fallback keys"`) {
			t.Fatalf("fallback not logged: %s", logs.String())
		}
		// Recovery: the next refresh lands, and the live set decides again.
		li.down.Store(false)
		clk.Add(jwksRefetchBackoff)
		if err := verifyEdge(r, clk, live); err != nil {
			t.Fatalf("live key after recovery: %v", err)
		}
		waitIdle(t, r.domains[1].keys)
		clk.Add(jwksRefetchBackoff)
		if err := verifyEdge(r, clk, pinnedOnly); brokercore.DenialReason(err) != "token_keys_unavailable" {
			t.Fatalf("fallback-only key after recovery: %v", err)
		}

		// A broker that starts while the issuer hangs verifies with the
		// fallback at once, and refuses with none.
		gate := make(chan struct{})
		var release sync.Once
		open := func() { release.Do(func() { close(gate) }) }
		t.Cleanup(open)
		li.hang.Store(&gate)
		cold, clk2, _ := liveResolver(t, li.domain(live))
		start := time.Now()
		if err := verifyEdge(cold, clk2, live); err != nil {
			t.Fatalf("cold start with a fallback: %v", err)
		}
		if waited := time.Since(start); waited > time.Second {
			t.Fatalf("fallback key waited %v on a hung issuer", waited)
		}
		open()
		li.hang.Store(nil)
		waitIdle(t, cold.domains[1].keys)
		li.down.Store(true)
		defer li.down.Store(false)
		bare, clk3, _ := liveResolver(t, li.domain())
		if err := verifyEdge(bare, clk3, live); brokercore.DenialReason(err) != "token_keys_unavailable" {
			t.Fatalf("cold start without a fallback: %v", err)
		}
	})

	t.Run("an empty published set is an outage, not a revocation", func(t *testing.T) {
		reset(t)
		r, clk, logs := liveResolver(t, li.domain())
		if err := verifyEdge(r, clk, live); err != nil {
			t.Fatal(err)
		}
		li.publish()
		defer li.publish(live)
		clk.Add(jwksMaxAge)
		if err := verifyEdge(r, clk, live); err != nil {
			t.Fatalf("known key after an empty set: %v", err)
		}
		waitIdle(t, r.domains[1].keys)
		if !strings.Contains(logs.String(), "published no usable key") {
			t.Fatalf("empty set not logged: %s", logs.String())
		}
	})
}

// A token cannot choose where its keys come from. An issuer outside the
// allowlist refuses without any fetch, a jku or x5u header is never followed,
// a forged token naming a trusted issuer fails its signature, and a near-miss
// issuer string is a different issuer.
func TestSpoofedIssuerRefused(t *testing.T) {
	li := newLiveIssuer(t)
	real := newSigner(t, "real-key")
	li.publish(real)

	attacker := newLiveIssuer(t)
	forger := newSigner(t, "real-key") // reuses the trusted kid
	newKid := newSigner(t, "attacker-key")
	attacker.publish(forger, newKid)
	attackerKeys := attacker.srv.URL + "/jwks"

	r, clk, _ := liveResolver(t, li.domain(real))
	if err := verifyEdge(r, clk, real); err != nil {
		t.Fatal(err)
	}
	waitIdle(t, r.domains[1].keys)
	fetches := li.calls.Load()
	clk.Add(jwksRefetchBackoff)

	attackerIssuer, _ := url.Parse(attacker.srv.URL)
	cases := []struct {
		name, reason, token string
	}{
		{"issuer outside the allowlist", "token_issuer", func() string {
			c := edgeClaims(clk.Now())
			c.Issuer = attackerIssuer.String()
			return newKid.token(c, nil)
		}()},
		{"trailing slash on a trusted issuer", "token_issuer", func() string {
			c := edgeClaims(clk.Now())
			c.Issuer = remoteIssuer + "/"
			return newKid.token(c, nil)
		}()},
		{"trusted issuer, trusted kid, attacker's key", "token_signature", forger.token(edgeClaims(clk.Now()), nil)},
		{"trusted issuer, jku to the attacker's keys", "token_keys_unavailable", newKid.token(edgeClaims(clk.Now()), map[string]any{"jku": attackerKeys})},
		{"trusted issuer, x5u to the attacker", "token_signature", forger.token(edgeClaims(clk.Now()), map[string]any{"x5u": attackerKeys})},
	}
	for _, tc := range cases {
		if _, _, err := r.verifyLocally(context.Background(), tc.token, false); brokercore.DenialReason(err) != tc.reason {
			t.Errorf("%s: %v, want %s", tc.name, err, tc.reason)
		}
	}
	if n := attacker.calls.Load(); n != 0 {
		t.Fatalf("the attacker's key server was fetched %d times", n)
	}
	// The unknown attacker kid refetched only the configured issuer, once.
	if n := li.calls.Load() - fetches; n != 1 {
		t.Fatalf("configured issuer fetched %d more times, want 1", n)
	}
	if err := verifyEdge(r, clk, real); err != nil {
		t.Fatalf("real key after the attempts: %v", err)
	}
}

// jwksDialAddress fixes the address the fetch connects to, while TLS still
// verifies the URL's host: a certificate for another name refuses.
func TestRemoteKeysDialAddress(t *testing.T) {
	li := newLiveIssuer(t)
	k := newSigner(t, "dial-key")
	li.publish(k)
	addr := li.srv.Listener.Addr().String()
	_, port, _ := strings.Cut(addr, ":")

	// httptest's certificate names example.com, which this test never
	// resolves: the connection goes to the dial address.
	td := li.domain()
	td.JWKSURL, td.JWKSDialAddress = "https://example.com:"+port+"/jwks", addr
	r, clk, _ := liveResolver(t, td)
	if err := verifyEdge(r, clk, k); err != nil {
		t.Fatalf("via the dial address: %v", err)
	}

	wrongName := li.domain()
	wrongName.JWKSURL, wrongName.JWKSDialAddress = "https://keys.sandbox.test:"+port+"/jwks", addr
	r2, clk2, logs := liveResolver(t, wrongName)
	if err := verifyEdge(r2, clk2, k); brokercore.DenialReason(err) != "token_keys_unavailable" {
		t.Fatalf("certificate for another host: %v", err)
	}
	if !strings.Contains(logs.String(), "trust domain keys refresh failed") {
		t.Fatalf("refused fetch not logged: %s", logs.String())
	}

	f := setupPool(t)
	for _, bad := range []string{"keys.example:443", "199.36.153.8", "0.0.0.0:443", "[::]:443", "199.36.153.8:0"} {
		c := f.r.config
		td := li.domain()
		td.JWKSDialAddress = bad
		c.TrustDomains = []TrustDomain{td}
		if _, err := New(c, &fakeStore{status: "active", role: "proxy"}); err == nil {
			t.Errorf("dial address %q accepted", bad)
		}
	}
}

// Tokens signed with a just-rotated key that arrive while its fetch runs
// wait for that fetch and verify; none is refused for arriving second.
func TestRotationBurstJoinsTheRunningFetch(t *testing.T) {
	li := newLiveIssuer(t)
	oldKey, newKey := newSigner(t, "key-old"), newSigner(t, "key-new")
	li.publish(oldKey)
	r, clk, _ := liveResolver(t, li.domain())
	if err := verifyEdge(r, clk, oldKey); err != nil {
		t.Fatal(err)
	}
	li.publish(oldKey, newKey)
	clk.Add(jwksRefetchBackoff)
	gate := make(chan struct{})
	var release sync.Once
	open := func() { release.Do(func() { close(gate) }) }
	t.Cleanup(open)
	li.hang.Store(&gate)
	calls := li.calls.Load()
	done := make(chan error, 6)
	go func() { done <- verifyEdge(r, clk, newKey) }()
	for li.calls.Load() == calls {
		time.Sleep(time.Millisecond)
	}
	// The rest arrive inside the backoff, with the fetch still running.
	clk.Add(time.Second)
	for i := 0; i < 5; i++ {
		go func() { done <- verifyEdge(r, clk, newKey) }()
	}
	time.Sleep(50 * time.Millisecond)
	open()
	for i := 0; i < 6; i++ {
		if err := <-done; err != nil {
			t.Fatalf("token %d during the fetch: %v", i, err)
		}
	}
	if n := li.calls.Load() - calls; n != 1 {
		t.Fatalf("fetches %d, want 1", n)
	}
}
