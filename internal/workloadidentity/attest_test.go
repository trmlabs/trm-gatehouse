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
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
)

// poolFixture serves the cluster's signing keys and one live Pod, with really signed tokens.
type poolFixture struct {
	r          *Resolver
	key        *rsa.PrivateKey
	kid        string
	c          claims
	pod        map[string]any
	podStatus  int
	jwksCalls  atomic.Int64
	jwksFail   atomic.Bool
	jwksGate   atomic.Pointer[chan struct{}] // when set, a key fetch waits for it
	reviewSeen atomic.Bool
	start      time.Time
}

var workerIP = netip.MustParseAddr("10.244.0.9")

func setupPool(t *testing.T) *poolFixture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &poolFixture{key: key, kid: "cluster-key-1", podStatus: 200, start: time.Now().Add(-time.Minute)}
	f.c.Issuer, f.c.Subject, f.c.Audience = "https://issuer.test", "system:serviceaccount:pool:worker", []string{"gatehouse"}
	f.c.Issued = time.Now().Unix() - 1
	f.c.Expires = f.c.Issued + 600
	f.c.Kubernetes.Namespace = "pool"
	f.c.Kubernetes.ServiceAccount.Name, f.c.Kubernetes.ServiceAccount.UID = "worker", "account-uid"
	f.c.Kubernetes.Pod.Name, f.c.Kubernetes.Pod.UID = "worker-abc", "pod-uid"
	controller := true
	f.pod = map[string]any{
		"metadata": map[string]any{"name": "worker-abc", "namespace": "pool", "uid": "pod-uid",
			"ownerReferences": []any{map[string]any{"uid": "pool-controller-uid", "controller": controller, "blockOwnerDeletion": true}}},
		"spec": map[string]any{"serviceAccountName": "worker", "activeDeadlineSeconds": 1800},
		"status": map[string]any{"phase": "Running", "podIP": workerIP.String(), "startTime": f.start.UTC().Format(time.RFC3339),
			"containerStatuses":     []any{map[string]any{"name": "agent", "imageID": "registry.example/worker@" + workerDigest, "restartCount": 0, "state": map[string]any{"running": map[string]any{}}}},
			"initContainerStatuses": []any{map[string]any{"name": "gatehouse-sidecar", "imageID": "registry.example/broker@" + sidecarDigest, "restartCount": 0, "state": map[string]any{"running": map[string]any{}}}}},
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer reviewer" {
			w.WriteHeader(401)
			return
		}
		switch r.URL.Path {
		case "/openid/v1/jwks":
			f.jwksCalls.Add(1)
			if gate := f.jwksGate.Load(); gate != nil {
				<-*gate
			}
			if f.jwksFail.Load() {
				w.WriteHeader(503)
				return
			}
			e := big.NewInt(int64(f.key.E)).Bytes()
			json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{"kty": "RSA", "kid": f.kid, "alg": "RS256", "use": "sig",
				"n": base64.RawURLEncoding.EncodeToString(f.key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(e)}}})
		case "/api/v1/namespaces/pool/pods/worker-abc":
			w.WriteHeader(f.podStatus)
			json.NewEncoder(w).Encode(f.pod)
		case "/apis/authentication.k8s.io/v1/tokenreviews":
			f.reviewSeen.Store(true)
			w.WriteHeader(500)
		default:
			t.Error("unexpected API path", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	caFile, tokenFile := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "reviewer")
	os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0600)
	os.WriteFile(tokenFile, []byte("reviewer"), 0600)
	c := Config{APIServer: srv.URL, CAFile: caFile, ReviewerTokenFile: tokenFile, Issuer: f.c.Issuer, Audience: "gatehouse",
		Bindings: []Binding{{Namespace: "pool", ServiceAccount: "worker", ServiceAccountUID: "account-uid", AgentID: "agent", VaultID: "vault",
			OwnerUIDs: []string{"pool-controller-uid"}, ContainerName: "agent", MaxPodSeconds: 3600, Pool: "database-developers",
			ImageDigests: []string{workerDigest, sidecarDigest}}}}
	r, err := New(c, &fakeStore{status: "active", role: "proxy"})
	if err != nil {
		t.Fatal(err)
	}
	f.r = r
	return f
}

func (f *poolFixture) token(c claims) string { return f.tokenWithKid(c, f.kid) }

func (f *poolFixture) tokenWithKid(c claims, kid string) string {
	header, _ := json.Marshal(map[string]any{"alg": "RS256", "kid": kid, "typ": "JWT"})
	payload, _ := json.Marshal(c)
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(input))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, digest[:])
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

const (
	workerDigest  = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	sidecarDigest = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	otherDigest   = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
)

func TestAttestAdmitsPoolPodWithItsDeadline(t *testing.T) {
	f := setupPool(t)
	scope, err := f.r.Attest(context.Background(), f.token(f.c), workerIP)
	if err != nil {
		t.Fatal(err)
	}
	if scope.AgentID != "agent" || scope.WorkloadID != "pod-uid" || scope.VaultName != "allowed" || scope.Pool != "database-developers" {
		t.Fatalf("scope %+v", scope)
	}
	// activeDeadlineSeconds (1800) is earlier than the binding's 3600.
	if want := f.start.Truncate(time.Second).Add(1800 * time.Second); !scope.NotAfter.Equal(want) {
		t.Fatalf("NotAfter %v, want %v", scope.NotAfter, want)
	}
	if f.reviewSeen.Load() {
		t.Fatal("pool admission used TokenReview instead of local verification")
	}
	// Keys are cached: a second admission fetches no keys.
	if _, err := f.r.Attest(context.Background(), f.token(f.c), workerIP); err != nil || f.jwksCalls.Load() != 1 {
		t.Fatalf("err %v, key fetches %d", err, f.jwksCalls.Load())
	}
}

// The run Cursor's spawn hook recorded on the live Pod rides on the scope, read fresh at each admission.
func TestAttestCarriesTheClaimedRun(t *testing.T) {
	f := setupPool(t)
	scope, err := f.r.Attest(context.Background(), f.token(f.c), workerIP)
	if err != nil || scope.ClaimedRun != "" {
		t.Fatalf("no annotation: %+v %v", scope, err)
	}
	f.pod["metadata"].(map[string]any)["annotations"] = map[string]any{brokercore.CursorRunAnnotation: "bc-1", "other": "x"}
	scope, err = f.r.Attest(context.Background(), f.token(f.c), workerIP)
	if err != nil || scope.ClaimedRun != "bc-1" {
		t.Fatalf("annotated: %+v %v", scope, err)
	}
}

func TestAttestRefusals(t *testing.T) {
	t.Parallel()
	cases := map[string]func(f *poolFixture) (string, netip.Addr){
		"stolen token from another address": func(f *poolFixture) (string, netip.Addr) {
			return f.token(f.c), netip.MustParseAddr("10.244.0.77")
		},
		"loopback peer": func(f *poolFixture) (string, netip.Addr) { return f.token(f.c), netip.MustParseAddr("127.0.0.1") },
		"no peer":       func(f *poolFixture) (string, netip.Addr) { return f.token(f.c), netip.Addr{} },
		"Pod outside the pool": func(f *poolFixture) (string, netip.Addr) {
			f.pod["metadata"].(map[string]any)["ownerReferences"] = []any{map[string]any{"uid": "other-controller", "controller": true}}
			return f.token(f.c), workerIP
		},
		"controller reference without blockOwnerDeletion": func(f *poolFixture) (string, netip.Addr) {
			f.pod["metadata"].(map[string]any)["ownerReferences"] = []any{map[string]any{"uid": "pool-controller-uid", "controller": true}}
			return f.token(f.c), workerIP
		},
		"owner that is not the controller": func(f *poolFixture) (string, netip.Addr) {
			f.pod["metadata"].(map[string]any)["ownerReferences"] = []any{map[string]any{"uid": "pool-controller-uid", "controller": false}}
			return f.token(f.c), workerIP
		},
		"deleted Pod": func(f *poolFixture) (string, netip.Addr) {
			f.podStatus = 404
			return f.token(f.c), workerIP
		},
		"terminating Pod": func(f *poolFixture) (string, netip.Addr) {
			f.pod["metadata"].(map[string]any)["deletionTimestamp"] = time.Now().UTC().Format(time.RFC3339)
			return f.token(f.c), workerIP
		},
		"replaced Pod with the same name": func(f *poolFixture) (string, netip.Addr) {
			f.pod["metadata"].(map[string]any)["uid"] = "new-pod-uid"
			return f.token(f.c), workerIP
		},
		"past its deadline": func(f *poolFixture) (string, netip.Addr) {
			f.pod["status"].(map[string]any)["startTime"] = time.Now().Add(-31 * time.Minute).UTC().Format(time.RFC3339)
			return f.token(f.c), workerIP
		},
		"worker container restarted": func(f *poolFixture) (string, netip.Addr) {
			f.pod["status"].(map[string]any)["containerStatuses"] = []any{map[string]any{"name": "agent", "restartCount": 1, "state": map[string]any{"running": map[string]any{}}}}
			return f.token(f.c), workerIP
		},
		"swapped worker image": func(f *poolFixture) (string, netip.Addr) {
			f.pod["status"].(map[string]any)["containerStatuses"].([]any)[0].(map[string]any)["imageID"] = "registry.example/worker@" + otherDigest
			return f.token(f.c), workerIP
		},
		"unlisted init container image": func(f *poolFixture) (string, netip.Addr) {
			status := f.pod["status"].(map[string]any)
			status["initContainerStatuses"] = append(status["initContainerStatuses"].([]any),
				map[string]any{"name": "setup", "imageID": "registry.example/setup@" + otherDigest, "state": map[string]any{}})
			return f.token(f.c), workerIP
		},
		"ephemeral container": func(f *poolFixture) (string, netip.Addr) {
			f.pod["spec"].(map[string]any)["ephemeralContainers"] = []any{map[string]any{"name": "debugger", "image": "busybox"}}
			return f.token(f.c), workerIP
		},
		"image not yet resolved": func(f *poolFixture) (string, netip.Addr) {
			f.pod["status"].(map[string]any)["initContainerStatuses"].([]any)[0].(map[string]any)["imageID"] = ""
			return f.token(f.c), workerIP
		},
		"not running": func(f *poolFixture) (string, netip.Addr) {
			f.pod["status"].(map[string]any)["phase"] = "Pending"
			return f.token(f.c), workerIP
		},
		"wrong audience": func(f *poolFixture) (string, netip.Addr) {
			c := f.c
			c.Audience = []string{"other"}
			return f.token(c), workerIP
		},
		"expired token": func(f *poolFixture) (string, netip.Addr) {
			c := f.c
			c.Issued, c.Expires = time.Now().Unix()-700, time.Now().Unix()-100
			return f.token(c), workerIP
		},
		"other account": func(f *poolFixture) (string, netip.Addr) {
			c := f.c
			c.Kubernetes.ServiceAccount.UID = "other-account"
			return f.token(c), workerIP
		},
		"forged signature": func(f *poolFixture) (string, netip.Addr) {
			other, _ := rsa.GenerateKey(rand.Reader, 2048)
			real := f.key
			f.key = other
			tok := f.token(f.c)
			f.key = real
			return tok, workerIP
		},
		"unknown key id": func(f *poolFixture) (string, netip.Addr) {
			real := f.kid
			f.kid = "rotated-away"
			tok := f.token(f.c)
			f.kid = real
			return tok, workerIP
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := setupPool(t)
			tok, peer := mutate(f)
			if scope, err := f.r.Attest(context.Background(), tok, peer); err == nil || scope != nil {
				t.Fatalf("admitted: %+v", scope)
			}
		})
	}
}

func TestPoolBindingNeverAdmittedWithoutPeer(t *testing.T) {
	f := setupPool(t)
	if scope, err := f.r.ResolveForProxy(context.Background(), f.token(f.c), ""); err == nil || scope != nil {
		t.Fatal("a pool binding was admitted without its peer address")
	}
}

func TestPoolBindingValidation(t *testing.T) {
	t.Parallel()
	base := Binding{Namespace: "pool", ServiceAccount: "worker", ServiceAccountUID: "u", AgentID: "a", VaultID: "v", OwnerUIDs: []string{"o"}, MaxPodSeconds: 1800,
		ImageDigests: []string{workerDigest}}
	f := setupPool(t)
	c := f.r.config
	c.Bindings = []Binding{base}
	if _, err := New(c, &fakeStore{status: "active", role: "proxy"}); err != nil {
		t.Fatalf("valid pool binding refused: %v", err)
	}
	// Thousands of approved images load: the list has no fixed upper bound.
	many := base
	many.ImageDigests = nil
	for i := range 5000 {
		many.ImageDigests = append(many.ImageDigests, fmt.Sprintf("sha256:%064x", i))
	}
	c.Bindings = []Binding{many}
	if _, err := New(c, &fakeStore{status: "active", role: "proxy"}); err != nil {
		t.Fatalf("5,000 image digests refused: %v", err)
	}
	for name, mutate := range map[string]func(*Binding){
		"no image digests":              func(b *Binding) { b.ImageDigests = nil },
		"malformed image digest":        func(b *Binding) { b.ImageDigests = []string{"sha256:ABC"} },
		"tag instead of a digest":       func(b *Binding) { b.ImageDigests = []string{"worker:latest"} },
		"digests on a non-pool binding": func(b *Binding) { b.OwnerUIDs, b.MaxPodSeconds = nil, 0 },
		"Pod UID pinned":                func(b *Binding) { b.PodUID = "p" },
		"lifetime over the ceiling":     func(b *Binding) { b.MaxPodSeconds = 24*3600 + 1 },
		"lifetime missing":              func(b *Binding) { b.MaxPodSeconds = 0 },
		"empty owner":                   func(b *Binding) { b.OwnerUIDs = []string{""} },
		"bad container":                 func(b *Binding) { b.ContainerName = "Bad Name" },
		"bad pool name":                 func(b *Binding) { b.Pool = "Pool A" },
	} {
		b := base
		mutate(&b)
		f := setupPool(t)
		c := f.r.config
		c.Bindings = []Binding{b}
		if _, err := New(c, &fakeStore{status: "active", role: "proxy"}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// A failed key fetch keeps the last good keys.
func TestSigningKeysSurviveAFailedFetch(t *testing.T) {
	f := setupPool(t)
	if _, err := f.r.Attest(context.Background(), f.token(f.c), workerIP); err != nil {
		t.Fatal(err)
	}
	f.jwksFail.Store(true)
	later := time.Now().Add(jwksRefetchBackoff + time.Second)
	f.r.now = func() time.Time { return later }
	if _, err := f.r.Attest(context.Background(), f.tokenWithKid(f.c, "unknown-kid"), workerIP); err == nil || f.jwksCalls.Load() != 2 {
		t.Fatalf("unknown kid: err %v, key fetches %d", err, f.jwksCalls.Load())
	}
	if _, err := f.r.Attest(context.Background(), f.token(f.c), workerIP); err != nil {
		t.Fatalf("known key lost after a failed fetch: %v", err)
	}
	// The set is old: refetch, fail, keep it (moving the clock would expire the token first).
	f.r.jwks.mu.Lock()
	f.r.jwks.fetched, f.r.jwks.attempted = later.Add(-jwksMaxAge), later.Add(-jwksRefetchBackoff)
	f.r.jwks.mu.Unlock()
	// The known key serves at once and the refresh runs behind it.
	if _, err := f.r.Attest(context.Background(), f.token(f.c), workerIP); err != nil {
		t.Fatalf("old set: %v", err)
	}
	waitForFetches(t, &f.jwksCalls, 3, f.r.jwks)
	if _, err := f.r.Attest(context.Background(), f.token(f.c), workerIP); err != nil {
		t.Fatalf("old set after a failed refetch: %v", err)
	}
}

func waitForFetches(t *testing.T, calls *atomic.Int64, n int64, keys *signingKeys) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		keys.mu.Lock()
		idle := keys.flight == nil
		keys.mu.Unlock()
		if calls.Load() >= n && idle {
			if got := calls.Load(); got != n {
				t.Fatalf("key fetches %d, want %d", got, n)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("key fetches %d, want %d", calls.Load(), n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// A slow refetch for an unknown kid runs outside the lock: cached-key admissions go on and concurrent misses share one fetch.
func TestSigningKeyFetchIsSingleFlightOutsideTheLock(t *testing.T) {
	f := setupPool(t)
	if _, err := f.r.Attest(context.Background(), f.token(f.c), workerIP); err != nil {
		t.Fatal(err)
	}
	gate := make(chan struct{})
	var release sync.Once
	open := func() { release.Do(func() { close(gate) }) }
	t.Cleanup(open) // before the server closes, so a held fetch ends
	f.jwksGate.Store(&gate)
	later := time.Now().Add(jwksRefetchBackoff + time.Second)
	f.r.now = func() time.Time { return later }
	unknown := f.tokenWithKid(f.c, "unknown-kid")
	cancelled, cancel := context.WithCancel(context.Background())
	done := make(chan error, 9)
	go func() { _, err := f.r.Attest(cancelled, unknown, workerIP); done <- err }()
	for f.jwksCalls.Load() < 2 {
		runtime.Gosched()
	}
	for i := 0; i < 8; i++ {
		go func() { _, err := f.r.Attest(context.Background(), unknown, workerIP); done <- err }()
	}
	known := make(chan error, 1)
	go func() { _, err := f.r.Attest(context.Background(), f.token(f.c), workerIP); known <- err }()
	select {
	case err := <-known:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a cached key waited on the refetch")
	}
	cancel()
	if err := <-done; err == nil {
		t.Fatal("cancelled caller admitted")
	}
	open()
	for i := 0; i < 8; i++ {
		<-done
	}
	if n := f.jwksCalls.Load(); n != 2 {
		t.Fatalf("key fetches %d, want 2", n)
	}
}

// A Pod refused for an unlisted image is logged with the reason and container; the worker sees a generic refusal.
func TestAttestLogsTheRefusedImage(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		mutate    func(f *poolFixture)
		container string
	}{
		"swapped worker image": {func(f *poolFixture) {
			f.pod["status"].(map[string]any)["containerStatuses"].([]any)[0].(map[string]any)["imageID"] = "registry.example/worker@" + otherDigest
		}, "container=agent"},
		"unlisted sidecar image": {func(f *poolFixture) {
			f.pod["status"].(map[string]any)["initContainerStatuses"].([]any)[0].(map[string]any)["imageID"] = "registry.example/broker@" + otherDigest
		}, "container=gatehouse-sidecar"},
		"ephemeral container": {func(f *poolFixture) {
			f.pod["spec"].(map[string]any)["ephemeralContainers"] = []any{map[string]any{"name": "debugger", "image": "busybox"}}
		}, "container=ephemeral:debugger"},
	} {
		t.Run(name, func(t *testing.T) {
			f := setupPool(t)
			var logs bytes.Buffer
			f.r.SetLogger(slog.New(slog.NewTextHandler(&logs, nil)))
			tc.mutate(f)
			if scope, err := f.r.Attest(context.Background(), f.token(f.c), workerIP); err == nil || scope != nil {
				t.Fatalf("admitted: %+v", scope)
			} else if !errors.Is(err, brokercore.ErrInvalidSession) {
				t.Fatalf("worker saw %v, want the generic refusal", err)
			}
			reason := "reason=image_not_allowed"
			if strings.HasPrefix(tc.container, "container=ephemeral:") {
				reason = "reason=ephemeral_container"
			}
			if !strings.Contains(logs.String(), reason) || !strings.Contains(logs.String(), tc.container) {
				t.Fatalf("log %q lacks %s or %s", logs.String(), reason, tc.container)
			}
		})
	}
	// Other refusals do not claim an image reason.
	f := setupPool(t)
	var logs bytes.Buffer
	f.r.SetLogger(slog.New(slog.NewTextHandler(&logs, nil)))
	if _, err := f.r.Attest(context.Background(), f.token(f.c), netip.MustParseAddr("10.244.0.77")); err == nil {
		t.Fatal("stolen token admitted")
	}
	if strings.Contains(logs.String(), "image_not_allowed") {
		t.Fatalf("address refusal logged as an image refusal: %q", logs.String())
	}
}

// setupService turns the pool fixture's binding into a service binding: a pool, no controller, no lifetime, no images.
func setupService(t *testing.T) *poolFixture {
	t.Helper()
	f := setupPool(t)
	f.r.config.Bindings = []Binding{{Namespace: "pool", ServiceAccount: "worker", ServiceAccountUID: "account-uid", AgentID: "agent", VaultID: "vault",
		Service: true, AllowUnpinnedImages: true, Pool: "example-runtime"}}
	f.pod["metadata"].(map[string]any)["ownerReferences"] = nil
	f.pod["status"].(map[string]any)["startTime"] = time.Now().Add(-90 * 24 * time.Hour).UTC().Format(time.RFC3339)
	delete(f.pod["spec"].(map[string]any), "activeDeadlineSeconds")
	return f
}

func TestAttestAdmitsServicePodIntoItsPool(t *testing.T) {
	f := setupService(t)
	scope, err := f.r.Attest(context.Background(), f.token(f.c), workerIP)
	if err != nil {
		t.Fatal(err)
	}
	if scope.Pool != "example-runtime" || scope.AgentID != "agent" || scope.WorkloadID != "pod-uid" || !scope.NotAfter.Equal(time.Unix(f.c.Expires, 0)) {
		t.Fatalf("scope %+v", scope)
	}
	if f.reviewSeen.Load() {
		t.Fatal("service admission used TokenReview instead of local verification")
	}
	// A recheck of an open tunnel inside its deadline succeeds while the Pod still qualifies.
	if scope, err := f.r.Reattest(context.Background(), f.token(f.c), workerIP); err != nil || scope.Pool != "example-runtime" {
		t.Fatalf("recheck: %+v %v", scope, err)
	}
}

func TestServiceBindingRefusals(t *testing.T) {
	t.Parallel()
	cases := map[string]func(f *poolFixture) (string, netip.Addr){
		"wrong service account": func(f *poolFixture) (string, netip.Addr) {
			c := f.c
			c.Kubernetes.ServiceAccount.Name, c.Subject = "intruder", "system:serviceaccount:pool:intruder"
			return f.token(c), workerIP
		},
		"wrong namespace": func(f *poolFixture) (string, netip.Addr) {
			c := f.c
			c.Kubernetes.Namespace, c.Subject = "elsewhere", "system:serviceaccount:elsewhere:worker"
			return f.token(c), workerIP
		},
		"other account UID": func(f *poolFixture) (string, netip.Addr) {
			c := f.c
			c.Kubernetes.ServiceAccount.UID = "other-account"
			return f.token(c), workerIP
		},
		"stolen token from another address": func(f *poolFixture) (string, netip.Addr) {
			return f.token(f.c), netip.MustParseAddr("10.244.0.77")
		},
		"terminating Pod": func(f *poolFixture) (string, netip.Addr) {
			f.pod["metadata"].(map[string]any)["deletionTimestamp"] = time.Now().UTC().Format(time.RFC3339)
			return f.token(f.c), workerIP
		},
		"not running": func(f *poolFixture) (string, netip.Addr) {
			f.pod["status"].(map[string]any)["phase"] = "Pending"
			return f.token(f.c), workerIP
		},
		"Pod under another account": func(f *poolFixture) (string, netip.Addr) {
			f.pod["spec"].(map[string]any)["serviceAccountName"] = "intruder"
			return f.token(f.c), workerIP
		},
		"expired token on a new connection": func(f *poolFixture) (string, netip.Addr) {
			c := f.c
			c.Issued, c.Expires = time.Now().Unix()-700, time.Now().Unix()-100
			return f.token(c), workerIP
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := setupService(t)
			tok, peer := mutate(f)
			if scope, err := f.r.Attest(context.Background(), tok, peer); err == nil || scope != nil {
				t.Fatalf("admitted: %+v", scope)
			}
		})
	}
	t.Run("listed images enforced", func(t *testing.T) {
		f := setupService(t)
		f.r.config.Bindings[0].AllowUnpinnedImages, f.r.config.Bindings[0].ImageDigests = false, []string{workerDigest, sidecarDigest}
		if _, err := f.r.Attest(context.Background(), f.token(f.c), workerIP); err != nil {
			t.Fatalf("listed images refused: %v", err)
		}
		f.pod["status"].(map[string]any)["containerStatuses"].([]any)[0].(map[string]any)["imageID"] = "registry.example/worker@" + otherDigest
		if scope, err := f.r.Attest(context.Background(), f.token(f.c), workerIP); err == nil || scope != nil {
			t.Fatalf("swapped image admitted: %+v", scope)
		}
	})
	t.Run("ephemeral container", func(t *testing.T) {
		f := setupService(t)
		f.pod["spec"].(map[string]any)["ephemeralContainers"] = []any{map[string]any{"name": "debugger", "image": "busybox"}}
		if scope, err := f.r.Attest(context.Background(), f.token(f.c), workerIP); err == nil || scope != nil {
			t.Fatalf("admitted: %+v", scope)
		}
	})
	t.Run("never without its peer address", func(t *testing.T) {
		f := setupService(t)
		if scope, err := f.r.ResolveForProxy(context.Background(), f.token(f.c), ""); err == nil || scope != nil {
			t.Fatalf("admitted with no peer: %+v", scope)
		}
	})
}

func TestServiceBindingProfile(t *testing.T) {
	f := setupService(t)
	profile := Profile{Name: "example-services", Issuer: "https://issuer.test", Audience: "gatehouse", Kind: IdentityServiceToken, Namespaces: []string{"pool"}}
	f.r.SetProfiles(func(pool string) (Profile, bool) { return profile, pool == "example-runtime" })
	if _, err := f.r.Attest(context.Background(), f.token(f.c), workerIP); err != nil {
		t.Fatalf("matching profile refused: %v", err)
	}
	profile.Kind = IdentityPodToken
	if _, err := f.r.Attest(context.Background(), f.token(f.c), workerIP); err == nil {
		t.Fatal("a pod-token profile admitted a service binding")
	}
	profile.Kind, profile.Namespaces = IdentityServiceToken, []string{"other"}
	if _, err := f.r.Attest(context.Background(), f.token(f.c), workerIP); err == nil {
		t.Fatal("a profile for another namespace admitted the service")
	}
	// A pool binding is not admitted by a service-token profile.
	g := setupPool(t)
	g.r.SetProfiles(func(string) (Profile, bool) {
		return Profile{Issuer: "https://issuer.test", Audience: "gatehouse", Kind: IdentityServiceToken, Namespaces: []string{"pool"}}, true
	})
	if _, err := g.r.Attest(context.Background(), g.token(g.c), workerIP); err == nil {
		t.Fatal("a service-token profile admitted a pool binding")
	}
}

func TestServiceProfilePinNeedsReportedImages(t *testing.T) {
	f := setupService(t)
	f.r.SetProfiles(func(string) (Profile, bool) {
		return Profile{Issuer: "https://issuer.test", Audience: "gatehouse", Kind: IdentityServiceToken, Namespaces: []string{"pool"}, ImageDigests: []string{workerDigest, sidecarDigest}}, true
	})
	if _, err := f.r.Attest(context.Background(), f.token(f.c), workerIP); err != nil {
		t.Fatalf("pinned profile refused a matching Pod: %v", err)
	}
	f.pod["status"].(map[string]any)["containerStatuses"] = []any{}
	f.pod["status"].(map[string]any)["initContainerStatuses"] = []any{}
	if scope, err := f.r.Attest(context.Background(), f.token(f.c), workerIP); err == nil || scope != nil {
		t.Fatalf("a pinned profile admitted a Pod reporting no images: %+v", scope)
	}
}

func TestServiceProfilePrefixOnly(t *testing.T) {
	f := setupService(t)
	profile := Profile{Issuer: "https://issuer.test", Audience: "gatehouse", Kind: IdentityServiceToken, Namespaces: []string{"pool"}, ImagePrefix: "registry.example/"}
	f.r.SetProfiles(func(string) (Profile, bool) { return profile, true })
	if _, err := f.r.Attest(context.Background(), f.token(f.c), workerIP); err != nil {
		t.Fatalf("prefix-only profile refused a Pod under the prefix: %v", err)
	}
	profile.ImagePrefix = "elsewhere.example/"
	if scope, err := f.r.Attest(context.Background(), f.token(f.c), workerIP); err == nil || scope != nil {
		t.Fatalf("prefix-only profile admitted a Pod outside the prefix: %+v", scope)
	}
}

func TestServiceBindingValidation(t *testing.T) {
	t.Parallel()
	base := Binding{Namespace: "pool", ServiceAccount: "worker", ServiceAccountUID: "u", AgentID: "a", VaultID: "v", Service: true, ImageDigests: []string{workerDigest}, Pool: "example-runtime"}
	f := setupPool(t)
	c := f.r.config
	c.Bindings = []Binding{base}
	if _, err := New(c, &fakeStore{status: "active", role: "proxy"}); err != nil {
		t.Fatalf("valid service binding refused: %v", err)
	}
	if !needsProvisioning(Binding{Namespace: "pool", ServiceAccount: "worker", ServiceAccountUID: "u", Service: true, Pool: "example-runtime"}) {
		t.Fatal("a service binding without IDs is not provisioned")
	}
	opt := base
	opt.ImageDigests, opt.AllowUnpinnedImages = nil, true
	c.Bindings = []Binding{opt}
	if _, err := New(c, &fakeStore{status: "active", role: "proxy"}); err != nil {
		t.Fatalf("explicitly unpinned service binding refused: %v", err)
	}
	for name, mutate := range map[string]func(*Binding){
		"no pool":               func(b *Binding) { b.Pool = "" },
		"bad pool name":         func(b *Binding) { b.Pool = "Pool A" },
		"owner UIDs":            func(b *Binding) { b.OwnerUIDs = []string{"o"} },
		"Pod UID pinned":        func(b *Binding) { b.PodUID = "p" },
		"lifetime":              func(b *Binding) { b.MaxPodSeconds = 3600 },
		"container":             func(b *Binding) { b.ContainerName = "agent" },
		"malformed digest":      func(b *Binding) { b.ImageDigests = []string{"sha256:ABC"} },
		"no digests, no opt-in": func(b *Binding) { b.ImageDigests = nil },
		"digests and opt-in":    func(b *Binding) { b.AllowUnpinnedImages = true },
		"proxy binding":         func(b *Binding) { b.Proxy = &ProxyBinding{} },
		"unlisted trust set":    func(b *Binding) { b.TrustDomain = "elsewhere" },
	} {
		b := base
		mutate(&b)
		c.Bindings = []Binding{b}
		if _, err := New(c, &fakeStore{status: "active", role: "proxy"}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestServiceBindingClaimsNoRun(t *testing.T) {
	f := setupService(t)
	f.pod["metadata"].(map[string]any)["annotations"] = map[string]any{brokercore.CursorRunAnnotation: "bc-1"}
	scope, err := f.r.Attest(context.Background(), f.token(f.c), workerIP)
	if err != nil {
		t.Fatal(err)
	}
	if scope.ClaimedRun != "" {
		t.Fatalf("service Pod claimed run %q", scope.ClaimedRun)
	}
}

func TestServiceBindingRecheckRefusals(t *testing.T) {
	t.Parallel()
	valid := func(f *poolFixture) string { return f.token(f.c) }
	cases := map[string]func(f *poolFixture){
		"terminating Pod": func(f *poolFixture) {
			f.pod["metadata"].(map[string]any)["deletionTimestamp"] = time.Now().UTC().Format(time.RFC3339)
		},
		"not running": func(f *poolFixture) { f.pod["status"].(map[string]any)["phase"] = "Failed" },
		"swapped image": func(f *poolFixture) {
			f.r.config.Bindings[0].AllowUnpinnedImages, f.r.config.Bindings[0].ImageDigests = false, []string{workerDigest, sidecarDigest}
			f.pod["status"].(map[string]any)["containerStatuses"].([]any)[0].(map[string]any)["imageID"] = "registry.example/worker@" + otherDigest
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := setupService(t)
			mutate(f)
			if scope, err := f.r.Reattest(context.Background(), valid(f), workerIP); err == nil || scope != nil {
				t.Fatalf("recheck admitted: %+v", scope)
			}
		})
	}
}

func TestServiceBindingLogsEphemeralReason(t *testing.T) {
	f := setupService(t)
	var logs bytes.Buffer
	f.r.SetLogger(slog.New(slog.NewTextHandler(&logs, nil)))
	f.pod["spec"].(map[string]any)["ephemeralContainers"] = []any{map[string]any{"name": "debugger", "image": "busybox"}}
	_, err := f.r.Attest(context.Background(), f.token(f.c), workerIP)
	if err == nil {
		t.Fatal("admitted")
	}
	if got := brokercore.DenialReason(err); got != "ephemeral_container" {
		t.Fatalf("denial reason %q", got)
	}
	if !strings.Contains(logs.String(), "reason=ephemeral_container") || strings.Contains(logs.String(), "image_not_allowed") {
		t.Fatalf("log %q", logs.String())
	}
}

func TestServiceSessionEndsWithTokenOrLimit(t *testing.T) {
	f := setupService(t)
	scope, err := f.r.Attest(context.Background(), f.token(f.c), workerIP)
	if err != nil || !scope.NotAfter.Equal(time.Unix(f.c.Expires, 0)) {
		t.Fatalf("token expiry is the deadline: %+v %v", scope, err)
	}
	if scope.IdentityKind != brokercore.KindServiceToken || brokercore.KindAdmitted(brokercore.ConnKinds(nil), scope.IdentityKind) {
		t.Fatalf("kind %q must be distinct and not admitted by default listeners", scope.IdentityKind)
	}
	f.r.config.MaxServiceSessionSeconds = 3300
	long := f.c
	long.Expires = long.Issued + 3600
	scope, err = f.r.Attest(context.Background(), f.token(long), workerIP)
	if err != nil || !scope.NotAfter.Equal(time.Unix(long.Issued, 0).Add(3300*time.Second)) {
		t.Fatalf("the configured limit is the deadline: %+v %v", scope, err)
	}
}

func TestServiceSessionPastDeadlineRefused(t *testing.T) {
	f := setupService(t)
	f.r.config.MaxServiceSessionSeconds = 3300
	c := f.c
	c.Issued, c.Expires = time.Now().Unix()-3400, time.Now().Unix()+500
	if scope, err := f.r.Attest(context.Background(), f.token(c), workerIP); err == nil || scope != nil {
		t.Fatalf("session past the service limit admitted: %+v", scope)
	}
	g := setupService(t)
	c = g.c
	c.Issued, c.Expires = time.Now().Unix()-700, time.Now().Unix()-100
	if scope, err := g.r.Reattest(context.Background(), g.token(c), workerIP); err == nil || scope != nil {
		t.Fatalf("recheck past the token's expiry admitted: %+v", scope)
	}
}

func TestServiceReattestsWithFreshToken(t *testing.T) {
	f := setupService(t)
	old := f.c
	old.Issued, old.Expires = time.Now().Unix()-700, time.Now().Unix()-100
	if _, err := f.r.Reattest(context.Background(), f.token(old), workerIP); err == nil {
		t.Fatal("expired token still admitted")
	}
	scope, err := f.r.Attest(context.Background(), f.token(f.c), workerIP)
	if err != nil || !scope.NotAfter.After(time.Now()) {
		t.Fatalf("fresh token refused: %+v %v", scope, err)
	}
}

func TestRemovedServiceBindingStopsReattestation(t *testing.T) {
	f := setupService(t)
	if _, err := f.r.Reattest(context.Background(), f.token(f.c), workerIP); err != nil {
		t.Fatal(err)
	}
	f.r.config.Bindings = nil
	if scope, err := f.r.Reattest(context.Background(), f.token(f.c), workerIP); err == nil || scope != nil {
		t.Fatalf("removed binding still admitted: %+v", scope)
	}
	if scope, err := f.r.Attest(context.Background(), f.token(f.c), workerIP); err == nil || scope != nil {
		t.Fatalf("removed binding still admitted a new connection: %+v", scope)
	}
}

func TestServiceSessionLimitValidation(t *testing.T) {
	f := setupService(t)
	for _, v := range []int64{59, 3179, 3601} {
		c := f.r.config
		c.MaxServiceSessionSeconds = v
		if _, err := New(c, &fakeStore{status: "active", role: "proxy"}); err == nil {
			t.Errorf("limit %d accepted", v)
		}
	}
	c := f.r.config
	c.MaxServiceSessionSeconds = 3180
	if _, err := New(c, &fakeStore{status: "active", role: "proxy"}); err != nil {
		t.Errorf("limit at the rotation floor refused: %v", err)
	}
	c = f.r.config
	c.MaxSessionSeconds = 600
	if _, err := New(c, &fakeStore{status: "active", role: "proxy"}); err == nil {
		t.Error("default limit below the rotation floor accepted")
	}
}

func TestAllowUnpinnedImagesRefusedOnPoolBinding(t *testing.T) {
	f := setupPool(t)
	c := f.r.config
	c.Bindings = append([]Binding(nil), c.Bindings...)
	c.Bindings[0].AllowUnpinnedImages = true
	if _, err := New(c, &fakeStore{status: "active", role: "proxy"}); err == nil {
		t.Error("allowUnpinnedImages accepted on a pool binding")
	}
}

// A service in a remote cluster is admitted by its live Pod read, with no peer address check, so the token's Pod binding is the check.
func TestRemoteServiceBinding(t *testing.T) {
	setup := func(t *testing.T) (*Resolver, *remotePods) {
		f := setupPool(t)
		rp := newRemotePods(t)
		c := f.r.config
		c.TrustDomains = []TrustDomain{rp.td}
		c.Bindings = []Binding{{Namespace: "pool", ServiceAccount: "worker", ServiceAccountUID: "remote-account-uid", AgentID: "agent", VaultID: "vault",
			Service: true, AllowUnpinnedImages: true, Pool: "remote-workers", TrustDomain: "workers"}}
		r, err := New(c, &fakeStore{status: "active", role: "proxy"})
		if err != nil {
			t.Fatal(err)
		}
		return r, rp
	}
	t.Run("admitted with a deadline and no claimed run", func(t *testing.T) {
		r, rp := setup(t)
		scope, err := r.Attest(context.Background(), rp.token(rp.claims()), loadBalancer)
		if err != nil {
			t.Fatal(err)
		}
		if scope.Pool != "remote-workers" || scope.WorkloadID != "remote-pod-uid" || scope.NotAfter.IsZero() || scope.ClaimedRun != "" || scope.IdentityKind != brokercore.KindServiceToken {
			t.Fatalf("scope %+v", scope)
		}
	})
	t.Run("token for another Pod", func(t *testing.T) {
		r, rp := setup(t)
		c := rp.claims()
		c.Kubernetes.Pod.UID = "other-pod-uid"
		if scope, err := r.Attest(context.Background(), rp.token(c), loadBalancer); err == nil || scope != nil {
			t.Fatalf("admitted: %+v", scope)
		}
	})
	t.Run("deleted Pod", func(t *testing.T) {
		r, rp := setup(t)
		rp.podStatus.Store(404)
		if scope, err := r.Reattest(context.Background(), rp.token(rp.claims()), loadBalancer); err == nil || scope != nil {
			t.Fatalf("admitted: %+v", scope)
		}
	})
}
