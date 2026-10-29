package workloadidentity

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/Infisical/agent-vault/internal/brokercore"
)

const workersIssuer = "https://container.googleapis.com/v1/projects/workers/locations/l/clusters/workers"

// loadBalancer is the peer a remote sidecar's connection arrives from: not
// its Pod's address.
var loadBalancer = netip.MustParseAddr("198.51.100.40")

// remotePods is another cluster with sidecar workers: its signing keys and
// its API server, which serves one worker Pod to a bearer token. The API
// server is reached by name (example.com, in the test certificate), never by
// address.
type remotePods struct {
	key        *rsa.PrivateKey
	kid        string
	pod        map[string]any
	podStatus  atomic.Int32
	podReads   atomic.Int64
	bearer     string
	td         TrustDomain
	tokenFile  string
	authHeader atomic.Value // last Authorization header the Pod read carried
}

func newRemotePods(t *testing.T) *remotePods {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now().Add(-time.Minute)
	controller := true
	rp := &remotePods{key: key, kid: "workers-key-1", bearer: "remote-reader"}
	rp.podStatus.Store(200)
	rp.pod = map[string]any{
		"metadata": map[string]any{"name": "worker-abc", "namespace": "pool", "uid": "remote-pod-uid",
			"annotations":     map[string]any{brokercore.CursorRunAnnotation: "bc-remote"},
			"ownerReferences": []any{map[string]any{"uid": "remote-controller-uid", "controller": controller, "blockOwnerDeletion": true}}},
		"spec": map[string]any{"serviceAccountName": "worker", "activeDeadlineSeconds": 1800},
		"status": map[string]any{"phase": "Running", "podIP": "10.244.1.9", "startTime": start.UTC().Format(time.RFC3339),
			"containerStatuses":     []any{map[string]any{"name": "agent", "imageID": "registry.example/worker@" + workerDigest, "restartCount": 0, "state": map[string]any{"running": map[string]any{}}}},
			"initContainerStatuses": []any{map[string]any{"name": "gatehouse-sidecar", "imageID": "registry.example/broker@" + sidecarDigest, "restartCount": 0, "state": map[string]any{"running": map[string]any{}}}}},
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/jwks":
			e := big.NewInt(int64(key.E)).Bytes()
			json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{"kty": "RSA", "kid": rp.kid, "alg": "RS256", "use": "sig",
				"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(e)}}})
		case "/api/v1/namespaces/pool/pods/worker-abc":
			rp.podReads.Add(1)
			rp.authHeader.Store(r.Header.Get("Authorization"))
			// Asked by name: the request's host is the configured one.
			if r.Header.Get("Authorization") != "Bearer "+rp.bearer || !strings.HasPrefix(r.Host, "example.com:") {
				w.WriteHeader(401)
				return
			}
			w.WriteHeader(int(rp.podStatus.Load()))
			json.NewEncoder(w).Encode(rp.pod)
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(srv.Close)
	local := srv.Listener.Addr().String()
	_, port, _ := net.SplitHostPort(local)
	// The named API server resolves, for this test, to the local server.
	remotePodsDial = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "example.com:"+port {
			return nil, errors.New("unexpected remote API address " + address)
		}
		var d net.Dialer
		return d.DialContext(ctx, network, local)
	}
	t.Cleanup(func() { remotePodsDial = nil })
	dir := t.TempDir()
	ca := filepath.Join(dir, "workers-ca.pem")
	os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0600)
	rp.tokenFile = filepath.Join(dir, "reader-token")
	os.WriteFile(rp.tokenFile, []byte(rp.bearer+"\n"), 0600)
	rp.td = TrustDomain{Name: "workers", Issuer: workersIssuer, Audience: "gatehouse", Keys: "remote", JWKSURL: srv.URL + "/jwks", CAFile: ca,
		MaxTokenLifetimeSeconds: 600,
		Pods:                    &RemotePods{APIServer: "https://example.com:" + port, CAFile: ca, Credential: "token-file", TokenFile: rp.tokenFile}}
	return rp
}

// claims is the token the remote cluster projects into its worker's sidecar.
func (rp *remotePods) claims() claims {
	var c claims
	c.Issuer, c.Subject, c.Audience = workersIssuer, "system:serviceaccount:pool:worker", []string{"gatehouse"}
	c.Issued = time.Now().Unix() - 1
	c.Expires = c.Issued + 600
	c.Kubernetes.Namespace = "pool"
	c.Kubernetes.ServiceAccount.Name, c.Kubernetes.ServiceAccount.UID = "worker", "remote-account-uid"
	c.Kubernetes.Pod.Name, c.Kubernetes.Pod.UID = "worker-abc", "remote-pod-uid"
	return c
}

func (rp *remotePods) token(c claims) string {
	return (&poolFixture{key: rp.key, kid: rp.kid}).token(c)
}

func (rp *remotePods) binding() Binding {
	return Binding{Namespace: "pool", ServiceAccount: "worker", ServiceAccountUID: "remote-account-uid", AgentID: "agent", VaultID: "vault",
		OwnerUIDs: []string{"remote-controller-uid"}, ContainerName: "agent", MaxPodSeconds: 3600, Pool: "remote-workers",
		ImageDigests: []string{workerDigest, sidecarDigest}, TrustDomain: "workers"}
}

// withRemotePods is the broker's resolver with the remote domain and its
// pool binding beside the broker's own cluster's.
func withRemotePods(t *testing.T, f *poolFixture, rp *remotePods) *Resolver {
	t.Helper()
	c := f.r.config
	c.TrustDomains = []TrustDomain{rp.td}
	c.Bindings = append(append([]Binding(nil), c.Bindings...), rp.binding())
	r, err := New(c, &fakeStore{status: "active", role: "proxy"})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// A sidecar in another cluster is admitted as a pool worker: its token is
// verified by its cluster's keys and its live Pod read from its cluster's API
// server, with the bearer the broker was given. The connection arrives from a
// load balancer, not the Pod's address, and is still admitted; the Pod's
// deadline and claimed run ride on the scope as for the broker's own cluster.
func TestRemoteSidecarAdmittedByItsLivePod(t *testing.T) {
	f := setupPool(t)
	rp := newRemotePods(t)
	r := withRemotePods(t, f, rp)
	scope, err := r.Attest(context.Background(), rp.token(rp.claims()), loadBalancer)
	if err != nil {
		t.Fatal(err)
	}
	if scope.WorkloadID != "remote-pod-uid" || scope.Pool != "remote-workers" || scope.IdentityKind != brokercore.KindPodToken || scope.ClaimedRun != "bc-remote" || scope.AgentID != "agent" {
		t.Fatalf("scope %+v", scope)
	}
	if scope.NotAfter.IsZero() || scope.NotAfter.After(time.Now().Add(1800*time.Second)) {
		t.Fatalf("NotAfter %v is not the Pod's deadline", scope.NotAfter)
	}
	if got := rp.authHeader.Load(); got != "Bearer remote-reader" || rp.podReads.Load() != 1 {
		t.Fatalf("Pod read with %q, %d reads", got, rp.podReads.Load())
	}
	// The recheck of an open session reads the Pod again.
	if _, err := r.Reattest(context.Background(), rp.token(rp.claims()), loadBalancer); err != nil || rp.podReads.Load() != 2 {
		t.Fatalf("recheck: %v, %d reads", err, rp.podReads.Load())
	}
	// The broker's own pool still requires the Pod's own address.
	if _, err := r.Attest(context.Background(), f.token(f.c), loadBalancer); err == nil {
		t.Fatal("an in-cluster pool token was admitted from another address")
	}
	if _, err := r.Attest(context.Background(), f.token(f.c), workerIP); err != nil {
		t.Fatalf("in-cluster pool worker refused: %v", err)
	}
}

// Every live-Pod check but the address still refuses a remote sidecar, and so
// does a Pod the broker cannot read.
func TestRemoteSidecarRefusals(t *testing.T) {
	cases := map[string]func(rp *remotePods) string{
		"deleted Pod": func(rp *remotePods) string { rp.podStatus.Store(404); return rp.token(rp.claims()) },
		"terminating Pod": func(rp *remotePods) string {
			rp.pod["metadata"].(map[string]any)["deletionTimestamp"] = time.Now().UTC().Format(time.RFC3339)
			return rp.token(rp.claims())
		},
		"replaced Pod": func(rp *remotePods) string {
			rp.pod["metadata"].(map[string]any)["uid"] = "new-uid"
			return rp.token(rp.claims())
		},
		"Pod outside the pool": func(rp *remotePods) string {
			rp.pod["metadata"].(map[string]any)["ownerReferences"] = []any{map[string]any{"uid": "other", "controller": true, "blockOwnerDeletion": true}}
			return rp.token(rp.claims())
		},
		"swapped image": func(rp *remotePods) string {
			rp.pod["status"].(map[string]any)["containerStatuses"].([]any)[0].(map[string]any)["imageID"] = "registry.example/worker@" + otherDigest
			return rp.token(rp.claims())
		},
		"past its deadline": func(rp *remotePods) string {
			rp.pod["status"].(map[string]any)["startTime"] = time.Now().Add(-31 * time.Minute).UTC().Format(time.RFC3339)
			return rp.token(rp.claims())
		},
		"reader token refused": func(rp *remotePods) string {
			os.WriteFile(rp.tokenFile, []byte("stale"), 0600)
			return rp.token(rp.claims())
		},
		"reader token missing": func(rp *remotePods) string {
			os.Remove(rp.tokenFile)
			return rp.token(rp.claims())
		},
		"signed by another key": func(rp *remotePods) string {
			other, _ := rsa.GenerateKey(rand.Reader, 2048)
			return (&poolFixture{key: other, kid: rp.kid}).token(rp.claims())
		},
		"token over the domain's lifetime": func(rp *remotePods) string {
			c := rp.claims()
			c.Expires = c.Issued + 3600
			return rp.token(c)
		},
		"another account": func(rp *remotePods) string {
			c := rp.claims()
			c.Kubernetes.ServiceAccount.UID = "other-account"
			return rp.token(c)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := setupPool(t)
			rp := newRemotePods(t)
			r := withRemotePods(t, f, rp)
			if scope, err := r.Attest(context.Background(), mutate(rp), loadBalancer); err == nil || scope != nil {
				t.Fatalf("admitted: %+v", scope)
			}
		})
	}
}

// A remote domain admits sidecars only where the broker reads its Pods, and
// only through a pool binding; the Pod reader names its API server by host,
// over HTTPS, with one known credential.
func TestRemotePodsValidation(t *testing.T) {
	f := setupPool(t)
	rp := newRemotePods(t)
	build := func(mutate func(*Config)) error {
		c := f.r.config
		td := rp.td
		pods := *td.Pods
		td.Pods = &pods
		c.TrustDomains = []TrustDomain{td}
		c.Bindings = append(append([]Binding(nil), c.Bindings...), rp.binding())
		mutate(&c)
		_, err := New(c, &fakeStore{status: "active", role: "proxy"})
		return err
	}
	if err := build(func(*Config) {}); err != nil {
		t.Fatalf("valid remote pool binding refused: %v", err)
	}
	for name, mutate := range map[string]func(*Config){
		"domain without pods": func(c *Config) { c.TrustDomains[0].Pods = nil },
		"remote binding with no owner": func(c *Config) {
			c.Bindings[1].OwnerUIDs, c.Bindings[1].MaxPodSeconds, c.Bindings[1].ImageDigests = nil, 0, nil
		},
		"API server by address":      func(c *Config) { c.TrustDomains[0].Pods.APIServer = "https://10.0.0.1" },
		"API server by IPv6 address": func(c *Config) { c.TrustDomains[0].Pods.APIServer = "https://[fd00::1]:443" },
		"API server over HTTP":       func(c *Config) { c.TrustDomains[0].Pods.APIServer = "http://example.com" },
		"API server with a path":     func(c *Config) { c.TrustDomains[0].Pods.APIServer = "https://example.com/api" },
		"unknown credential":         func(c *Config) { c.TrustDomains[0].Pods.Credential = "kubeconfig" },
		"no credential":              func(c *Config) { c.TrustDomains[0].Pods.Credential = "" },
		"relative token file":        func(c *Config) { c.TrustDomains[0].Pods.TokenFile = "reader-token" },
		"google with a token file":   func(c *Config) { c.TrustDomains[0].Pods.Credential = "google" },
		"unreadable CA":              func(c *Config) { c.TrustDomains[0].Pods.CAFile = "/nonexistent/ca.pem" },
	} {
		if err := build(mutate); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

type staticToken string

func (s staticToken) Token() (*oauth2.Token, error) {
	return &oauth2.Token{AccessToken: string(s)}, nil
}

// With the google credential, the broker reads Pods with its own Google
// identity's access token; a broker with no Google identity fails at start.
func TestRemotePodsGoogleCredential(t *testing.T) {
	f := setupPool(t)
	rp := newRemotePods(t)
	saved := googleTokenSource
	t.Cleanup(func() { googleTokenSource = saved })
	googleTokenSource = func(context.Context) (oauth2.TokenSource, error) { return staticToken(rp.bearer), nil }
	rp.td.Pods = &RemotePods{APIServer: rp.td.Pods.APIServer, CAFile: rp.td.Pods.CAFile, Credential: "google"}
	r := withRemotePods(t, f, rp)
	if _, err := r.Attest(context.Background(), rp.token(rp.claims()), loadBalancer); err != nil {
		t.Fatalf("google credential: %v", err)
	}
	googleTokenSource = func(context.Context) (oauth2.TokenSource, error) { return nil, errors.New("no credentials") }
	c := f.r.config
	c.TrustDomains = []TrustDomain{rp.td}
	c.Bindings = append(append([]Binding(nil), c.Bindings...), rp.binding())
	if _, err := New(c, &fakeStore{status: "active", role: "proxy"}); err == nil {
		t.Fatal("a broker with no Google identity started with a google Pod reader")
	}
}
