package mitm

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/Infisical/agent-vault/internal/authorize/authorizetest"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/entitlement"
	"github.com/Infisical/agent-vault/internal/httpcatalog"
	"github.com/Infisical/agent-vault/internal/runnerid"
)

type gcpRoot struct{}

func (gcpRoot) Token() (*oauth2.Token, error) {
	return &oauth2.Token{AccessToken: "synthetic-broker-root", Expiry: time.Now().Add(time.Hour)}, nil
}

// gcpFake plays STS, IAM Credentials, Cloud Storage, BigQuery and a service
// of the operator's own that verifies Google ID tokens. Storage honors each
// downscoped token's boundary the way Google does: an object outside the
// boundary's prefix is refused. The service accepts only an ID token it saw
// minted for its own audience.
type gcpFake struct {
	mu         sync.Mutex
	boundary   map[string]string // downscoped token -> allowed object prefix
	accounts   map[string]string // impersonated token -> service account
	identities map[string]string // ID token -> service account email
	mints      atomic.Int32
	requested  []string    // service accounts asked for
	reject     atomic.Bool // the service refuses the next request with 401
}

// syntheticIDToken is shaped like a Google ID token, unsigned: a payload
// with aud, email and exp an hour out, and a signature naming the mint.
func syntheticIDToken(audience, email string, n int32) string {
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	payload, _ := json.Marshal(map[string]any{"aud": audience, "email": email, "exp": time.Now().Add(time.Hour).Unix()})
	return base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf("synthetic-id-%d-%s", n, strings.Repeat("s", 240)))) // RS256 signatures are 256 bytes
}

func (f *gcpFake) handler(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if h, _, err := net.SplitHostPort(r.Host); err == nil {
		host = h
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	switch host {
	case "sts.googleapis.com":
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		_ = r.ParseForm()
		var options struct {
			AccessBoundary struct {
				Rules []struct {
					Condition struct{ Expression string } `json:"availabilityCondition"`
				} `json:"accessBoundaryRules"`
			} `json:"accessBoundary"`
		}
		if r.Form.Get("subject_token") != "synthetic-broker-root" || json.Unmarshal([]byte(r.Form.Get("options")), &options) != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		expression := options.AccessBoundary.Rules[0].Condition.Expression
		start := strings.Index(expression, "/objects/") + len("/objects/")
		prefix := expression[start : start+strings.Index(expression[start:], "'")]
		token := fmt.Sprintf("synthetic-downscoped-%d", f.mints.Add(1))
		f.boundary[token] = prefix
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": token, "token_type": "Bearer"})
	case "iamcredentials.googleapis.com":
		if bearer != "synthetic-broker-root" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		method := r.URL.Path[strings.LastIndex(r.URL.Path, ":"):]
		account := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/projects/-/serviceAccounts/"), method)
		f.requested = append(f.requested, account)
		if method == ":generateIdToken" {
			var body struct {
				Audience     string `json:"audience"`
				IncludeEmail bool   `json:"includeEmail"`
			}
			if json.NewDecoder(r.Body).Decode(&body) != nil || body.Audience == "" || !body.IncludeEmail {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			token := syntheticIDToken(body.Audience, account, f.mints.Add(1))
			f.identities[token] = account
			_ = json.NewEncoder(w).Encode(map[string]any{"token": token})
			return
		}
		token := fmt.Sprintf("synthetic-impersonated-%d", f.mints.Add(1))
		f.accounts[token] = account
		_ = json.NewEncoder(w).Encode(map[string]any{"accessToken": token, "expireTime": time.Now().Add(15 * time.Minute).UTC().Format(time.RFC3339)})
	case "storage.googleapis.com":
		prefix, ok := f.boundary[bearer]
		object := strings.TrimPrefix(r.URL.Path, "/storage/v1/b/example-agent-files/o/")
		if !ok || !strings.HasPrefix(object, prefix) {
			http.Error(w, `{"error":{"code":403}}`, http.StatusForbidden)
			return
		}
		fmt.Fprintf(w, `{"name":%q}`, object) // #nosec G705 -- test fake; JSON response
	case "bigquery.googleapis.com":
		account, ok := f.accounts[bearer]
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		fmt.Fprintf(w, `{"principal":%q}`, account) // #nosec G705 -- test fake; JSON response
	case "svc.example.com":
		// An audience-pinned service: a Google-signed ID token for its own
		// audience, from an allowed account. The fake checks the token it
		// minted and the aud in its payload, as the real one would verify.
		email, ok := f.identities[bearer]
		var claims struct {
			Aud string `json:"aud"`
		}
		if parts := strings.Split(bearer, "."); len(parts) == 3 {
			payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
			_ = json.Unmarshal(payload, &claims)
		}
		if !ok || claims.Aud != "https://svc.example.com" || f.reject.Swap(false) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Path == "/api/echo" {
			fmt.Fprintf(w, `{"authorization":%q}`, r.Header.Get("Authorization")) // #nosec G705 -- test fake; JSON response
			return
		}
		if r.URL.Path == "/api/claims" {
			// Echoes the decoded claims and the signature, never the token as sent.
			parts := strings.Split(bearer, ".")
			payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
			fmt.Fprintf(w, `{"claims":%s,"signature":%q}`, payload, parts[2]) // #nosec G705 -- test fake; JSON response
			return
		}
		if r.URL.Path == "/api/denied" {
			w.WriteHeader(http.StatusForbidden) // the service's own denial, not a refused token
			return
		}
		fmt.Fprintf(w, `{"principal":%q}`, email) // #nosec G705 -- test fake; JSON response
	}
}

type gcpFixture struct {
	fake     *gcpFake
	proxyURL *url.URL
	roots    *x509.CertPool
	audit    *adapterAudit
	sessions *scopeResolver
}

func newGCPFixture(t *testing.T) *gcpFixture {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "google"},
		DNSNames:  []string{"sts.googleapis.com", "iamcredentials.googleapis.com", "storage.googleapis.com", "bigquery.googleapis.com", "svc.example.com"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)
	googleRoots := x509.NewCertPool()
	googleRoots.AddCert(cert)
	fake := &gcpFake{boundary: map[string]string{}, accounts: map[string]string{}, identities: map[string]string{}}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(fake.handler))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	addr := srv.Listener.Addr().String()
	dial := func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	catalog, err := httpcatalog.Parse([]byte(`{"pools":[
	  {"name":"cursor","namespace":"n","serviceAccount":"cursor"},
	  {"name":"claude","namespace":"n","serviceAccount":"claude","identity":"claude-session","ccpoolID":"ccpool_abc","ceiling":"T1"}],
	 "entries":[
	  {"name":"team-files","kind":"gcp","host":"storage.googleapis.com","tier":"T1","requires":["` + authzGroup + `"],"placeholder":"__vault_GCP__","pools":["claude"],
	   "gcp":{"bucket":"example-agent-files","prefix":"teams/analytics/","role":"roles/storage.objectViewer"}},
	  {"name":"bq-cases","kind":"gcp","host":"bigquery.googleapis.com","tier":"T1","requires":["` + authzGroup + `"],"placeholder":"__vault_GCP__","pools":["claude"],
	   "pathPrefixes":["/bigquery/v2/projects/example-analytics/"],"gcp":{"serviceAccount":"bq-cases@example-analytics.iam.gserviceaccount.com"}},
	  {"name":"bq-other","kind":"gcp","host":"bigquery.googleapis.com","tier":"T1","requires":["` + authzGroup + `"],"placeholder":"__vault_GCP__","pools":["claude"],
	   "pathPrefixes":["/bigquery/v2/projects/example-finance/"],"gcp":{"serviceAccount":"bq-finance@example-finance.iam.gserviceaccount.com"}},
	  {"name":"example-svc","kind":"gcp","host":"svc.example.com","tier":"T1","requires":["` + authzGroup + `"],"placeholder":"__vault_GCP__","pools":["claude"],
	   "pathPrefixes":["/api/"],"gcp":{"serviceAccount":"example-svc-caller@example-analytics.iam.gserviceaccount.com","audience":"https://svc.example.com"}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{DialContext: dial, TLSClientConfig: &tls.Config{RootCAs: googleRoots}}}
	f := &gcpFixture{fake: fake, audit: &adapterAudit{}}
	f.sessions = &scopeResolver{scope: &brokercore.ProxyScope{VaultID: "vault-1", AgentID: "pool-agent", Pool: "claude", WorkloadID: "pod-uid-1", VaultRole: "proxy"}}
	runner := fakeRunner{"alice": {Kind: runnerid.KindPerson, Subject: "sso|alice", Pools: []string{"ccpool_abc"}, TokenSHA256: "aa"},
		"bob": {Kind: runnerid.KindPerson, Subject: "sso|bob", Pools: []string{"ccpool_abc"}, TokenSHA256: "bb"}}
	proxyURL, roots, p := setupProxy(t, f.sessions, &fakeCredProvider{}, func(o *Options) {
		o.StrictCredentialProxy = true
		o.HeaderAdapter = &HeaderAdapter{Catalog: catalog, Keys: &adapterKeys{value: "unused"}, Audit: f.audit, Runner: runner,
			Sessions:     &authorizetest.MemBinder{},
			Entitlements: &entitlement.Cache{Source: directory{"sso|alice": {authzGroup}, "sso|bob": {}}},
			GCPTokens: &httpcatalog.GCPTokens{Root: gcpRoot{}, Client: client, STSURL: "https://sts.googleapis.com/v1/token",
				IAMCredentialsURL: "https://iamcredentials.googleapis.com"}}
	})
	p.upstream.TLSClientConfig.RootCAs = googleRoots
	p.upstream.DialContext = dial
	f.proxyURL, f.roots = proxyURL, roots
	return f
}

// get calls through the broker as a worker whose sidecar names session.
func (f *gcpFixture) get(t *testing.T, session, rawURL string) (int, string) {
	t.Helper()
	client := newTrustingClient(f.proxyURL, url.User("workload-token"), f.roots)
	defer client.CloseIdleConnections()
	if session != "" {
		client.Transport.(*http.Transport).ProxyConnectHeader = http.Header{SessionHeader: {session}}
	}
	r, _ := http.NewRequest("GET", rawURL, nil)
	r.Header.Set("Authorization", "Bearer __vault_GCP__")
	resp, err := client.Do(r)
	if err != nil {
		return 0, err.Error()
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(data), "synthetic-") || strings.Contains(fmt.Sprint(resp.Header), "synthetic-") {
		t.Fatal("a Google token reached the worker")
	}
	return resp.StatusCode, string(data)
}

// A downscoped token reads its own prefix and nothing else in the bucket;
// Storage refuses the other prefix with the very token the broker minted.
func TestGCPDownscopedTokenStaysInItsPrefix(t *testing.T) {
	f := newGCPFixture(t)
	code, body := f.get(t, "alice", "https://storage.googleapis.com/storage/v1/b/example-agent-files/o/teams%2Fanalytics%2Fq3.csv")
	if code != 200 || !strings.Contains(body, "teams/analytics/q3.csv") {
		t.Fatalf("own prefix: %d %s", code, body)
	}
	if code, _ := f.get(t, "alice", "https://storage.googleapis.com/storage/v1/b/example-agent-files/o/teams%2Ffinance%2Fpayroll.csv"); code != 403 {
		t.Fatalf("another prefix: %d", code)
	}
	if f.fake.mints.Load() != 1 {
		t.Fatalf("minted %d tokens, want one reused", f.fake.mints.Load())
	}
}

// Each impersonating entry gets a token for its own service account only.
func TestGCPImpersonationUsesOnlyTheEntrysAccount(t *testing.T) {
	f := newGCPFixture(t)
	code, body := f.get(t, "alice", "https://bigquery.googleapis.com/bigquery/v2/projects/example-analytics/datasets")
	if code != 200 || body != `{"principal":"bq-cases@example-analytics.iam.gserviceaccount.com"}` {
		t.Fatalf("analytics: %d %s", code, body)
	}
	if code, body := f.get(t, "alice", "https://bigquery.googleapis.com/bigquery/v2/projects/example-finance/datasets"); code != 200 ||
		body != `{"principal":"bq-finance@example-finance.iam.gserviceaccount.com"}` {
		t.Fatalf("finance: %d %s", code, body)
	}
	if code, _ := f.get(t, "alice", "https://bigquery.googleapis.com/bigquery/v2/projects/example-hr/datasets"); code != 403 {
		t.Fatalf("unlisted project: %d", code)
	}
	f.fake.mu.Lock()
	requested := strings.Join(f.fake.requested, ",")
	f.fake.mu.Unlock()
	if requested != "bq-cases@example-analytics.iam.gserviceaccount.com,bq-finance@example-finance.iam.gserviceaccount.com" {
		t.Fatalf("service accounts requested: %s", requested)
	}
}

// An identity entry turns the worker's placeholder into an ID token for the
// service's audience, carrying the account's email and no scope. The token
// is reused, screened out of a response that echoes it, dropped when the
// service refuses it, and never sent beyond the entry's paths.
func TestGCPIdentityTokenIsBoundToTheAudience(t *testing.T) {
	f := newGCPFixture(t)
	whoami := "https://svc.example.com/api/whoami"
	code, body := f.get(t, "alice", whoami)
	if code != 200 || body != `{"principal":"example-svc-caller@example-analytics.iam.gserviceaccount.com"}` {
		t.Fatalf("identity: %d %s", code, body)
	}
	if code, _ := f.get(t, "alice", whoami); code != 200 || f.fake.mints.Load() != 1 {
		t.Fatalf("second request: %d, minted %d tokens, want one reused", code, f.fake.mints.Load())
	}
	// A response that echoes the token is cut off before the worker sees it;
	// get fails the test if any token reaches the worker.
	if code, _ := f.get(t, "alice", "https://svc.example.com/api/echo"); f.audit.last().Outcome != "secret_echo" {
		t.Fatalf("echoed token: %d %q", code, f.audit.last().Outcome)
	}
	if code, _ := f.get(t, "alice", "https://svc.example.com/api/claims"); f.audit.last().Outcome != "secret_echo" {
		t.Fatalf("echoed signature: %d %q", code, f.audit.last().Outcome)
	}
	if code, _ := f.get(t, "alice", "https://svc.example.com/admin/users"); code != 403 {
		t.Fatalf("path outside the entry: %d", code)
	}
	// The service's own 403 keeps the token; only a refused token mints again.
	if code, _ := f.get(t, "alice", "https://svc.example.com/api/denied"); code != 403 {
		t.Fatalf("denied by the service: %d", code)
	}
	if code, _ := f.get(t, "alice", whoami); code != 200 || f.fake.mints.Load() != 1 {
		t.Fatalf("after the service's 403: %d, minted %d tokens, want the first reused", code, f.fake.mints.Load())
	}
	// The service's 401 drops the token; the next request mints a new one.
	f.fake.reject.Store(true)
	if code, _ := f.get(t, "alice", whoami); code != 401 {
		t.Fatalf("refused by the service: %d", code)
	}
	if code, _ := f.get(t, "alice", whoami); code != 200 || f.fake.mints.Load() != 2 {
		t.Fatalf("after refusal: %d, minted %d tokens, want a new one", code, f.fake.mints.Load())
	}
	f.fake.mu.Lock()
	requested, accessTokens := strings.Join(f.fake.requested, ","), len(f.fake.accounts)
	f.fake.mu.Unlock()
	if requested != "example-svc-caller@example-analytics.iam.gserviceaccount.com,example-svc-caller@example-analytics.iam.gserviceaccount.com" || accessTokens != 0 {
		t.Fatalf("service accounts requested: %s, with %d access tokens", requested, accessTokens)
	}
}

// The Cursor pool, a person outside the group, and a worker with no session
// are refused before any token is minted.
func TestGCPRefusesCursorPoolAndUnentitledPeople(t *testing.T) {
	f := newGCPFixture(t)
	gcs := "https://storage.googleapis.com/storage/v1/b/example-agent-files/o/teams%2Fanalytics%2Fq3.csv"
	if code, _ := f.get(t, "bob", gcs); code != 403 || f.audit.last().Outcome != "not_entitled" {
		t.Fatalf("non-member: %d %q", code, f.audit.last().Outcome)
	}
	if code, _ := f.get(t, "", gcs); code != 403 || f.audit.last().Outcome != "no_person" {
		t.Fatalf("no session: %d %q", code, f.audit.last().Outcome)
	}
	f.sessions.set(&brokercore.ProxyScope{VaultID: "vault-1", AgentID: "pool-agent", Pool: "cursor", WorkloadID: "pod-uid-9", VaultRole: "proxy"})
	// A pool without the grant is refused at CONNECT, before any tunnel opens.
	if code, _ := f.get(t, "alice", gcs); code != 0 || f.audit.last().Outcome != "pool" {
		t.Fatalf("cursor pool: %d %q", code, f.audit.last().Outcome)
	}
	if last := f.audit.last(); last.Method != "CONNECT" || last.Path != "" {
		t.Fatalf("a refused CONNECT row records method %q path %q", last.Method, last.Path)
	}
	if f.fake.mints.Load() != 0 {
		t.Fatalf("minted %d tokens for refused requests", f.fake.mints.Load())
	}
}
