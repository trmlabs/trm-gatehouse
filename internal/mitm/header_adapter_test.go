package mitm

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/auditchain"
	"github.com/Infisical/agent-vault/internal/authorize/authorizetest"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/entitlement"
	"github.com/Infisical/agent-vault/internal/httpcatalog"
	"github.com/Infisical/agent-vault/internal/runnerid"
)

// Synthetic vendor keys; never real credentials.
const (
	adapterKeyV1 = "sk-synthetic-adapter-key-v1-7f3a91"
	adapterKeyV2 = "sk-synthetic-adapter-key-v2-c04e5d"
)

type adapterAudit struct {
	mu       sync.Mutex
	events   []auditchain.Event
	admitErr error
}

func (a *adapterAudit) Admit() error { a.mu.Lock(); defer a.mu.Unlock(); return a.admitErr }

// Record refuses what the real chain refuses, so a row the chain would reject
// fails here too.
func (a *adapterAudit) Record(e auditchain.Event) error {
	if err := e.Validate(); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, e)
	return nil
}
func (a *adapterAudit) last() auditchain.Event {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.events) == 0 {
		return auditchain.Event{}
	}
	return a.events[len(a.events)-1]
}
func (a *adapterAudit) all() []auditchain.Event {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]auditchain.Event(nil), a.events...)
}

type adapterKeys struct {
	mu          sync.Mutex
	value       string
	err         error
	invalidated int
}

func (k *adapterKeys) Get(context.Context, httpcatalog.KeyRef) (httpcatalog.Secret, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.err != nil {
		return httpcatalog.Secret{}, k.err
	}
	return testSecret(k.value), nil
}
func (k *adapterKeys) Invalidate(httpcatalog.KeyRef) { k.mu.Lock(); k.invalidated++; k.mu.Unlock() }

// testSecret builds a Secret through the public catalog cache with a fake Vault.
func testSecret(value string) httpcatalog.Secret {
	keys := &httpcatalog.Keys{Vault: staticVault(value)}
	s, err := keys.Get(context.Background(), httpcatalog.KeyRef{Mount: "gatehouse", Path: "vendor", Field: "key"})
	if err != nil {
		panic(err)
	}
	return s
}

type adapterFixture struct {
	vendor   *httptest.Server
	port     int
	calls    atomic.Int32
	keys     *adapterKeys
	audit    *adapterAudit
	client   *http.Client
	proxy    *Proxy
	acceptsV string
	seen     atomic.Value // http.Header of the last vendor request
	release  chan struct{}
	sessions *scopeResolver
	proxyURL *url.URL
	roots    *x509.CertPool
}

// scopeResolver lets a test change the admitted scope without touching the
// running proxy.
type scopeResolver struct {
	mu      sync.Mutex
	scope   *brokercore.ProxyScope
	expired bool // every later resolution fails, as for an expired session
}

func (s *scopeResolver) ResolveForProxy(_ context.Context, token, _ string) (*brokercore.ProxyScope, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if token != "workload-token" || s.expired {
		return nil, brokercore.ErrInvalidSession
	}
	return s.scope, nil
}

func (s *scopeResolver) set(scope *brokercore.ProxyScope) {
	s.mu.Lock()
	s.scope = scope
	s.mu.Unlock()
}

func newAdapterFixture(t *testing.T, options ...func(*Options)) *adapterFixture {
	t.Helper()
	return newAdapterFixtureWith(t, "", options...)
}

// basicKey is how a vendor expecting the key as a Basic user name sees it.
func basicKey(key string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(key+":"))
}

// newAdapterFixtureWith builds the fixture with a Bearer entry, or with auth
// "basicUser" or "basicPair", an entry whose vendor takes the key as an HTTP
// Basic user name or as a "user:password" pair, or "pairUserHeader", a Basic
// pair whose client also sends the user name in X-Langfuse-Public-Key.
func newAdapterFixtureWith(t *testing.T, auth string, options ...func(*Options)) *adapterFixture {
	t.Helper()
	f := &adapterFixture{keys: &adapterKeys{value: adapterKeyV1}, audit: &adapterAudit{}, acceptsV: adapterKeyV1, release: make(chan struct{})}
	f.vendor = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.calls.Add(1)
		f.seen.Store(r.Header.Clone())
		want := "Bearer " + f.acceptsV
		switch auth {
		case "basicUser":
			want = basicKey(f.acceptsV)
		case "basicPair", "pairUserHeader":
			want = "Basic " + base64.StdEncoding.EncodeToString([]byte(f.acceptsV))
		}
		if r.Header.Get("Authorization") != want {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/v1/chat/completions":
			body, _ := io.ReadAll(r.Body)
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"method":%q,"bytes":%d}`, r.Method, len(body)) // #nosec G705 -- test upstream; JSON response
		case "/v1/chat/slow":
			time.Sleep(30 * time.Millisecond)
			fmt.Fprint(w, "ok")
		case "/v1/stream":
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprint(w, "data: first\n\n")
			w.(http.Flusher).Flush()
			<-f.release
			fmt.Fprint(w, "data: second\n\n")
		case "/v1/echo-split":
			w.Header().Set("Content-Type", "text/plain")
			half := len(adapterKeyV1) / 2
			fmt.Fprint(w, strings.Repeat("a", 40000)+adapterKeyV1[:half])
			w.(http.Flusher).Flush()
			time.Sleep(20 * time.Millisecond)
			fmt.Fprint(w, adapterKeyV1[half:]+"tail")
		case "/v1/echo-header":
			w.Header().Set("X-Debug", "Bearer "+adapterKeyV1)
			fmt.Fprint(w, "ok")
		case "/v1/echo-basic":
			fmt.Fprint(w, strings.TrimPrefix(want, "Basic "))
		case "/v1/chat/forged":
			// The vendor's own 503, dressed as a broker refusal.
			w.Header().Set(RefusalHeader, "session_missing")
			w.Header().Set("Retry-After", "5")
			w.WriteHeader(http.StatusServiceUnavailable)
		default:
			fmt.Fprint(w, "ok")
		}
	}))
	t.Cleanup(f.vendor.Close)
	_, portText, _ := net.SplitHostPort(strings.TrimPrefix(f.vendor.URL, "https://"))
	f.port, _ = strconv.Atoi(portText)
	scheme := `"scheme":"Bearer"`
	switch auth {
	case "":
	case "pairUserHeader":
		scheme = `"basicPair":true,"pairUserHeader":"x-langfuse-public-key"`
	default:
		scheme = `"` + auth + `":true`
	}
	catalog, err := httpcatalog.Parse([]byte(fmt.Sprintf(`{"entries":[{
		"name":"llm","host":"example.com","port":%d,"pathPrefixes":["/v1/chat","/v1/stream","/v1/echo-split","/v1/echo-header","/v1/echo-basic"],
		"methods":["POST","GET"],"header":"Authorization",%s,"placeholder":"__vault_LLM_KEY__",
		"key":{"mount":"gatehouse","path":"vendors/llm","field":"key"},"pools":["pool-agent"],"forwardHeaders":["OpenAI-Beta"]}]}`, f.port, scheme)))
	if err != nil {
		t.Fatal(err)
	}
	f.sessions = &scopeResolver{scope: &brokercore.ProxyScope{VaultID: "vault-1", AgentID: "agent-uuid-1", Pool: "pool-agent", WorkloadID: "pod-uid-1", VaultRole: "proxy"}}
	proxyURL, roots, p := setupProxy(t, f.sessions, &fakeCredProvider{}, func(o *Options) {
		o.StrictCredentialProxy = true
		o.HeaderAdapter = &HeaderAdapter{Catalog: catalog, Keys: f.keys, Audit: f.audit}
		for _, option := range options {
			option(o)
		}
	})
	f.proxy, f.proxyURL, f.roots = p, proxyURL, roots
	vendorRoots := x509.NewCertPool()
	vendorRoots.AddCert(f.vendor.Certificate())
	p.upstream.TLSClientConfig.RootCAs = vendorRoots
	vendorAddr := strings.TrimPrefix(f.vendor.URL, "https://")
	p.upstream.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, vendorAddr)
	}
	f.client = newTrustingClient(proxyURL, url.User("workload-token"), roots)
	t.Cleanup(f.client.CloseIdleConnections)
	return f
}

func (f *adapterFixture) url(path string) string {
	return "https://example.com:" + strconv.Itoa(f.port) + path
}

func (f *adapterFixture) do(t *testing.T, method, path, body string, mutate func(*http.Request)) (int, string, error) {
	t.Helper()
	r, err := http.NewRequest(method, f.url(path), strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer __vault_LLM_KEY__")
	if mutate != nil {
		mutate(r)
	}
	resp, err := f.client.Do(r)
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = resp.Body.Close() }()
	data, readErr := io.ReadAll(resp.Body)
	pair := base64.StdEncoding.EncodeToString([]byte(f.acceptsV)) // the encoded key, as a Basic pair sends it
	for _, key := range []string{adapterKeyV1, adapterKeyV2, basicKey(adapterKeyV1)[6:], basicKey(adapterKeyV2)[6:], pair} {
		if strings.Contains(string(data), key) || strings.Contains(fmt.Sprint(resp.Header), key) {
			t.Fatal("key reached the worker")
		}
	}
	return resp.StatusCode, string(data), readErr
}

// A worker holding only a placeholder, or nothing, gets a POST through with
// the real key added at the broker, and each call leaves admitted and
// completed rows naming the pool, Pod and binding.
func TestAdapterInjectsKeyForPlaceholderOrOmittedHeader(t *testing.T) {
	f := newAdapterFixture(t)
	for _, mutate := range []func(*http.Request){nil, func(r *http.Request) { r.Header.Del("Authorization") }} {
		code, body, err := f.do(t, "POST", "/v1/chat/completions", `{"model":"m","messages":[]}`, mutate)
		if err != nil || code != 200 || body != `{"method":"POST","bytes":27}` {
			t.Fatalf("chat: %d %q %v", code, body, err)
		}
	}
	events := f.audit.all()
	if len(events) != 4 || events[0].Event != auditchain.EventHTTPRequest || events[1].Event != auditchain.EventHTTPResponse || events[1].Status != 200 || events[1].Outcome != "completed" {
		t.Fatalf("audit: %+v", events)
	}
	for _, e := range events {
		if e.Pool != "pool-agent" || e.Agent != "agent-uuid-1" || e.PodUID != "pod-uid-1" || e.Binding != "llm" || e.Method != "POST" || e.Session == "" {
			t.Fatalf("attribution: %+v", e)
		}
		if e.Target != "" {
			t.Fatalf("an admitted call carries a target: %+v", e)
		}
	}
}

// A response row records how long the call took from admission, and the
// admitted row carries no duration.
func TestAdapterRecordsResponseDuration(t *testing.T) {
	f := newAdapterFixture(t)
	if code, body, err := f.do(t, "GET", "/v1/chat/slow", "", nil); err != nil || code != 200 || body != "ok" {
		t.Fatalf("slow call: %d %q %v", code, body, err)
	}
	events := f.audit.all()
	if len(events) != 2 || events[0].Event != auditchain.EventHTTPRequest || events[0].Duration != 0 {
		t.Fatalf("admitted row: %+v", events)
	}
	if done := events[1]; done.Event != auditchain.EventHTTPResponse || done.Outcome != "completed" || done.Duration < 30 || done.Duration > 10_000 {
		t.Fatalf("response row: %+v", done)
	}
}

// A refusal inside an open tunnel records the tunnel's CONNECT target, the
// host the broker checked, not the Host header the client sent.
func TestTunnelRefusalRecordsConnectTarget(t *testing.T) {
	f := newAdapterFixture(t)
	if code, _, err := f.do(t, "GET", "/v1/chat/x", "", nil); err != nil || code != 200 {
		t.Fatalf("open tunnel: %d %v", code, err)
	}
	f.sessions.mu.Lock()
	f.sessions.expired = true
	f.sessions.mu.Unlock()
	code, _, err := f.do(t, "GET", "/v1/chat/x", "", func(r *http.Request) { r.Host = "other.example.net" })
	if err != nil || code != http.StatusForbidden {
		t.Fatalf("in-tunnel refusal: %d %v", code, err)
	}
	if e, want := f.audit.last(), "example.com:"+strconv.Itoa(f.port); e.Event != auditchain.EventDenied || e.Target != want {
		t.Fatalf("refusal row %+v, want target %q", e, want)
	}
}

func TestAdapterRefusesOutsideTheCatalog(t *testing.T) {
	f := newAdapterFixture(t)
	for _, tc := range []struct {
		name, method, path, outcome string
		code                        int
	}{
		{"unlisted path", "POST", "/v1/admin", "unlisted", 403},
		{"prefix is not a segment", "POST", "/v1/chatx", "unlisted", 403},
		{"method", "DELETE", "/v1/chat/completions", "method", 405},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, _, err := f.do(t, tc.method, tc.path, "", nil)
			if err != nil || code != tc.code || f.audit.last().Outcome != tc.outcome || f.calls.Load() != 0 {
				t.Fatalf("code=%d outcome=%q calls=%d err=%v", code, f.audit.last().Outcome, f.calls.Load(), err)
			}
			if got, want := f.audit.last().Target, "example.com:"+strconv.Itoa(f.port); got != want {
				t.Fatalf("refusal target %q, want %q", got, want)
			}
		})
	}
	// An unlisted host is refused before the tunnel opens.
	r, _ := http.NewRequest("GET", "https://other.example.net:"+strconv.Itoa(f.port)+"/v1/chat", nil)
	resp, err := f.client.Do(r)
	if err == nil {
		_ = resp.Body.Close()
	}
	if err == nil || f.audit.last().Outcome != "unlisted" || f.calls.Load() != 0 {
		t.Fatalf("unlisted host tunnelled: %v %+v", err, f.audit.last())
	}
	if got, want := f.audit.last().Target, "other.example.net:"+strconv.Itoa(f.port); got != want {
		t.Fatalf("unlisted host target %q, want %q", got, want)
	}
	// A pool without the grant is still refused per request inside a tunnel
	// that is already open (this client reuses its earlier tunnel); a new
	// tunnel for it is refused at CONNECT (TestAdapterRefusesAScopeWithoutAPool).
	other := &brokercore.ProxyScope{VaultID: "vault-1", AgentID: "agent-uuid-9", Pool: "other-pool", WorkloadID: "pod-9"}
	f.sessions.set(other)
	if code, _, _ := f.do(t, "POST", "/v1/chat/completions", "{}", nil); code != 403 || f.audit.last().Outcome != "pool" || f.calls.Load() != 0 {
		t.Fatalf("ungranted pool: %d %+v", code, f.audit.last())
	}
}

func TestAdapterRejectsMisplacedPlaceholdersAndRoutingHeaders(t *testing.T) {
	f := newAdapterFixture(t)
	for _, tc := range []struct {
		name   string
		path   string
		body   string
		mutate func(*http.Request)
	}{
		{"placeholder in body", "/v1/chat/completions", `{"key":"__vault_LLM_KEY__"}`, nil},
		{"placeholder in query", "/v1/chat/completions?k=__vault_LLM_KEY__", "{}", nil},
		{"placeholder in another header", "/v1/chat/completions", "{}", func(r *http.Request) { r.Header.Set("X-Key", "__vault_LLM_KEY__") }},
		{"own credential", "/v1/chat/completions", "{}", func(r *http.Request) { r.Header.Set("Authorization", "Bearer sk-worker-supplied") }},
		{"wrong placeholder", "/v1/chat/completions", "{}", func(r *http.Request) { r.Header.Set("Authorization", "Bearer __vault_OTHER__") }},
		{"traversal", "/v1/chat/../admin", "{}", nil},
		{"encoded traversal", "/v1/chat/..%2Fadmin", "{}", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, _, err := f.do(t, "POST", tc.path, tc.body, tc.mutate)
			if err != nil || code != 400 || f.calls.Load() != 0 {
				t.Fatalf("code=%d calls=%d err=%v", code, f.calls.Load(), err)
			}
		})
	}
	code, _, err := f.do(t, "POST", "/v1/chat/completions", "{}", func(r *http.Request) {
		r.Header.Set("X-HTTP-Method-Override", "DELETE")
		r.Header.Set("X-Forwarded-Host", "evil.example.net")
		r.Header.Set("Cookie", "session=worker")
		r.Header.Set("OpenAI-Beta", "assistants=v2")
	})
	seen, _ := f.seen.Load().(http.Header)
	if err != nil || code != 200 || seen.Get("X-Http-Method-Override") != "" || seen.Get("X-Forwarded-Host") != "" || seen.Get("Cookie") != "" || seen.Get("Openai-Beta") != "assistants=v2" {
		t.Fatalf("header policy: %d %v", code, seen)
	}
}

// A vendor that takes the key as a Basic user name (axios auth.username,
// curl -u key:) gets it that way. The worker sends the placeholder encoded the
// same way, or nothing; the bare placeholder or its own key is refused, and an
// echo of the encoded key is cut off.
func TestAdapterSendsKeyAsBasicUser(t *testing.T) {
	f := newAdapterFixtureWith(t, "basicUser")
	placeholder := func(r *http.Request) { r.Header.Set("Authorization", basicKey("__vault_LLM_KEY__")) }
	for _, mutate := range []func(*http.Request){placeholder, func(r *http.Request) { r.Header.Del("Authorization") }} {
		code, body, err := f.do(t, "POST", "/v1/chat/completions", `{}`, mutate)
		if err != nil || code != 200 || body != `{"method":"POST","bytes":2}` {
			t.Fatalf("basic: %d %q %v", code, body, err)
		}
	}
	for name, value := range map[string]string{
		"bare placeholder": "Basic __vault_LLM_KEY__",
		"bearer":           "Bearer __vault_LLM_KEY__",
		"own key":          basicKey("sk-worker-own-key"),
		"with password":    "Basic " + base64.StdEncoding.EncodeToString([]byte("__vault_LLM_KEY__:x")),
	} {
		calls := f.calls.Load()
		code, _, _ := f.do(t, "POST", "/v1/chat/completions", `{}`, func(r *http.Request) { r.Header.Set("Authorization", value) })
		if code != 400 || f.calls.Load() != calls || f.audit.last().Outcome != "credential_header" {
			t.Fatalf("%s: %d %+v", name, code, f.audit.last())
		}
	}
	f.do(t, "GET", "/v1/echo-basic", "", placeholder)
	if got := f.audit.last(); got.Event != auditchain.EventHTTPResponse || got.Outcome != "secret_echo" {
		t.Fatalf("encoded key echo: %+v", got)
	}
}

// A vendor that takes a key pair as Basic credentials (a public and a secret
// key) gets the stored "user:password" key that way. The worker sends the
// placeholder as both halves, or nothing; any other value is refused, a key
// that is not a pair is never sent and is refused as lasting, since only
// rewriting it clears that, and an echo of the encoded pair or of the
// password alone is cut off.
func TestAdapterSendsKeyPairAsBasic(t *testing.T) {
	f := newAdapterFixtureWith(t, "basicPair")
	pair := "pk-synthetic-adapter:" + adapterKeyV1
	f.keys.mu.Lock()
	f.keys.value, f.acceptsV = pair, pair
	f.keys.mu.Unlock()
	encode := func(s string) string { return "Basic " + base64.StdEncoding.EncodeToString([]byte(s)) }
	placeholder := func(r *http.Request) { r.Header.Set("Authorization", encode("__vault_LLM_KEY__:__vault_LLM_KEY__")) }
	for _, mutate := range []func(*http.Request){placeholder, func(r *http.Request) { r.Header.Del("Authorization") }} {
		code, body, err := f.do(t, "POST", "/v1/chat/completions", `{}`, mutate)
		if err != nil || code != 200 || body != `{"method":"POST","bytes":2}` {
			t.Fatalf("pair: %d %q %v", code, body, err)
		}
	}
	for name, value := range map[string]string{
		"user only":        basicKey("__vault_LLM_KEY__"),
		"bare placeholder": "Basic __vault_LLM_KEY__",
		"own pair":         encode("pk-worker-own:sk-worker-own"),
		"own user":         encode("pk-worker-own:__vault_LLM_KEY__"),
	} {
		calls := f.calls.Load()
		code, _, _ := f.do(t, "POST", "/v1/chat/completions", `{}`, func(r *http.Request) { r.Header.Set("Authorization", value) })
		if code != 400 || f.calls.Load() != calls || f.audit.last().Outcome != "credential_header" {
			t.Fatalf("%s: %d %+v", name, code, f.audit.last())
		}
	}
	for _, path := range []string{"/v1/echo-basic", "/v1/echo-split"} {
		f.do(t, "GET", path, "", placeholder)
		if got := f.audit.last(); got.Event != auditchain.EventHTTPResponse || got.Outcome != "secret_echo" {
			t.Fatalf("%s: %+v", path, got)
		}
	}
	for name, stored := range map[string]string{"no colon": adapterKeyV1, "no password": "pk-synthetic-adapter:", "no user": ":" + adapterKeyV1} {
		f.keys.mu.Lock()
		f.keys.value = stored
		f.keys.mu.Unlock()
		calls := f.calls.Load()
		r, _ := http.NewRequest("POST", f.url("/v1/chat/completions"), strings.NewReader(`{}`))
		placeholder(r)
		resp, err := f.client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != 503 || resp.Header.Get(RefusalHeader) != "key_not_basic_pair" || resp.Header.Get("Retry-After") != "" ||
			!strings.HasPrefix(string(body), "key_not_basic_pair: ") || f.calls.Load() != calls || f.audit.last().Outcome != "key_not_basic_pair" {
			t.Fatalf("%s: %d %q Retry-After %q, outcome %q", name, resp.StatusCode, resp.Header.Get(RefusalHeader), resp.Header.Get("Retry-After"), f.audit.last().Outcome)
		}
	}
}

// A Basic pair client given the real public key and the placeholder as its
// secret key, as Langfuse's SDKs need, is served: the stored user name may
// stand in Authorization and in the entry's user header, which reaches the
// vendor only when the client sent it. Any other user name, two values, or
// the placeholder in the user header is refused before the vendor is called.
func TestAdapterServesAPairClientHoldingItsPublicKey(t *testing.T) {
	const publicKey = "pk-synthetic-adapter"
	pair := publicKey + ":" + adapterKeyV1
	encode := func(s string) string { return "Basic " + base64.StdEncoding.EncodeToString([]byte(s)) }
	sdk := encode(publicKey + ":__vault_LLM_KEY__")
	placeholders := encode("__vault_LLM_KEY__:__vault_LLM_KEY__")
	setPair := func(f *adapterFixture) {
		f.keys.mu.Lock()
		f.keys.value, f.acceptsV = pair, pair
		f.keys.mu.Unlock()
	}
	headers := func(values map[string][]string) func(*http.Request) {
		return func(r *http.Request) {
			r.Header.Del("Authorization")
			for name, v := range values {
				r.Header[name] = v
			}
		}
	}

	f := newAdapterFixtureWith(t, "pairUserHeader")
	setPair(f)
	for _, tc := range []struct {
		name     string
		mutate   func(*http.Request)
		wantUser string
	}{
		{"sdk", headers(map[string][]string{"Authorization": {sdk}, "X-Langfuse-Public-Key": {publicKey}, "X-Langfuse-Sdk-Name": {"python"}}), publicKey},
		{"sdk without the user header", headers(map[string][]string{"Authorization": {sdk}}), ""},
		{"placeholders and the user header", headers(map[string][]string{"Authorization": {placeholders}, "X-Langfuse-Public-Key": {publicKey}}), publicKey},
		{"placeholders only", headers(map[string][]string{"Authorization": {placeholders}}), ""},
		{"user header only", headers(map[string][]string{"X-Langfuse-Public-Key": {publicKey}}), publicKey},
	} {
		code, body, err := f.do(t, "POST", "/v1/chat/completions", `{}`, tc.mutate)
		seen, _ := f.seen.Load().(http.Header)
		if err != nil || code != 200 || body != `{"method":"POST","bytes":2}` {
			t.Fatalf("%s: %d %q %v", tc.name, code, body, err)
		}
		if got := seen.Values("X-Langfuse-Public-Key"); (tc.wantUser == "" && len(got) != 0) || (tc.wantUser != "" && (len(got) != 1 || got[0] != tc.wantUser)) {
			t.Fatalf("%s: vendor saw user header %q", tc.name, got)
		}
		if seen.Get("X-Langfuse-Sdk-Name") != "" {
			t.Fatalf("%s: an unlisted header was forwarded", tc.name)
		}
	}
	for _, tc := range []struct {
		name, outcome string
		mutate        func(*http.Request)
	}{
		{"another user", "credential_header", headers(map[string][]string{"Authorization": {encode("pk-worker-own:__vault_LLM_KEY__")}})},
		{"another user in the header", "credential_header", headers(map[string][]string{"Authorization": {sdk}, "X-Langfuse-Public-Key": {"pk-worker-own"}})},
		{"another user beside placeholders", "credential_header", headers(map[string][]string{"Authorization": {placeholders}, "X-Langfuse-Public-Key": {"pk-worker-own"}})},
		{"empty user header", "credential_header", headers(map[string][]string{"X-Langfuse-Public-Key": {""}})},
		{"two user headers", "credential_header", headers(map[string][]string{"Authorization": {sdk}, "X-Langfuse-Public-Key": {publicKey, publicKey}})},
		{"own secret key", "credential_header", headers(map[string][]string{"Authorization": {encode(publicKey + ":sk-worker-own")}})},
		{"user with a colon", "credential_header", headers(map[string][]string{"Authorization": {encode(publicKey + ":x:__vault_LLM_KEY__")}})},
		{"unpadded", "credential_header", headers(map[string][]string{"Authorization": {strings.TrimRight(sdk, "=")}})},
		{"placeholder in the user header", "placeholder_misplaced", headers(map[string][]string{"Authorization": {sdk}, "X-Langfuse-Public-Key": {"__vault_LLM_KEY__"}})},
	} {
		calls := f.calls.Load()
		code, _, _ := f.do(t, "POST", "/v1/chat/completions", `{}`, tc.mutate)
		if code != 400 || f.calls.Load() != calls || f.audit.last().Outcome != tc.outcome {
			t.Fatalf("%s: %d %+v", tc.name, code, f.audit.last())
		}
	}

	// Without a user header in the entry, the public key may still stand in
	// Authorization, and the client's copy of it is dropped like any
	// unlisted header.
	plain := newAdapterFixtureWith(t, "basicPair")
	setPair(plain)
	code, _, err := plain.do(t, "POST", "/v1/chat/completions", `{}`, headers(map[string][]string{"Authorization": {sdk}, "X-Langfuse-Public-Key": {publicKey}}))
	if seen, _ := plain.seen.Load().(http.Header); err != nil || code != 200 || seen.Get("X-Langfuse-Public-Key") != "" {
		t.Fatalf("plain pair: %d %v %v", code, err, seen)
	}
}

// The key never reaches the worker, even split across two writes of a
// streamed body: the broker aborts before releasing the first half.
func TestAdapterBlocksKeyEchoes(t *testing.T) {
	f := newAdapterFixture(t)
	code, body, err := f.do(t, "GET", "/v1/echo-split", "", nil)
	if err == nil && code == 200 && !strings.Contains(body, "tail") {
		t.Fatalf("expected an aborted stream, got %d", code)
	}
	if err == nil && strings.Contains(body, "tail") {
		t.Fatal("echoing stream completed")
	}
	if strings.Contains(body, adapterKeyV1[:len(adapterKeyV1)/2]) {
		t.Fatal("first half of the key released before screening")
	}
	if got := f.audit.last(); got.Event != auditchain.EventHTTPResponse || got.Outcome != "secret_echo" {
		t.Fatalf("echo outcome: %+v", got)
	}
	if code, _, _ := f.do(t, "GET", "/v1/echo-header", "", nil); code != 502 || f.audit.last().Outcome != "response_refused" {
		t.Fatalf("header echo: %d %+v", code, f.audit.last())
	}
}

// Server-sent events reach the worker as they are produced.
func TestAdapterStreamsServerSentEvents(t *testing.T) {
	f := newAdapterFixture(t)
	r, _ := http.NewRequest("GET", f.url("/v1/stream"), nil)
	r.Header.Set("Authorization", "Bearer __vault_LLM_KEY__")
	resp, err := f.client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	reader := bufio.NewReader(resp.Body)
	first, err := reader.ReadString('\n')
	if err != nil || first != "data: first\n" {
		t.Fatalf("first event not streamed: %q %v", first, err)
	}
	close(f.release)
	rest, _ := io.ReadAll(reader)
	if !strings.Contains(string(rest), "data: second") {
		t.Fatalf("second event missing: %q", rest)
	}
}

// After the vendor rejects a rotated-out key, the next request reads the new one.
func TestAdapterRefreshesKeyAfterVendorRejection(t *testing.T) {
	f := newAdapterFixture(t)
	f.acceptsV = adapterKeyV2
	if code, _, _ := f.do(t, "POST", "/v1/chat/completions", "{}", nil); code != 401 || f.keys.invalidated != 1 {
		t.Fatalf("rejection: %d invalidated=%d", code, f.keys.invalidated)
	}
	f.keys.mu.Lock()
	f.keys.value = adapterKeyV2
	f.keys.mu.Unlock()
	if code, _, _ := f.do(t, "POST", "/v1/chat/completions", "{}", nil); code != 200 {
		t.Fatalf("rotated key: %d", code)
	}
}

func TestAdapterFailsClosed(t *testing.T) {
	f := newAdapterFixture(t)
	f.audit.mu.Lock()
	f.audit.admitErr = auditchain.ErrCheckpointOverdue
	f.audit.mu.Unlock()
	if code, _, _ := f.do(t, "POST", "/v1/chat/completions", "{}", nil); code != 503 || f.audit.last().Outcome != "audit_unavailable" {
		t.Fatalf("audit unavailable: %d", code)
	}
	f.audit.mu.Lock()
	f.audit.admitErr = nil
	f.audit.mu.Unlock()
	f.keys.mu.Lock()
	f.keys.err = errors.New("vault sealed")
	f.keys.mu.Unlock()
	if code, _, _ := f.do(t, "POST", "/v1/chat/completions", "{}", nil); code != 503 || f.audit.last().Outcome != "key_unavailable" {
		t.Fatalf("key unavailable: %d", code)
	}
	if f.calls.Load() != 0 {
		t.Fatal("vendor called while failing closed")
	}
	invalid := &Proxy{adapter: &HeaderAdapter{}}
	rec := httptest.NewRecorder()
	invalid.forwardStrict(rec, httptest.NewRequest("GET", "https://example.com/", nil), "example.com:443", "example.com", 443, true, nil)
	if rec.Code != 503 {
		t.Fatalf("incomplete adapter served: %d", rec.Code)
	}
}

// A verified agent whose scope carries no catalog pool reaches nothing: its
// CONNECT is refused before a tunnel opens.
func TestAdapterRefusesAScopeWithoutAPool(t *testing.T) {
	f := newAdapterFixture(t)
	f.sessions.set(&brokercore.ProxyScope{VaultID: "vault-1", AgentID: "agent-uuid-1", WorkloadID: "pod-uid-1"})
	if code, _, _ := f.do(t, "POST", "/v1/chat/completions", "{}", nil); code != 0 || f.audit.last().Outcome != "pool" || f.calls.Load() != 0 {
		t.Fatalf("pool-less scope admitted: %d %+v", code, f.audit.last())
	}
}

// Paths some backends normalise differently are refused before the prefix
// match: path parameters and segments that begin with "..".
func TestUnsafePathRefusesTraversalForms(t *testing.T) {
	for path, unsafe := range map[string]bool{
		"/v1/allowed/..;/admin": true,
		"/v1/allowed;x=1":       true,
		"/v1/allowed/..x":       true,
		"/v1/allowed/../admin":  true,
		"/v1/allowed/./x":       true,
		"/v1/allowed/a..b":      false,
		"/v1/allowed/x.json":    false,
	} {
		if got := unsafePath(path); got != unsafe {
			t.Errorf("unsafePath(%q) = %v, want %v", path, got, unsafe)
		}
	}
}

// An entry with requestFields forwards a request only when each limited
// parameter appears once with a listed value, and audits every refusal.
func TestAdapterHoldsRequestFieldsToListedValues(t *testing.T) {
	f := newAdapterFixture(t, func(o *Options) {
		port := o.HeaderAdapter.Catalog.Current().Entries()[0].Port
		catalog, err := httpcatalog.Parse([]byte(fmt.Sprintf(`{"entries":[{
			"name":"llm","host":"example.com","port":%d,"pathPrefixes":["/v1/chat"],"methods":["POST"],
			"header":"Authorization","scheme":"Bearer","placeholder":"__vault_LLM_KEY__",
			"key":{"mount":"gatehouse","path":"vendors/llm","field":"key"},"pools":["pool-agent"],
			"requestFields":[{"name":"channel","values":["C0123456789"]}]}]}`, port)))
		if err != nil {
			t.Fatal(err)
		}
		o.HeaderAdapter.Catalog = catalog
	})
	if code, _, err := f.do(t, "POST", "/v1/chat/completions", `{"channel":"C0123456789","text":"x"}`, nil); err != nil || code != 200 {
		t.Fatalf("listed channel: %d %v", code, err)
	}
	for name, tc := range map[string]struct{ path, body string }{
		"unlisted":          {"/v1/chat/completions", `{"channel":"D0123456789","text":"x"}`},
		"missing":           {"/v1/chat/completions", `{"text":"x"}`},
		"duplicate key":     {"/v1/chat/completions", `{"channel":"C0123456789","channel":"D0123456789"}`},
		"query and body":    {"/v1/chat/completions?channel=C0123456789", `{"channel":"C0123456789"}`},
		"unlisted in query": {"/v1/chat/completions?channel=D0123456789", ``},
	} {
		calls := f.calls.Load()
		code, _, err := f.do(t, "POST", tc.path, tc.body, nil)
		if err != nil || code != http.StatusForbidden || f.calls.Load() != calls || f.audit.last().Outcome != "request_field" {
			t.Errorf("%s: %d %v outcome=%q, vendor calls %d->%d", name, code, err, f.audit.last().Outcome, calls, f.calls.Load())
		}
	}
}

// A Slack entry forwards a call that uses only its method's parameters and
// refuses a key Slack could read as a second channel, or one the method does
// not take, before anything reaches Slack.
func TestAdapterHoldsSlackCallsToTheirMethodsParameters(t *testing.T) {
	f := newAdapterFixture(t, func(o *Options) {
		port := o.HeaderAdapter.Catalog.Current().Entries()[0].Port
		entry := `{"name":"%s","host":"slack.com","port":%d,"pathPrefixes":["%s"],"methods":["%s"],
			"header":"Authorization","scheme":"Bearer","placeholder":"__vault_LLM_KEY__",
			"key":{"mount":"gatehouse","path":"vendors/slack","field":"key"},"pools":["%s"],
			"requestFields":[{"name":"channel","values":["C0123456789"]}]}`
		catalog, err := httpcatalog.Parse([]byte(`{"entries":[` +
			fmt.Sprintf(entry, "slack", port, "/api/conversations.history", "GET", "pool-agent") + `,` +
			fmt.Sprintf(entry, "slack-post", port, "/api/chat.postMessage", "POST", "pool-other") + `]}`))
		if err != nil {
			t.Fatal(err)
		}
		o.HeaderAdapter.Catalog = catalog
	})
	// The test vendor's certificate names example.com, not slack.com.
	f.proxy.upstream.TLSClientConfig.ServerName = "example.com"
	call := func(method, path, query string) int {
		t.Helper()
		r, err := http.NewRequest(method, "https://slack.com:"+strconv.Itoa(f.port)+path+"?"+query, nil)
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Authorization", "Bearer __vault_LLM_KEY__")
		resp, err := f.client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	// Each row names the method, so a read is told apart from a post, the
	// refused rows included.
	if code := call("GET", "/api/conversations.history", "channel=C0123456789&limit=20"); code != http.StatusOK || f.calls.Load() != 1 ||
		f.audit.last().Operation != "slack.conversations_history" {
		t.Fatalf("listed channel: %d, vendor calls %d, operation %q", code, f.calls.Load(), f.audit.last().Operation)
	}
	for name, tc := range map[string]struct {
		method, path, query, outcome, operation string
		status                                  int
	}{
		"leading space":                 {"GET", "/api/conversations.history", "channel=C0123456789&%20channel=D0123456789", "request_field", "slack.conversations_history", http.StatusForbidden},
		"NUL":                           {"GET", "/api/conversations.history", "channel=C0123456789&channel%00=D0123456789", "request_field", "slack.conversations_history", http.StatusForbidden},
		"not a parameter of the method": {"GET", "/api/conversations.history", "channel=C0123456789&name=eyes", "request_field", "slack.conversations_history", http.StatusForbidden},
		"unlisted verb":                 {"POST", "/api/conversations.history", "channel=C0123456789", "method", "slack.conversations_history", http.StatusMethodNotAllowed},
		"another pool's method":         {"POST", "/api/chat.postMessage", "channel=C0123456789", "pool", "slack.chat_post_message", http.StatusForbidden},
	} {
		code := call(tc.method, tc.path, tc.query)
		if row := f.audit.last(); code != tc.status || f.calls.Load() != 1 || row.Outcome != tc.outcome || row.Operation != tc.operation {
			t.Errorf("%s: %d outcome=%q operation=%q, vendor calls %d", name, code, row.Outcome, row.Operation, f.calls.Load())
		}
	}
}

// A groundcover MCP entry forwards the query client's own requests, with the
// headers it sends, and names the tool in the row. It refuses another tool,
// a message it cannot read as one, an unlisted argument and a missing,
// repeated or other X-Backend-Id before anything reaches groundcover, with
// the reason in the row and the refusal header.
func TestAdapterForwardsOnlyListedGroundcoverTools(t *testing.T) {
	f := newAdapterFixture(t, func(o *Options) {
		port := o.HeaderAdapter.Catalog.Current().Entries()[0].Port
		catalog, err := httpcatalog.Parse([]byte(fmt.Sprintf(`{"entries":[{"name":"groundcover","host":"mcp.groundcover.com","port":%d,
			"pathPrefixes":["/api/mcp"],"methods":["DELETE","GET","POST"],"header":"Authorization","scheme":"Bearer",
			"placeholder":"__vault_LLM_KEY__","key":{"mount":"gatehouse","path":"vendors/groundcover","field":"key"},
			"forwardHeaders":["Mcp-Session-Id","Mcp-Protocol-Version","Last-Event-Id","X-Backend-Id","X-Tenant-UUID","X-Timezone"],
			"requestHeaders":[{"name":"X-Backend-Id","values":["us-backend"]}],"pools":["pool-agent"]}]}`, port)))
		if err != nil {
			t.Fatal(err)
		}
		o.HeaderAdapter.Catalog = catalog
	})
	// The test vendor's certificate names example.com, not groundcover's host.
	f.proxy.upstream.TLSClientConfig.ServerName = "example.com"
	// call sends what a Python query client sends: every header it sets, the
	// session after initialize, and its body. backends replaces X-Backend-Id.
	call := func(method, body string, backends ...string) (int, string) {
		t.Helper()
		r, err := http.NewRequest(method, "https://mcp.groundcover.com:"+strconv.Itoa(f.port)+"/api/mcp", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Accept", "application/json, text/event-stream")
		r.Header.Set("Authorization", "Bearer __vault_LLM_KEY__")
		r.Header.Set("MCP-Protocol-Version", "2024-11-05")
		r.Header.Set("User-Agent", "example-query/0.1.0")
		r.Header.Set("X-Tenant-UUID", "00000000-0000-0000-0000-000000000000")
		r.Header.Set("X-Timezone", "UTC")
		if body != "" {
			r.Header.Set("Content-Type", "application/json")
		}
		if !strings.Contains(body, `"initialize"`) {
			r.Header.Set("Mcp-Session-Id", "session-1")
		}
		if backends == nil {
			backends = []string{"us-backend"}
		}
		for _, b := range backends {
			r.Header.Add("X-Backend-Id", b)
		}
		resp, err := f.client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode, resp.Header.Get(RefusalHeader)
	}
	tool := func(name string) string {
		return `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"` + name + `","arguments":{"query":"* | limit 1","period":"PT1H"}}}`
	}
	// The POSTs of one log query and one metric query (initialize, the
	// notification and each tool call), byte for byte as the client
	// serializes them, then the event stream.
	calls := int32(0)
	for _, tc := range []struct{ method, body, operation string }{
		{"POST", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"example-query","version":"0.1.0"}}}`, "groundcover.initialize"},
		{"POST", `{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}`, "groundcover.initialized"},
		{"POST", `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"query_logs","arguments":{"query":"level:error | limit 10","period":"PT1H"}}}`, "groundcover.query_logs"},
		{"POST", `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"query_metrics","arguments":{"mode":"query_range","envs":["production"],"start":"2026-01-01T00:00:00Z","end":"2026-01-01T01:00:00Z","promql":"sum(up)","step":"1m"}}}`, "groundcover.query_metrics"},
		{"GET", "", ""},
	} {
		calls++
		code, refusal := call(tc.method, tc.body)
		seen, _ := f.seen.Load().(http.Header)
		if code != http.StatusOK || refusal != "" || f.calls.Load() != calls || f.audit.last().Operation != tc.operation || seen.Get("X-Backend-Id") != "us-backend" {
			t.Errorf("%s %s: %d %q operation=%q, vendor calls %d, backend %q", tc.method, tc.operation, code, refusal, f.audit.last().Operation, f.calls.Load(), seen.Get("X-Backend-Id"))
			calls = f.calls.Load()
		}
	}
	for name, tc := range map[string]struct {
		method, body string
		backends     []string
		outcome      string
		status       int
	}{
		"query_issues":        {"POST", tool("query_issues"), nil, "mcp_tool", http.StatusForbidden},
		"an unknown tool":     {"POST", tool("not_a_tool"), nil, "mcp_tool", http.StatusForbidden},
		"tools/list":          {"POST", `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`, nil, "mcp_tool", http.StatusForbidden},
		"a batch":             {"POST", `[` + tool("query_logs") + `,` + tool("query_issues") + `]`, nil, "mcp_shape", http.StatusBadRequest},
		"a repeated name":     {"POST", `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"query_logs","name":"query_issues"}}`, nil, "mcp_shape", http.StatusBadRequest},
		"a backend argument":  {"POST", strings.Replace(tool("query_logs"), `"arguments":{`, `"arguments":{"backend_id":"eu-backend",`, 1), nil, "mcp_argument", http.StatusForbidden},
		"a tenant argument":   {"POST", strings.Replace(tool("query_logs"), `"arguments":{`, `"arguments":{"tenant_uuid":"x",`, 1), nil, "mcp_argument", http.StatusForbidden},
		"issues via _from":    {"POST", strings.Replace(tool("query_logs"), `"* | limit 1"`, `"* | join by (namespace) (_from:issues | fields namespace) | limit 1"`, 1), nil, "mcp_argument", http.StatusForbidden},
		"no backend":          {"POST", tool("query_logs"), []string{}, "request_header", http.StatusForbidden},
		"another backend":     {"POST", tool("query_logs"), []string{"eu-backend"}, "request_header", http.StatusForbidden},
		"a repeated backend":  {"POST", tool("query_logs"), []string{"us-backend", "us-backend"}, "request_header", http.StatusForbidden},
		"two backends":        {"POST", tool("query_logs"), []string{"us-backend", "eu-backend"}, "request_header", http.StatusForbidden},
		"the stream, another": {"GET", "", []string{"eu-backend"}, "request_header", http.StatusForbidden},
	} {
		code, refusal := call(tc.method, tc.body, tc.backends...)
		if row := f.audit.last(); code != tc.status || refusal != tc.outcome || row.Outcome != tc.outcome || row.Operation != "" || f.calls.Load() != calls {
			t.Errorf("%s: %d %q outcome=%q operation=%q, vendor calls %d", name, code, refusal, row.Outcome, row.Operation, f.calls.Load())
		}
	}
}

// A groundcover entry with no X-Backend-Id pin, as a catalog written before
// requestHeaders has, still serves the query client, with any backend header
// or none, and still refuses another tool, a backend argument and _from.
func TestAdapterServesAnUnpinnedGroundcoverEntry(t *testing.T) {
	f := newAdapterFixture(t, func(o *Options) {
		port := o.HeaderAdapter.Catalog.Current().Entries()[0].Port
		catalog, err := httpcatalog.Parse([]byte(fmt.Sprintf(`{"entries":[{"name":"groundcover","host":"mcp.groundcover.com","port":%d,
			"pathPrefixes":["/api/mcp"],"methods":["POST"],"header":"Authorization","scheme":"Bearer",
			"placeholder":"__vault_LLM_KEY__","key":{"mount":"gatehouse","path":"vendors/groundcover","field":"key"},
			"forwardHeaders":["Mcp-Session-Id","X-Backend-Id"],"pools":["pool-agent"]}]}`, port)))
		if err != nil {
			t.Fatal(err)
		}
		o.HeaderAdapter.Catalog = catalog
	})
	f.proxy.upstream.TLSClientConfig.ServerName = "example.com"
	call := func(body string, backends ...string) (int, string) {
		t.Helper()
		r, err := http.NewRequest("POST", "https://mcp.groundcover.com:"+strconv.Itoa(f.port)+"/api/mcp", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Authorization", "Bearer __vault_LLM_KEY__")
		r.Header.Set("Content-Type", "application/json")
		for _, b := range backends {
			r.Header.Add("X-Backend-Id", b)
		}
		resp, err := f.client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode, resp.Header.Get(RefusalHeader)
	}
	logs := func(args string) string {
		return `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"query_logs","arguments":{` + args + `}}}`
	}
	calls := int32(0)
	for _, backends := range [][]string{nil, {"us-backend"}} {
		calls++
		if code, refusal := call(logs(`"query":"level:error | limit 10","period":"PT1H"`), backends...); code != http.StatusOK || refusal != "" || f.calls.Load() != calls || f.audit.last().Operation != "groundcover.query_logs" {
			t.Errorf("backends %v: %d %q, vendor calls %d", backends, code, refusal, f.calls.Load())
		}
	}
	for name, tc := range map[string]struct{ body, outcome string }{
		"query_issues":       {`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"query_issues","arguments":{}}}`, "mcp_tool"},
		"a backend argument": {logs(`"query":"*","backend_id":"eu-backend"`), "mcp_argument"},
		"_from":              {logs(`"query":"_from:issues | limit 1"`), "mcp_argument"},
	} {
		if code, refusal := call(tc.body); code != http.StatusForbidden || refusal != tc.outcome || f.calls.Load() != calls {
			t.Errorf("%s: %d %q, vendor calls %d", name, code, refusal, f.calls.Load())
		}
	}
}

// Authorization refuses a call after its entry matched, which is where the
// row for an unentitled requester is written. A Slack call refused there
// names its method too, and the same call from a member goes through.
func TestAdapterSlackAuthorizationRefusalNamesTheMethod(t *testing.T) {
	f := newAdapterFixture(t, func(o *Options) {
		port := o.HeaderAdapter.Catalog.Current().Entries()[0].Port
		catalog, err := httpcatalog.Parse([]byte(fmt.Sprintf(`{"pools":[
			{"name":"pool-agent","namespace":"n","serviceAccount":"claude","identity":"claude-session","ccpoolID":"ccpool_abc","ceiling":"T1"}],
			"entries":[{"name":"slack","host":"slack.com","port":%d,"pathPrefixes":["/api/conversations.history"],"methods":["GET"],
			"header":"Authorization","scheme":"Bearer","placeholder":"__vault_LLM_KEY__",
			"key":{"mount":"gatehouse","path":"vendors/slack","field":"key"},"pools":["pool-agent"],"tier":"T1","requires":["%s"],
			"requestFields":[{"name":"channel","values":["C0123456789"]}]}]}`, port, authzGroup)))
		if err != nil {
			t.Fatal(err)
		}
		o.HeaderAdapter.Catalog = catalog
		o.HeaderAdapter.Runner = fakeRunner{
			"alice": {Kind: runnerid.KindPerson, Subject: "sso|alice", Pools: []string{"ccpool_abc"}, TokenSHA256: "aa"},
			"bob":   {Kind: runnerid.KindPerson, Subject: "sso|bob", Pools: []string{"ccpool_abc"}, TokenSHA256: "bb"}}
		o.HeaderAdapter.Sessions = &authorizetest.MemBinder{}
		o.HeaderAdapter.Entitlements = &entitlement.Cache{Source: directory{"sso|alice": {authzGroup}, "sso|bob": {}}}
	})
	// The test vendor's certificate names example.com, not slack.com.
	f.proxy.upstream.TLSClientConfig.ServerName = "example.com"
	call := func(session string) int {
		t.Helper()
		client := newTrustingClient(f.proxyURL, url.User("workload-token"), f.roots)
		defer client.CloseIdleConnections()
		client.Transport.(*http.Transport).ProxyConnectHeader = http.Header{SessionHeader: {session}}
		r, _ := http.NewRequest("GET", "https://slack.com:"+strconv.Itoa(f.port)+"/api/conversations.history?channel=C0123456789", nil)
		r.Header.Set("Authorization", "Bearer __vault_LLM_KEY__")
		resp, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	if code, row := call("bob"), f.audit.last(); code != http.StatusForbidden || f.calls.Load() != 0 || row.Outcome != "not_entitled" ||
		row.Binding != "slack" || row.Operation != "slack.conversations_history" {
		t.Fatalf("non-member: %d outcome=%q binding=%q operation=%q, vendor calls %d", code, row.Outcome, row.Binding, row.Operation, f.calls.Load())
	}
	if code, row := call("alice"), f.audit.last(); code != http.StatusOK || f.calls.Load() != 1 || row.Operation != "slack.conversations_history" {
		t.Fatalf("member: %d outcome=%q operation=%q, vendor calls %d", code, row.Outcome, row.Operation, f.calls.Load())
	}
}
