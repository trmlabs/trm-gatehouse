package mitm

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/auditchain"
	"github.com/Infisical/agent-vault/internal/authorize"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/entitlement"
	"github.com/Infisical/agent-vault/internal/httpcatalog"
	"github.com/Infisical/agent-vault/internal/runnerid"
	"github.com/Infisical/agent-vault/internal/store"
)

// subagentPods answers PodRunning from the Pods marked live.
type subagentPods struct {
	mu   sync.Mutex
	live map[string]string // Pod UID: the run it serves
}

func (p *subagentPods) PodRunning(_ context.Context, pod brokercore.PodRef, run string) (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.live[pod.UID] == run, nil
}

func (p *subagentPods) end(uid string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.live, uid)
}

// subagentRunsFor are the explorer Automation's run, its subagent's run (no Automation named), and an unregistered web person run.
var subagentRunsFor = cursorRunner{
	"parent":  {Kind: runnerid.KindAgent, Subject: "service_account:9", Owner: "service_account:9", Run: "bc-1", Source: "AUTOMATIONS", Automation: "auto-1", Team: "7"},
	"child":   {Kind: runnerid.KindAgent, Subject: "service_account:9", Owner: "service_account:9", Run: "bc-20", Source: "API", Team: "7"},
	"person":  {Kind: runnerid.KindPerson, Subject: "alice@example.com", Owner: "user:1", Run: "bc-30", Source: "WEBSITE", Team: "7"},
	"auditor": {Kind: runnerid.KindAgent, Subject: "service_account:9", Owner: "service_account:9", Run: "bc-2", Source: "AUTOMATIONS", Automation: "auto-2", Team: "7"},
}

type subagentProxyFixture struct {
	proxyURL *url.URL
	roots    *x509.CertPool
	audit    *adapterAudit
	pods     *subagentPods
	port     int
	vendor   int // requests the vendor received
	mu       sync.Mutex
}

// newSubagentProxyFixture is one automation pool granted to explorer (two subagents) and auditor (none) behind a real store registry.
func newSubagentProxyFixture(t *testing.T) *subagentProxyFixture {
	t.Helper()
	f := &subagentProxyFixture{audit: &adapterAudit{}, pods: &subagentPods{live: map[string]string{"pod-parent": "bc-1", "pod-auditor": "bc-2"}}}
	vendor := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.vendor++
		f.mu.Unlock()
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(vendor.Close)
	_, portText, _ := net.SplitHostPort(strings.TrimPrefix(vendor.URL, "https://"))
	f.port, _ = strconv.Atoi(portText)
	catalog, err := httpcatalog.Parse([]byte(fmt.Sprintf(`{"pools":[{"name":"automations","namespace":"n","serviceAccount":"worker","identity":"cursor-automation"},
		{"name":"people","namespace":"p","serviceAccount":"worker","identity":"cursor-session"}],
	 "entries":[{"name":"tracker","host":"example.com","port":%d,"pathPrefixes":["/v1/"],"methods":["GET"],"header":"Authorization","placeholder":"__vault_KEY__",
	  "key":{"mount":"gatehouse","path":"vendors/t","field":"f"},"pools":["automations","people"]}],
	 "automations":[{"id":"auto-1","name":"explorer","owner":"platform-team","entries":["tracker"],"subagents":2},
	  {"id":"auto-2","name":"auditor","owner":"platform-team","entries":["tracker"]}]}`, f.port)))
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "subagents.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	notAfter := time.Now().Add(time.Hour)
	podScope := func(pool, uid, run string) *brokercore.ProxyScope {
		return &brokercore.ProxyScope{VaultID: "vault-1", AgentID: "agent-uuid-1", Pool: pool, WorkloadID: uid, ClaimedRun: run, NotAfter: notAfter,
			IdentityKind: brokercore.KindPodToken, Pod: brokercore.PodRef{Namespace: "n", Name: "worker-" + uid, UID: uid, Container: "agent"}}
	}
	scopes := map[string]*brokercore.ProxyScope{
		"parent-pod":  podScope("automations", "pod-parent", "bc-1"),
		"child-pod":   podScope("automations", "pod-child", "bc-20"),
		"person-pod":  podScope("automations", "pod-person", "bc-30"),
		"auditor-pod": podScope("automations", "pod-auditor", "bc-2"),
		"people-pod":  podScope("people", "pod-people", "bc-30"),
	}
	sessions := &fakeSessionResolver{resolve: func(token, _ string) (*brokercore.ProxyScope, error) {
		if s, ok := scopes[token]; ok {
			return s, nil
		}
		return nil, brokercore.ErrInvalidSession
	}}
	var p *Proxy
	f.proxyURL, f.roots, p = setupProxy(t, sessions, &fakeCredProvider{}, func(o *Options) {
		o.StrictCredentialProxy = true
		o.HeaderAdapter = &HeaderAdapter{Catalog: catalog, Keys: &adapterKeys{value: "unused"}, Audit: f.audit, Runner: subagentRunsFor,
			Entitlements: &entitlement.Cache{Source: directory{}},
			Sessions:     &authorize.Subagents{Binder: st, Registry: st, Pods: f.pods, Wait: 50 * time.Millisecond, LiveTTL: time.Nanosecond}}
	})
	vendorRoots := x509.NewCertPool()
	vendorRoots.AddCert(vendor.Certificate())
	p.upstream.TLSClientConfig.RootCAs = vendorRoots
	vendorAddr := strings.TrimPrefix(vendor.URL, "https://")
	p.upstream.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, vendorAddr)
	}
	return f
}

// send makes one request from a Pod as a run and returns status, refusal code and body.
func (f *subagentProxyFixture) send(t *testing.T, pod, run, method, rawURL, body string) (int, string, string) {
	t.Helper()
	client := newTrustingClient(f.proxyURL, url.User(pod), f.roots)
	defer client.CloseIdleConnections()
	client.Transport.(*http.Transport).ProxyConnectHeader = http.Header{SessionHeader: {run}}
	r, err := http.NewRequest(method, rawURL, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(r)
	if err != nil {
		return 0, "connect", ""
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header.Get(RefusalHeader), string(data)
}

func (f *subagentProxyFixture) tracker() string {
	return "https://example.com:" + strconv.Itoa(f.port) + "/v1/items"
}

func register(run string) string { return "https://" + SubagentHost + "/v1/subagents/" + run }

// A subagent is refused until its parent registers it through the proxy, then served the Automation's entry, and refused again once the parent Pod ends.
func TestSubagentRegisteredThroughTheProxyActsAsTheAutomation(t *testing.T) {
	f := newSubagentProxyFixture(t)
	if code, refusal, _ := f.send(t, "child-pod", "child", "GET", f.tracker(), ""); code != http.StatusForbidden || refusal != "not_automation" {
		t.Fatalf("before registration: %d %q", code, refusal)
	}
	code, refusal, body := f.send(t, "parent-pod", "parent", "POST", register("bc-20"), "")
	if code != http.StatusOK || refusal != "" {
		t.Fatalf("register: %d %q %s", code, refusal, body)
	}
	var answer subagentRegistered
	if err := json.Unmarshal([]byte(body), &answer); err != nil || answer.Run != "bc-20" || answer.ParentRun != "bc-1" || answer.Automation != "auto-1" || answer.Expires == "" {
		t.Fatalf("answer %q %v", body, err)
	}
	rows := f.audit.all()
	last := rows[len(rows)-1]
	if last.Event != auditchain.EventHTTPResponse || last.Outcome != "subagent_registered" || last.Binding != "subagents" || last.Operation != "subagent.register" ||
		last.Run != "bc-1" || last.ParentRun != "" || last.Path != "/v1/subagents/bc-20" || last.Automation != "auto-1" || last.PodUID != "pod-parent" {
		t.Fatalf("registration row %+v", last)
	}
	if code, refusal, body := f.send(t, "child-pod", "child", "GET", f.tracker(), ""); code != http.StatusOK || refusal != "" || body != "ok" {
		t.Fatalf("registered subagent: %d %q %q", code, refusal, body)
	}
	rows = f.audit.all()
	last = rows[len(rows)-1]
	if last.Binding != "tracker" || last.RequesterKind != "automation" || last.Automation != "auto-1" || last.AutomationName != "explorer" ||
		last.Source != "API" || last.Run != "bc-20" || last.ParentRun != "bc-1" || last.PodUID != "pod-child" || last.TokenSHA256 != "sha-child" {
		t.Fatalf("subagent row %+v", last)
	}
	f.pods.end("pod-parent")
	if code, refusal, _ := f.send(t, "child-pod", "child", "GET", f.tracker(), ""); code != http.StatusForbidden || refusal != "subagent_parent_gone" {
		t.Fatalf("after the parent ended: %d %q", code, refusal)
	}
	rows = f.audit.all()
	if last = rows[len(rows)-1]; last.Outcome != "subagent_parent_gone" || last.Run != "bc-20" || last.ParentRun != "bc-1" {
		t.Fatalf("refusal row %+v", last)
	}
}

// Only a POST from an Automation run whose block sets subagents registers one, on an automation pool, and nothing on the route reaches a destination.
func TestSubagentRouteRefusals(t *testing.T) {
	f := newSubagentProxyFixture(t)
	if code, refusal, _ := f.send(t, "parent-pod", "parent", "POST", register("bc-20"), ""); code != http.StatusOK || refusal != "" {
		t.Fatalf("register: %d %q", code, refusal)
	}
	for _, c := range []struct {
		name, pod, run, method, url, body string
		status                            int
		refusal                           string
	}{
		{"a person's run", "person-pod", "person", "POST", register("bc-21"), "", http.StatusForbidden, "not_automation"},
		{"a subagent", "child-pod", "child", "POST", register("bc-21"), "", http.StatusForbidden, "subagent_nested"},
		{"no subagents in the block", "auditor-pod", "auditor", "POST", register("bc-21"), "", http.StatusForbidden, "subagents_not_granted"},
		{"GET", "parent-pod", "parent", "GET", register("bc-21"), "", http.StatusMethodNotAllowed, "method"},
		{"a body", "parent-pod", "parent", "POST", register("bc-21"), "{}", http.StatusBadRequest, "request_shape"},
		{"a query", "parent-pod", "parent", "POST", register("bc-21") + "?x=1", "", http.StatusBadRequest, "request_shape"},
		{"another path", "parent-pod", "parent", "POST", "https://" + SubagentHost + "/v1/other", "", http.StatusBadRequest, "request_shape"},
		{"not a run id", "parent-pod", "parent", "POST", register("x-21"), "", http.StatusBadRequest, "request_shape"},
		{"its own run", "parent-pod", "parent", "POST", register("bc-1"), "", http.StatusBadRequest, "request_shape"},
		{"no run token", "parent-pod", "", "POST", register("bc-21"), "", http.StatusServiceUnavailable, "session_missing"},
	} {
		code, refusal, _ := f.send(t, c.pod, c.run, c.method, c.url, c.body)
		if refusal != c.refusal || code != c.status {
			t.Errorf("%s: %d %q, want %d %q", c.name, code, refusal, c.status, c.refusal)
		}
	}
	// Off automation pools the route does not exist and CONNECT is refused like any unlisted host.
	if code, refusal, _ := f.send(t, "people-pod", "person", "POST", register("bc-21"), ""); code != 0 || refusal != "connect" {
		t.Fatalf("person pool: %d %q", code, refusal)
	}
	// A third subagent is over explorer's count of two.
	if code, refusal, _ := f.send(t, "parent-pod", "parent", "POST", register("bc-21"), ""); code != http.StatusOK {
		t.Fatalf("second: %d %q", code, refusal)
	}
	if code, refusal, _ := f.send(t, "parent-pod", "parent", "POST", register("bc-22"), ""); code != http.StatusForbidden || refusal != "subagent_limit" {
		t.Fatalf("third: %d %q", code, refusal)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.vendor != 0 {
		t.Fatalf("the route reached the destination %d times", f.vendor)
	}
	for _, e := range f.audit.all() {
		if err := e.Validate(); err != nil {
			t.Fatalf("row %+v: %v", e, err)
		}
	}
}
