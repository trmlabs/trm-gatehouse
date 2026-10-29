package mitm

import (
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/auditchain"
	"github.com/Infisical/agent-vault/internal/authorize/authorizetest"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/httpcatalog"
	"github.com/Infisical/agent-vault/internal/runnerid"
)

// settingsCatalog has an Automation pool with two Automations, one with
// settings and one without, and a workload pool that names no requester.
const settingsCatalog = `{"pools":[{"name":"automations","namespace":"n","serviceAccount":"worker","identity":"cursor-automation"},
  {"name":"plain","namespace":"m","serviceAccount":"worker","identity":"workload"}],
 "entries":[{"name":"open","host":"api.vendor.example","pathPrefixes":["/"],"methods":["GET"],"header":"Authorization","placeholder":"__vault_KEY__","key":{"mount":"gatehouse","path":"vendors/p","field":"f"},"pools":["automations","plain"]}],
 "automations":[
  {"id":"auto-1","name":"explorer","owner":"platform-team","entries":["open"],"settings":{"API_BASE":"https://api.example.com/v1","AGENT_USER_IDS":"agent-1"}},
  {"id":"auto-2","name":"auditor","owner":"platform-team","entries":["open"]}]}`

// settingsRuns are Cursor run tokens: each Automation's run, a person's run
// from the web, an unlisted Automation's run, and a run started for another
// Pod than the one presenting it.
var settingsRuns = cursorRunner{
	"run-1":     {Kind: runnerid.KindPerson, Subject: "owner@example.com", Owner: "user:1", Run: "bc-1", Source: "AUTOMATIONS", Automation: "auto-1"},
	"run-2":     {Kind: runnerid.KindAgent, Subject: "service_account:4", Owner: "service_account:4", Run: "bc-2", Source: "AUTOMATIONS", Automation: "auto-2"},
	"web":       {Kind: runnerid.KindPerson, Subject: "owner@example.com", Owner: "user:1", Run: "bc-3", Source: "WEBSITE"},
	"unlisted":  {Kind: runnerid.KindPerson, Subject: "owner@example.com", Owner: "user:1", Run: "bc-4", Source: "AUTOMATIONS", Automation: "auto-9"},
	"other-pod": {Kind: runnerid.KindPerson, Subject: "owner@example.com", Owner: "user:1", Run: "bc-elsewhere", Source: "AUTOMATIONS", Automation: "auto-1"},
}

type settingsFixture struct {
	proxy *url.URL
	audit *adapterAudit
}

// newSettingsFixture serves the settings route. A worker proves its Pod with
// "<pool>/<pod>/<claimed run>", as the broker's attestation would read it
// from the live Pod.
func newSettingsFixture(t *testing.T) *settingsFixture {
	t.Helper()
	catalog, err := httpcatalog.Parse([]byte(settingsCatalog))
	if err != nil {
		t.Fatal(err)
	}
	f := &settingsFixture{audit: &adapterAudit{}}
	pods := &fakeSessionResolver{resolve: func(token, _ string) (*brokercore.ProxyScope, error) {
		parts := strings.Split(token, "/")
		if len(parts) != 3 {
			return nil, brokercore.ErrInvalidSession
		}
		return &brokercore.ProxyScope{VaultID: "vault-1", AgentID: "agent-" + parts[1], Pool: parts[0], WorkloadID: parts[1], ClaimedRun: parts[2]}, nil
	}}
	f.proxy, _, _ = setupProxy(t, pods, &fakeCredProvider{}, func(o *Options) {
		o.StrictCredentialProxy = true
		o.HeaderAdapter = &HeaderAdapter{Catalog: catalog, Keys: &adapterKeys{}, Audit: f.audit, Runner: settingsRuns, Sessions: &authorizetest.MemBinder{}}
	})
	return f
}

// get asks for settings as a sidecar does: the Pod's proof and, when given,
// the run's token. It returns the status, the body and the refusal header.
func (f *settingsFixture) get(t *testing.T, method, path, proof, run string) (int, string, string) {
	t.Helper()
	r, err := http.NewRequest(method, "http://"+f.proxy.Host+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if proof != "" {
		r.Header.Set("Proxy-Authorization", "Bearer "+proof)
	}
	if run != "" {
		r.Header.Set(SessionHeader, run)
	}
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body), resp.Header.Get(RefusalHeader)
}

// A run's sidecar gets exactly its own Automation's settings, an Automation
// without settings and a pool that names no Automation get an empty set, and
// each answer's audit row names the settings and never a value.
func TestSettingsServedForTheRunsOwnAutomation(t *testing.T) {
	f := newSettingsFixture(t)
	for _, c := range []struct {
		name, proof, run, body, names, automation string
	}{
		{"automation with settings", "automations/pod-1/bc-1", "run-1", `{"settings":{"AGENT_USER_IDS":"agent-1","API_BASE":"https://api.example.com/v1"}}`, "AGENT_USER_IDS,API_BASE", "auto-1"},
		{"automation without settings", "automations/pod-2/bc-2", "run-2", `{"settings":{}}`, "", "auto-2"},
		{"pool that names no automation", "plain/pod-3/", "", `{"settings":{}}`, "", ""},
	} {
		status, body, _ := f.get(t, http.MethodGet, httpcatalog.SettingsPath, c.proof, c.run)
		if status != http.StatusOK || body != c.body {
			t.Errorf("%s: %d %s", c.name, status, body)
			continue
		}
		row := f.audit.last()
		if row.Event != auditchain.EventSettings || row.Outcome != "served" || row.Settings != c.names || row.Automation != c.automation || row.Path != httpcatalog.SettingsPath {
			t.Errorf("%s: row %+v", c.name, row)
		}
		if strings.Contains(strings.Join([]string{row.Settings, row.Decision, row.Target, row.Path}, " "), "api.example.com") {
			t.Errorf("%s: a value reached the row: %+v", c.name, row)
		}
	}
	if row := f.audit.all()[0]; row.AutomationName != "explorer" || row.AutomationOwner != "platform-team" || row.Requester != "owner@example.com" || row.Pool != "automations" || row.PodUID != "pod-1" {
		t.Errorf("first row %+v", row)
	}
}

// Every refusal is a bare 403, no body and no refusal code, and its audit row
// names why: a run started for another Pod, a person's run on the
// Automation pool, an Automation the catalog does not list, a run token on a
// pool that takes none, and a Pod the broker does not admit.
func TestSettingsRefusalsAreBare(t *testing.T) {
	f := newSettingsFixture(t)
	for _, c := range []struct {
		name, proof, run, decision string
	}{
		{"another pod's run", "automations/pod-1/bc-1", "other-pod", "session_run"},
		{"a person's run", "automations/pod-3/bc-3", "web", "not_automation"},
		{"unlisted automation", "automations/pod-4/bc-4", "unlisted", "automation_unlisted"},
		{"no run token", "automations/pod-1/bc-1", "", "session_missing"},
		{"run token on a workload pool", "plain/pod-5/bc-1", "run-1", "session_unexpected"},
		{"pod not admitted", "not-a-pod", "run-1", ""},
		{"no pod proof", "", "run-1", ""},
	} {
		status, body, refusal := f.get(t, http.MethodGet, httpcatalog.SettingsPath, c.proof, c.run)
		if status != http.StatusForbidden || body != "" || refusal != "" {
			t.Errorf("%s: %d %q %q", c.name, status, body, refusal)
		}
		row := f.audit.last()
		if row.Event != auditchain.EventDenied || row.Decision != c.decision || row.Outcome != "refused" || row.Operation != "automation.settings" || row.Settings != "" {
			t.Errorf("%s: row %+v", c.name, row)
		}
	}
}

// Only a plain GET of the route itself is served: another method, a query or
// a body is a bad request, answered before any identity check.
func TestSettingsRouteIsAPlainGet(t *testing.T) {
	f := newSettingsFixture(t)
	for _, c := range []struct{ method, path string }{
		{http.MethodPost, httpcatalog.SettingsPath},
		{http.MethodGet, httpcatalog.SettingsPath + "?automation=auto-2"},
		{http.MethodDelete, httpcatalog.SettingsPath},
	} {
		if status, body, _ := f.get(t, c.method, c.path, "automations/pod-1/bc-1", "run-1"); status != http.StatusBadRequest || body != "" {
			t.Errorf("%s %s: %d %q", c.method, c.path, status, body)
		}
	}
	if n := len(f.audit.all()); n != 0 {
		t.Fatalf("%d rows for bad requests", n)
	}
}

// Nothing is served that cannot be recorded.
func TestSettingsNeedTheAuditTrail(t *testing.T) {
	f := newSettingsFixture(t)
	f.audit.admitErr = errors.New("checkpoint overdue")
	if status, body, _ := f.get(t, http.MethodGet, httpcatalog.SettingsPath, "automations/pod-1/bc-1", "run-1"); status != http.StatusServiceUnavailable || body != "" {
		t.Fatalf("%d %q", status, body)
	}
}
