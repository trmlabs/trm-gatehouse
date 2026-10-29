package mitm

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/authorize/authorizetest"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/entitlement"
	"github.com/Infisical/agent-vault/internal/githubapp"
	"github.com/Infisical/agent-vault/internal/httpcatalog"
	"github.com/Infisical/agent-vault/internal/runnerid"
)

// restartFixture fronts a fake GitHub for a repository that opts into the CI
// restart operations, with a git entry that lets the pool push under
// cursor/pool-agent/. Each route answers only to a token minted with exactly
// the scope it needs, and the fake records every write GitHub received.
type restartFixture struct {
	*apiFixture
	received []string // "METHOD path body" for every write
	answer   string   // the update-branch answer as "status body"; empty accepts it
}

const (
	restartRepo   = "/repos/example-org/example-repo"
	updateScope   = `{"contents":"write","metadata":"read","pull_requests":"write"}`
	rerunScope    = `{"actions":"write","metadata":"read"}`
	restartCommit = "0123456789abcdef0123456789abcdef01234567"
)

func newRestartFixture(t *testing.T, operations, refPrefixes string) *restartFixture {
	t.Helper()
	return newRestartFixtureFor(t, operations, `"pool-agent"`, `"refPrefixes":[`+refPrefixes+`]`)
}

// newRestartFixtureFor is newRestartFixture with the pools both entries grant
// and the git repository's prefix fields given whole.
func newRestartFixtureFor(t *testing.T, operations, pools, prefixFields string) *restartFixture {
	t.Helper()
	f := &restartFixture{apiFixture: &apiFixture{audit: &adapterAudit{}, minted: map[string]string{}}}
	// Pull requests: 12 the pool's own, 13 from a person's branch, 14 from a
	// fork, 15 unreadable, 16 another pool's. Runs: 21 a push and 22 a pull
	// request from the pool's branch; 23 a push to the default branch (a
	// deploy); 24 a dispatch, 25 a pull request from a fork, 27 a
	// pull_request_target, 28 a workflow_run and 29 a schedule, each naming
	// the pool's branch; 26 unreadable; 30 a push to another pool's branch.
	same, fork := `{"full_name":"example-org/example-repo"}`, `{"full_name":"someone/example-repo"}`
	run := func(event, branch, head string) string {
		return fmt.Sprintf(`{"event":%q,"head_branch":%q,"repository":%s,"head_repository":%s}`, event, branch, same, head)
	}
	reads := map[string]string{
		"/pulls/12":        `{"number":12,"head":{"ref":"cursor/pool-agent/x","repo":` + same + `}}`,
		"/pulls/13":        `{"number":13,"head":{"ref":"person/x","repo":` + same + `}}`,
		"/pulls/14":        `{"number":14,"head":{"ref":"cursor/pool-agent/x","repo":` + fork + `}}`,
		"/pulls/16":        `{"number":16,"head":{"ref":"cursor/pool-other/x","repo":` + same + `}}`,
		"/actions/runs/21": run("push", "cursor/pool-agent/x", same),
		"/actions/runs/22": run("pull_request", "cursor/pool-agent/y", same),
		"/actions/runs/23": run("push", "main", same),
		"/actions/runs/24": run("workflow_dispatch", "cursor/pool-agent/x", same),
		"/actions/runs/25": run("pull_request", "cursor/pool-agent/x", fork),
		"/actions/runs/27": run("pull_request_target", "cursor/pool-agent/x", same),
		"/actions/runs/28": run("workflow_run", "cursor/pool-agent/x", same),
		"/actions/runs/29": run("schedule", "cursor/pool-agent/x", same),
		"/actions/runs/30": run("push", "cursor/pool-other/x", same),
	}
	var seq int
	github := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/app/installations/42/access_tokens" {
			var body struct {
				Repositories []string          `json:"repositories"`
				Permissions  map[string]string `json:"permissions"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			f.mu.Lock()
			seq++
			token := fmt.Sprintf("ghs_syntheticrestarttoken%06d", seq)
			perms, _ := json.Marshal(body.Permissions)
			f.minted[token] = string(perms)
			f.mu.Unlock()
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"token": token, "expires_at": time.Now().Add(time.Hour).Format(time.RFC3339),
				"permissions": body.Permissions, "repositories": []map[string]string{{"full_name": "example-org/" + body.Repositories[0]}}})
			return
		}
		f.mu.Lock()
		scope := f.minted[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
		f.mu.Unlock()
		rest := strings.TrimPrefix(r.URL.Path, restartRepo)
		want := rerunScope
		if strings.HasPrefix(rest, "/pulls/") {
			want = updateScope
		}
		if scope != want {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			f.mu.Lock()
			f.reads++
			f.mu.Unlock()
			if body, ok := reads[rest]; ok {
				_, _ = io.WriteString(w, body)
				return
			}
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		body, _ := io.ReadAll(r.Body)
		line := r.Method + " " + r.URL.Path
		if len(body) > 0 {
			line += " " + r.Header.Get("Content-Type") + " " + string(body)
		}
		f.mu.Lock()
		f.received = append(f.received, line)
		f.mu.Unlock()
		if strings.HasSuffix(rest, "/update-branch") {
			f.mu.Lock()
			answer := f.answer
			f.mu.Unlock()
			if status, text, ok := strings.Cut(answer, " "); ok {
				code, _ := strconv.Atoi(status)
				w.WriteHeader(code)
				_, _ = io.WriteString(w, text)
				return
			}
			w.WriteHeader(http.StatusAccepted)
			_, _ = io.WriteString(w, `{"message":"Updating pull request branch."}`)
			return
		}
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(github.Close)
	_, portText, _ := net.SplitHostPort(strings.TrimPrefix(github.URL, "https://"))
	f.port, _ = strconv.Atoi(portText)
	f.host = "api.example.com"
	catalog, err := httpcatalog.Parse([]byte(fmt.Sprintf(`{"entries":[{"name":"github-api","host":"api.example.com","port":%d,"kind":"github-api",
		"pools":[%s],"git":{"appID":7,"installationID":42,"repos":[{"repo":"example-org/example-repo","access":"write",
		"operations":[%s]}]}},
		{"name":"github","host":"example.com","kind":"git","pools":[%s],"git":{"appID":7,"installationID":42,
		"repos":[{"repo":"example-org/example-repo","access":"write",%s}]}}]}`, f.port, pools, operations, pools, prefixFields)))
	if err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	minter := &githubapp.Minter{Signer: rsaSigner{key}, API: github.URL, Client: github.Client()}
	scope := &brokercore.ProxyScope{VaultID: "vault-1", AgentID: "agent-uuid-1", Pool: "pool-agent", WorkloadID: "pod-uid-1"}
	proxyURL, roots, p := setupProxy(t, validTokenResolver("workload-token", scope), &fakeCredProvider{}, func(o *Options) {
		o.StrictCredentialProxy = true
		o.HeaderAdapter = &HeaderAdapter{Catalog: catalog, Keys: &adapterKeys{}, Audit: f.audit, GitTokens: minter}
	})
	p.upstream.TLSClientConfig.RootCAs = github.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	p.upstream.TLSClientConfig.ServerName = "example.com" // the test server's certificate name
	addr := strings.TrimPrefix(github.URL, "https://")
	p.upstream.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	f.client = newTrustingClient(proxyURL, url.User("workload-token"), roots)
	t.Cleanup(f.client.CloseIdleConnections)
	return f
}

const allRestarts = `"pr.read","pr.update_branch","actions.rerun","actions.rerun_failed"`

func (f *restartFixture) writes() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.received...)
}

// A pull request or run on the pool's own branch is updated or run again, with
// a token holding only the scope the route needs; the audit row names the
// operation and the branch, and GitHub receives the body rebuilt.
func TestCIRestartOnThePoolsBranch(t *testing.T) {
	f := newRestartFixture(t, allRestarts, `"refs/heads/cursor/pool-agent/"`)
	for _, tc := range []struct {
		method, path, body string
		status             int
		operation, branch  string
		want               string
	}{
		{"PUT", "/pulls/12/update-branch", "", 202, "pr.update_branch", "cursor/pool-agent/x", "PUT " + restartRepo + "/pulls/12/update-branch"},
		{"PUT", "/pulls/12/update-branch", `{ "expected_head_sha" : "` + restartCommit + `" }`, 202, "pr.update_branch", "cursor/pool-agent/x",
			"PUT " + restartRepo + `/pulls/12/update-branch application/json {"expected_head_sha":"` + restartCommit + `"}`},
		{"POST", "/actions/runs/21/rerun", "", 201, "actions.rerun", "cursor/pool-agent/x", "POST " + restartRepo + "/actions/runs/21/rerun"},
		{"POST", "/actions/runs/22/rerun-failed-jobs", "{}", 201, "actions.rerun_failed", "cursor/pool-agent/y", "POST " + restartRepo + "/actions/runs/22/rerun-failed-jobs"},
	} {
		before := len(f.writes())
		code, body := f.post(t, tc.method, restartRepo+tc.path, "Bearer "+githubTokenPlaceholder, tc.body)
		e := f.audit.last()
		if code != tc.status || e.Outcome != "completed" || e.Operation != tc.operation || e.Branch != tc.branch || e.Binding != "github-api/example-org/example-repo" {
			t.Errorf("%s %s: %d %s, audit %+v", tc.method, tc.path, code, body, e)
		}
		writes := f.writes()
		if len(writes) != before+1 || writes[len(writes)-1] != tc.want {
			t.Errorf("%s %s: GitHub received %v, want %s", tc.method, tc.path, writes[before:], tc.want)
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	scopes := map[string]bool{}
	for _, s := range f.minted {
		scopes[s] = true
	}
	if len(scopes) != 2 || !scopes[updateScope] || !scopes[rerunScope] {
		t.Errorf("minted scopes %v, want only the branch update and rerun scopes", scopes)
	}
}

// A body need not be labelled JSON (curl -d sends a form Content-Type, a bare
// client none): the broker checks it as JSON, and GitHub receives it rebuilt
// and labelled application/json.
func TestCIRestartSendsTheRebuiltBodyAsJSON(t *testing.T) {
	f := newRestartFixture(t, allRestarts, `"refs/heads/cursor/pool-agent/"`)
	want := "PUT " + restartRepo + `/pulls/12/update-branch application/json {"expected_head_sha":"` + restartCommit + `"}`
	for _, contentType := range []string{"application/x-www-form-urlencoded", ""} {
		r, _ := http.NewRequest("PUT", "https://"+f.host+":"+strconv.Itoa(f.port)+restartRepo+"/pulls/12/update-branch",
			strings.NewReader(`{"expected_head_sha":"`+restartCommit+`"}`))
		if contentType != "" {
			r.Header.Set("Content-Type", contentType)
		}
		before := len(f.writes())
		resp, err := f.client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if writes := f.writes(); resp.StatusCode != http.StatusAccepted || len(writes) != before+1 || writes[len(writes)-1] != want {
			t.Errorf("Content-Type %q: %d, GitHub received %v, want %s", contentType, resp.StatusCode, writes[before:], want)
		}
	}
}

// Anything outside the pool's own branches is refused before GitHub sees a
// write: a person's branch, a fork, a run of the default branch (a deploy), a
// run not started by a push or pull request, and any lookup that fails.
func TestCIRestartRefusesOtherTargets(t *testing.T) {
	f := newRestartFixture(t, allRestarts, `"refs/heads/cursor/pool-agent/"`)
	for _, tc := range []struct {
		name, method, path, body, outcome, branch string
	}{
		{"person's branch", "PUT", "/pulls/13/update-branch", "", "pull_request_target", "person/x"},
		{"fork pull request", "PUT", "/pulls/14/update-branch", "", "pull_request_target", "cursor/pool-agent/x"},
		{"pull request lookup fails", "PUT", "/pulls/15/update-branch", "", "pull_request_target", ""},
		{"deploy run on the default branch", "POST", "/actions/runs/23/rerun", "", "run_target", "main"},
		{"failed jobs of the default branch", "POST", "/actions/runs/23/rerun-failed-jobs", "", "run_target", "main"},
		{"dispatched run", "POST", "/actions/runs/24/rerun", "", "run_target", "cursor/pool-agent/x"},
		{"fork run", "POST", "/actions/runs/25/rerun", "", "run_target", "cursor/pool-agent/x"},
		{"run lookup fails", "POST", "/actions/runs/26/rerun", "", "run_target", ""},
		{"pull_request_target run", "POST", "/actions/runs/27/rerun-failed-jobs", "", "run_target", "cursor/pool-agent/x"},
		{"workflow_run run", "POST", "/actions/runs/28/rerun", "", "run_target", "cursor/pool-agent/x"},
		{"scheduled run", "POST", "/actions/runs/29/rerun-failed-jobs", "", "run_target", "cursor/pool-agent/x"},
		{"debug logging", "POST", "/actions/runs/21/rerun", `{"enable_debug_logging":true}`, "request_shape", ""},
		{"short head", "PUT", "/pulls/12/update-branch", `{"expected_head_sha":"0123abc"}`, "request_shape", ""},
		{"other field", "PUT", "/pulls/12/update-branch", `{"update_method":"rebase"}`, "request_shape", ""},
		{"wrong method", "POST", "/pulls/12/update-branch", "", "method", ""},
		{"rerun one job", "POST", "/actions/jobs/9/rerun", "", "unlisted", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, _ := f.post(t, tc.method, restartRepo+tc.path, "", tc.body)
			if e := f.audit.last(); code < 400 || e.Outcome != tc.outcome || e.Branch != tc.branch {
				t.Fatalf("code=%d outcome=%q branch=%q, want %q %q", code, e.Outcome, e.Branch, tc.outcome, tc.branch)
			}
		})
	}
	if writes := f.writes(); len(writes) != 0 {
		t.Fatalf("GitHub received refused writes: %v", writes)
	}
}

// One git entry serves two pools, each on its own branches: a CI restart
// reads only the requesting pool's push prefixes, so pool-agent restarts its
// own pull request and run and is refused on pool-other's before GitHub sees
// a write.
func TestCIRestartStaysOnThePoolsOwnBranches(t *testing.T) {
	f := newRestartFixtureFor(t, allRestarts, `"pool-agent","pool-other"`,
		`"poolRefPrefixes":{"pool-agent":["refs/heads/cursor/pool-agent/"],"pool-other":["refs/heads/cursor/pool-other/"]}`)
	for _, tc := range []struct {
		method, path, outcome, branch string
	}{
		{"PUT", "/pulls/12/update-branch", "completed", "cursor/pool-agent/x"},
		{"POST", "/actions/runs/21/rerun", "completed", "cursor/pool-agent/x"},
		{"PUT", "/pulls/16/update-branch", "pull_request_target", "cursor/pool-other/x"},
		{"POST", "/actions/runs/30/rerun", "run_target", "cursor/pool-other/x"},
		{"POST", "/actions/runs/30/rerun-failed-jobs", "run_target", "cursor/pool-other/x"},
	} {
		code, _ := f.post(t, tc.method, restartRepo+tc.path, "", "")
		if e := f.audit.last(); (code < 400) != (tc.outcome == "completed") || e.Outcome != tc.outcome || e.Branch != tc.branch {
			t.Errorf("%s %s: code=%d outcome=%q branch=%q, want %q %q", tc.method, tc.path, code, e.Outcome, e.Branch, tc.outcome, tc.branch)
		}
	}
	if writes := f.writes(); len(writes) != 2 {
		t.Fatalf("GitHub received %v, want only the two writes on pool-agent's branch", writes)
	}
}

// The operations are opt-in, and a CI restart needs a git entry that lets the
// pool push to branch prefixes: without either the routes do not exist.
func TestCIRestartNeedsTheOptInAndPushPrefixes(t *testing.T) {
	for name, f := range map[string]*restartFixture{
		"not opted in":        newRestartFixture(t, `"pr.read","actions.read"`, `"refs/heads/cursor/pool-agent/"`),
		"no branch prefixes":  newRestartFixture(t, allRestarts, ``),
		"tag prefixes only":   newRestartFixture(t, allRestarts, `"refs/tags/cursor/"`),
		"every branch (none)": newRestartFixture(t, allRestarts, `"refs/heads/"`),
	} {
		for _, path := range []string{"/pulls/12/update-branch", "/actions/runs/21/rerun", "/actions/runs/22/rerun-failed-jobs"} {
			method := "POST"
			if strings.HasSuffix(path, "update-branch") {
				method = "PUT"
			}
			if code, _ := f.post(t, method, restartRepo+path, "", ""); code != 403 || f.audit.last().Outcome != "unlisted" {
				t.Errorf("%s: %s %s: code=%d outcome=%q", name, method, path, code, f.audit.last().Outcome)
			}
		}
		f.mu.Lock()
		minted, reads := len(f.minted), f.reads
		f.mu.Unlock()
		if minted != 0 || reads != 0 || len(f.writes()) != 0 {
			t.Errorf("%s: an unlisted restart reached GitHub: %d tokens, %d reads", name, minted, reads)
		}
	}
}

// A CI restart relies on the git entry a push would use, so that entry must
// authorize the requester too. Here it is T1 and needs a group: a person
// outside the group cannot run the pool's CI again, a member can.
func TestCIRestartNeedsTheGitEntrysAuthorization(t *testing.T) {
	audit := &adapterAudit{}
	github := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/app/installations/42/access_tokens" {
			var body struct {
				Permissions map[string]string `json:"permissions"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"token": "ghs_syntheticrestarttiertoken1", "expires_at": time.Now().Add(time.Hour).Format(time.RFC3339),
				"permissions": body.Permissions, "repositories": []map[string]string{{"full_name": "example-org/example-repo"}}})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			fmt.Fprint(w, `{"event":"push","head_branch":"cursor/pool-agent/x","repository":{"full_name":"example-org/example-repo"},
				"head_repository":{"full_name":"example-org/example-repo"}}`)
			return
		}
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(github.Close)
	_, portText, _ := net.SplitHostPort(strings.TrimPrefix(github.URL, "https://"))
	port, _ := strconv.Atoi(portText)
	catalog, err := httpcatalog.Parse([]byte(fmt.Sprintf(`{"pools":[
	  {"name":"claude","namespace":"n","serviceAccount":"claude","identity":"claude-session","ccpoolID":"ccpool_abc","ceiling":"T1"}],
	 "entries":[
	  {"name":"github-api","host":"api.example.com","port":%d,"kind":"github-api","pools":["claude"],
	   "git":{"appID":7,"installationID":42,"repos":[{"repo":"example-org/example-repo","access":"write","operations":["actions.rerun"]}]}},
	  {"name":"github","host":"example.com","kind":"git","pools":["claude"],"tier":"T1","requires":["`+authzGroup+`"],
	   "git":{"appID":7,"installationID":42,"repos":[{"repo":"example-org/example-repo","access":"write","refPrefixes":["refs/heads/cursor/pool-agent/"]}]}}]}`, port)))
	if err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	runner := fakeRunner{"alice": {Kind: runnerid.KindPerson, Subject: "sso|alice", Pools: []string{"ccpool_abc"}, TokenSHA256: "aa"},
		"bob": {Kind: runnerid.KindPerson, Subject: "sso|bob", Pools: []string{"ccpool_abc"}, TokenSHA256: "bb"}}
	scope := &brokercore.ProxyScope{VaultID: "vault-1", AgentID: "pool-agent", Pool: "claude", WorkloadID: "pod-uid-1"}
	proxyURL, roots, p := setupProxy(t, validTokenResolver("workload-token", scope), &fakeCredProvider{}, func(o *Options) {
		o.StrictCredentialProxy = true
		o.HeaderAdapter = &HeaderAdapter{Catalog: catalog, Keys: &adapterKeys{}, Audit: audit, Runner: runner,
			Sessions:     &authorizetest.MemBinder{},
			Entitlements: &entitlement.Cache{Source: directory{"sso|alice": {authzGroup}, "sso|bob": {}}},
			GitTokens:    &githubapp.Minter{Signer: rsaSigner{key}, API: github.URL, Client: github.Client()}}
	})
	p.upstream.TLSClientConfig.RootCAs = github.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	p.upstream.TLSClientConfig.ServerName = "example.com" // the test server's certificate name
	addr := strings.TrimPrefix(github.URL, "https://")
	p.upstream.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	rerun := func(session string) int {
		client := newTrustingClient(proxyURL, url.User("workload-token"), roots)
		defer client.CloseIdleConnections()
		client.Transport.(*http.Transport).ProxyConnectHeader = http.Header{SessionHeader: {session}}
		r, _ := http.NewRequest("POST", "https://api.example.com:"+strconv.Itoa(port)+restartRepo+"/actions/runs/21/rerun", nil)
		resp, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.StatusCode
	}
	if code := rerun("bob"); code != http.StatusForbidden || audit.last().Outcome != "not_entitled" || audit.last().Binding != "github" {
		t.Errorf("non-member: %d outcome=%q binding=%q", code, audit.last().Outcome, audit.last().Binding)
	}
	if code := rerun("alice"); code != http.StatusCreated || audit.last().Branch != "cursor/pool-agent/x" {
		t.Errorf("member: %d %+v", code, audit.last())
	}
}

// A 4xx from GitHub leaves its message, and nothing else of the body, on the row.
func TestGitHubErrorMessageIsOnTheRowAtFourHundred(t *testing.T) {
	f := newRestartFixture(t, allRestarts, `"refs/heads/cursor/pool-agent/"`)
	put := func() (int, string) {
		r, _ := http.NewRequest("PUT", "https://"+f.host+":"+strconv.Itoa(f.port)+restartRepo+"/pulls/12/update-branch", nil)
		resp, err := f.client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode, string(body)
	}
	for _, tc := range []struct{ answer, want string }{
		{"", ""},
		{`422 {"message":"There are no new commits on the base branch.","documentation_url":"https://example.com/docs","errors":[{"secret":"x"}]}`, "There are no new commits on the base branch."},
		{`422 {"message":"` + strings.Repeat("a", 300) + `"}`, strings.Repeat("a", 197) + "..."},
		{`422 {"message":"line one\nline two \u00e9"}`, "line one line two ?"},
		{`422 not json`, ""},
		{`500 {"message":"Server Error"}`, ""},
	} {
		f.mu.Lock()
		f.answer = tc.answer
		f.mu.Unlock()
		code, body := put()
		row := f.audit.last()
		if row.UpstreamMessage != tc.want || (tc.answer != "" && strings.SplitN(tc.answer, " ", 2)[1] != body) {
			t.Errorf("%.40q: row message %q, want %q (status %d, body %.40q)", tc.answer, row.UpstreamMessage, tc.want, code, body)
		}
	}
}
