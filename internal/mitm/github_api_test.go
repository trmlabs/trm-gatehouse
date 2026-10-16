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
	"sync"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/decoy"
	"github.com/Infisical/agent-vault/internal/githubapp"
	"github.com/Infisical/agent-vault/internal/httpcatalog"
)

// apiFixture fronts a fake api.github.com: it mints tokens and accepts a pull
// request or comment only with a token minted for that repository with
// contents read and pull_requests write, as GitHub needs to open one.
type apiFixture struct {
	client  *http.Client
	host    string // the API host; example.com when unset
	port    int
	audit   *adapterAudit
	mu      sync.Mutex
	minted  map[string]string // token -> "repo|permissions"
	created int
	reads   int
	echo    bool
	last    string // the last body GitHub received
	decoys  *decoy.Source
}

func newAPIFixture(t *testing.T) *apiFixture {
	t.Helper()
	return newAPIFixtureFor(t, `["pool-agent"]`, `"refPrefixes":["refs/heads/cursor/pool-agent/"]`)
}

// newAPIFixtureFor serves the broker's pool, pool-agent, from github-api and
// git entries granting pools, the git entry's repository carrying push.
func newAPIFixtureFor(t *testing.T, pools, push string) *apiFixture {
	t.Helper()
	f := &apiFixture{audit: &adapterAudit{}, minted: map[string]string{}, decoys: decoy.NewSource(nil)}
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
			token := fmt.Sprintf("ghs_syntheticapitoken%06d", seq)
			perms, _ := json.Marshal(body.Permissions)
			f.minted[token] = "example-org/" + body.Repositories[0] + "|" + string(perms)
			f.mu.Unlock()
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"token": token, "expires_at": time.Now().Add(time.Hour).Format(time.RFC3339),
				"permissions": body.Permissions, "repositories": []map[string]string{{"full_name": "example-org/" + body.Repositories[0]}}})
			return
		}
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		f.mu.Lock()
		scope := f.minted[token]
		f.mu.Unlock()
		if scope != `example-org/example-app|{"contents":"read","metadata":"read","pull_requests":"write"}` {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		if r.Method != http.MethodGet {
			f.last = string(body)
			f.created++ // writes only; reads are counted below
		}
		echo := f.echo
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			f.mu.Lock()
			f.reads++
			f.mu.Unlock()
			// 12 is the pool's own pull request; 13 comes from another pool's branch,
			// 14 from a fork; 20 is an issue, not a pull request.
			switch r.URL.Path {
			case "/repos/example-org/example-app/pulls/12":
				fmt.Fprintf(w, `{"number":12,"state":"open","received":%d,"head":{"ref":"cursor/pool-agent/x","repo":{"full_name":"example-org/example-app"}}}`, len(body))
			case "/repos/example-org/example-app/pulls/13":
				fmt.Fprint(w, `{"number":13,"head":{"ref":"cursor/other-pool/x","repo":{"full_name":"example-org/example-app"}}}`)
			case "/repos/example-org/example-app/pulls/14":
				fmt.Fprint(w, `{"number":14,"head":{"ref":"cursor/pool-agent/x","repo":{"full_name":"someone/example-app"}}}`)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
			return
		}
		w.WriteHeader(http.StatusCreated)
		if echo {
			fmt.Fprintf(w, `{"debug":%q}`, token) // #nosec G705 -- fake API echoing a synthetic token as JSON
			return
		}
		fmt.Fprintf(w, `{"number":12,"received":%d}`, len(body))
	}))
	t.Cleanup(github.Close)
	_, portText, _ := net.SplitHostPort(strings.TrimPrefix(github.URL, "https://"))
	f.port, _ = strconv.Atoi(portText)
	// The pool pushes only under cursor/pool-agent/, so it opens pull requests only from there.
	catalog, err := httpcatalog.Parse([]byte(fmt.Sprintf(`{"entries":[{"name":"github-api","host":"example.com","port":%d,"kind":"github-api",
		"pools":%[2]s,"git":{"appID":7,"installationID":42,"repos":[{"repo":"example-org/example-app","access":"write"}]}},
		{"name":"github","host":"git.example.com","kind":"git","pools":%[2]s,"git":{"appID":7,"installationID":42,
		"repos":[{"repo":"example-org/example-app","access":"write",%[3]s}]}}]}`, f.port, pools, push)))
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
		o.HeaderAdapter = &HeaderAdapter{Catalog: catalog, Keys: &adapterKeys{}, Audit: f.audit, GitTokens: minter, Decoys: f.decoys}
	})
	p.upstream.TLSClientConfig.RootCAs = github.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	addr := strings.TrimPrefix(github.URL, "https://")
	p.upstream.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	f.client = newTrustingClient(proxyURL, url.User("workload-token"), roots)
	t.Cleanup(f.client.CloseIdleConnections)
	return f
}

func (f *apiFixture) post(t *testing.T, method, path, auth, body string) (int, string) {
	t.Helper()
	host := f.host
	if host == "" {
		host = "example.com"
	}
	r, _ := http.NewRequest(method, "https://"+host+":"+strconv.Itoa(f.port)+path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/vnd.github+json")
	if auth != "" {
		r.Header.Set("Authorization", auth)
	}
	resp, err := f.client.Do(r)
	if err != nil {
		return 0, err.Error()
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(data), "ghs_") {
		t.Fatal("token reached the worker")
	}
	return resp.StatusCode, string(data)
}

func TestGitHubAPIOpensPullRequestsAndComments(t *testing.T) {
	f := newAPIFixture(t)
	for _, tc := range []struct{ path, auth, body string }{
		{"/repos/example-org/example-app/pulls", "token " + githubTokenPlaceholder, `{"title":"agent change","head":"cursor/pool-agent/x","base":"main"}`}, // gh sends "token"
		{"/repos/example-org/example-app/issues/12/comments", "Bearer " + githubTokenPlaceholder, `{"body":"note"}`},
		{"/repos/example-org/example-app/pulls/12/comments", "", `{"body":"note","commit_id":"abc","path":"a.go","line":1}`},
		{"/repos/example-org/example-app/pulls/12/comments/99/replies", "", `{"body":"note"}`},
	} {
		if code, body := f.post(t, "POST", tc.path, tc.auth, tc.body); code != 201 || !strings.Contains(body, `"number":12`) {
			t.Fatalf("%s: %d %s", tc.path, code, body)
		}
	}
	f.mu.Lock()
	for _, scope := range f.minted {
		if !strings.HasSuffix(scope, `{"contents":"read","metadata":"read","pull_requests":"write"}`) {
			t.Errorf("minted %s, want contents read and pull_requests write only", scope)
		}
	}
	f.mu.Unlock()
	if e := f.audit.last(); e.Binding != "github-api/example-org/example-app" || e.Outcome != "completed" || e.Status != 201 || e.Operation != "pr.comment" {
		t.Fatalf("audit: %+v", e)
	}
	// GitHub receives the request rebuilt from the checked fields, not the worker's bytes.
	if code, _ := f.post(t, "POST", "/repos/example-org/example-app/pulls", "", "{ \"head\" : \"cursor/pool-agent/y\", \"base\":\"main\", \"draft\":true, \"title\":\"t\", \"body\":\"b\" }"); code != 201 {
		t.Fatalf("create: %d", code)
	}
	f.mu.Lock()
	last := f.last
	f.mu.Unlock()
	if last != `{"base":"main","body":"b","draft":true,"head":"cursor/pool-agent/y","title":"t"}` {
		t.Fatalf("GitHub received %s", last)
	}
	// Reading one pull request, for its state, is a GET with no body.
	f.mu.Lock()
	before := f.reads
	f.mu.Unlock()
	r, _ := http.NewRequest(http.MethodGet, "https://example.com:"+strconv.Itoa(f.port)+"/repos/example-org/example-app/pulls/12", nil)
	resp, err := f.client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	f.mu.Lock()
	reads := f.reads - before
	f.mu.Unlock()
	if resp.StatusCode != 200 || !strings.Contains(string(data), `"state":"open"`) || reads != 1 {
		t.Fatalf("read: %d %s, reads=%d", resp.StatusCode, data, reads)
	}
}

// A comment goes only to the pool's own pull request: never to another pool's,
// a fork's, or an issue (people's work).
func TestGitHubAPICommentsOnlyOnThePoolsPullRequests(t *testing.T) {
	f := newAPIFixture(t)
	for _, path := range []string{
		"/repos/example-org/example-app/issues/13/comments",
		"/repos/example-org/example-app/pulls/14/comments",
		"/repos/example-org/example-app/issues/20/comments",
		"/repos/example-org/example-app/pulls/13/comments/99/replies",
	} {
		if code, _ := f.post(t, "POST", path, "", `{"body":"note"}`); code != 403 || f.audit.last().Outcome != "comment_target" {
			t.Fatalf("%s: code=%d outcome=%q", path, code, f.audit.last().Outcome)
		}
	}
	f.mu.Lock()
	created := f.created
	f.mu.Unlock()
	if created != 0 {
		t.Fatalf("GitHub received %d refused comments", created)
	}
	if code, _ := f.post(t, "POST", "/repos/example-org/example-app/issues/12/comments", "", `{"body":"note"}`); code != 201 {
		t.Fatalf("comment on the pool's own pull request: %d", code)
	}
}

// With one entry serving two pools, each on its own prefixes, the broker's
// pool opens and comments only from and on its own branches: another pool's
// pull request (13, from cursor/other-pool/) is out of reach.
func TestGitHubAPIStaysOnThePoolsOwnPrefixes(t *testing.T) {
	f := newAPIFixtureFor(t, `["pool-agent","other-pool"]`,
		`"poolRefPrefixes":{"pool-agent":["refs/heads/cursor/pool-agent/"],"other-pool":["refs/heads/cursor/other-pool/"]}`)
	if code, _ := f.post(t, "POST", "/repos/example-org/example-app/pulls", "", `{"head":"cursor/other-pool/x","base":"main"}`); code != 403 || f.audit.last().Outcome != "head" {
		t.Fatalf("open from another pool's branch: %d %+v", code, f.audit.last())
	}
	if code, _ := f.post(t, "POST", "/repos/example-org/example-app/issues/13/comments", "", `{"body":"note"}`); code != 403 || f.audit.last().Outcome != "comment_target" {
		t.Fatalf("comment on another pool's pull request: %d %+v", code, f.audit.last())
	}
	f.mu.Lock()
	created := f.created
	f.mu.Unlock()
	if created != 0 {
		t.Fatalf("GitHub received %d refused writes", created)
	}
	if code, _ := f.post(t, "POST", "/repos/example-org/example-app/pulls", "", `{"head":"cursor/pool-agent/x","base":"main"}`); code != 201 {
		t.Fatalf("open from the pool's own branch: %d", code)
	}
	if code, _ := f.post(t, "POST", "/repos/example-org/example-app/issues/12/comments", "", `{"body":"note"}`); code != 201 {
		t.Fatalf("comment on the pool's own pull request: %d", code)
	}
}

func TestGitHubAPIRefusesEverythingElse(t *testing.T) {
	f := newAPIFixture(t)
	for _, tc := range []struct {
		name, method, path, auth, body, outcome string
	}{
		{"approve a review", "POST", "/repos/example-org/example-app/pulls/12/reviews", "", `{"event":"APPROVE"}`, "unlisted"},
		{"merge", "PUT", "/repos/example-org/example-app/pulls/12/merge", "", `{}`, "unlisted"},
		{"another repository", "POST", "/repos/example-org/other/pulls", "", `{}`, "unlisted"},
		// The default operations: no list, edit, label, ready, dispatch, Actions or deployments.
		{"list pull requests", "GET", "/repos/example-org/example-app/pulls", "", "", "method"},
		{"update a pull request", "PATCH", "/repos/example-org/example-app/pulls/12", "", `{"body":"b"}`, "method"},
		{"delete a pull request", "DELETE", "/repos/example-org/example-app/pulls/12", "", "", "method"},
		{"mark ready", "POST", "/repos/example-org/example-app/pulls/12/ready", "", "", "unlisted"},
		{"edit a comment", "PATCH", "/repos/example-org/example-app/issues/comments/5", "", `{"body":"b"}`, "unlisted"},
		{"labels without a grant", "POST", "/repos/example-org/example-app/issues/12/labels", "", `{"labels":["x"]}`, "unlisted"},
		{"dispatch without a grant", "POST", "/repos/example-org/example-app/dispatches", "", `{"event_type":"x"}`, "unlisted"},
		{"actions without a grant", "GET", "/repos/example-org/example-app/actions/runs", "", "", "unlisted"},
		{"deployments without a grant", "GET", "/repos/example-org/example-app/deployments", "", "", "unlisted"},
		{"run a workflow", "POST", "/repos/example-org/example-app/actions/workflows/ci.yml/dispatches", "", `{"ref":"main"}`, "unlisted"},
		{"read with a body", "GET", "/repos/example-org/example-app/pulls/12", "", `{"x":1}`, "request_shape"},
		{"head outside the pool", "POST", "/repos/example-org/example-app/pulls", "", `{"head":"cursor/other/x","base":"main"}`, "head"},
		{"head is the prefix itself", "POST", "/repos/example-org/example-app/pulls", "", `{"head":"cursor/pool-agent/","base":"main"}`, "head"},
		{"head from a fork", "POST", "/repos/example-org/example-app/pulls", "", `{"head":"someone:cursor/pool-agent/x","base":"main"}`, "head"},
		{"head escapes the prefix", "POST", "/repos/example-org/example-app/pulls", "", `{"head":"cursor/pool-agent/../main","base":"main"}`, "head"},
		{"head from another repository", "POST", "/repos/example-org/example-app/pulls", "", `{"head":"cursor/pool-agent/x","head_repo":"example-org/other","base":"main"}`, "head"},
		{"pull request from an issue", "POST", "/repos/example-org/example-app/pulls", "", `{"issue":7,"head":"cursor/pool-agent/x","base":"main"}`, "head"},
		{"no head", "POST", "/repos/example-org/example-app/pulls", "", `{"base":"main"}`, "head"},
		{"duplicate head", "POST", "/repos/example-org/example-app/pulls", "", `{"head":"cursor/pool-agent/x","head":"main","base":"main"}`, "head"},
		{"case-variant head", "POST", "/repos/example-org/example-app/pulls", "", `{"head":"cursor/pool-agent/x","Head":"main","base":"main"}`, "head"},
		{"unknown field", "POST", "/repos/example-org/example-app/pulls", "", `{"head":"cursor/pool-agent/x","base":"main","maintainer_can_modify":true}`, "head"},
		{"null head", "POST", "/repos/example-org/example-app/pulls", "", `{"head":null,"base":"main"}`, "head"},
		{"head not a string", "POST", "/repos/example-org/example-app/pulls", "", `{"head":["cursor/pool-agent/x"],"base":"main"}`, "head"},
		{"trailing data", "POST", "/repos/example-org/example-app/pulls", "", `{"head":"cursor/pool-agent/x","base":"main"}{"head":"main"}`, "head"},
		{"worker token", "POST", "/repos/example-org/example-app/pulls", "token ghp_workersupplied", `{}`, "credential_header"},
		{"placeholder in body", "POST", "/repos/example-org/example-app/pulls", "", `{"body":"__vault_GITHUB_TOKEN__"}`, "placeholder_misplaced"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if code, _ := f.post(t, tc.method, tc.path, tc.auth, tc.body); code < 400 || f.audit.last().Outcome != tc.outcome {
				t.Fatalf("code=%d outcome=%q", code, f.audit.last().Outcome)
			}
			// A refusal past route matching names its operation; an unlisted
			// path has none, and the row never carries the path.
			want := ""
			switch tc.outcome {
			case "unlisted", "method":
			case "request_shape":
				want = "pr.read"
			default:
				want = "pr.open"
			}
			if got := f.audit.last().Operation; got != want {
				t.Fatalf("operation=%q, want %q", got, want)
			}
		})
	}
	f.mu.Lock()
	created := f.created
	f.mu.Unlock()
	if created != 0 {
		t.Fatalf("GitHub received %d refused requests", created)
	}
	f.mu.Lock()
	f.echo = true
	f.mu.Unlock()
	if code, _ := f.post(t, "POST", "/repos/example-org/example-app/pulls", "", `{"head":"cursor/pool-agent/x","base":"main"}`); code == 201 || f.audit.last().Outcome != "secret_echo" {
		t.Fatalf("token echo not blocked: %d %+v", code, f.audit.last())
	}
}

// A GitHub GraphQL request no route admits is refused before GitHub sees it,
// and a refusal that names an operation names "graphql", so those refusals can
// be counted apart from other unlisted paths. Which handler refuses it, and so
// whether the row carries the operation, is left to the GraphQL handler.
func TestGitHubAPIGraphQLRefusalNamesItsOperation(t *testing.T) {
	f := newAPIFixture(t)
	if code, _ := f.post(t, "POST", "/graphql", "", `{"query":"{ viewer { login } }"}`); code < 400 {
		t.Fatalf("GraphQL was not refused: %d", code)
	}
	e := f.audit.last()
	if e.Event != "denied" || e.Status < 400 || (e.Operation != "" && e.Operation != "graphql") {
		t.Fatalf("audit: %+v", e)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.last != "" || len(f.minted) != 0 {
		t.Fatalf("a refused GraphQL request reached GitHub: minted %v, body %q", f.minted, f.last)
	}
}

// An unmatched GitHub GraphQL path is named "graphql"; a matched route keeps
// its own operation, and any other unmatched path names none.
func TestGitHubAPIOperationNamesGraphQL(t *testing.T) {
	for path, want := range map[string]string{"/graphql": "graphql", "/api/graphql": "graphql", "/repos/o/r/pulls": ""} {
		if got := githubAPIOperation(httpcatalog.GitRequest{}, path); got != want {
			t.Errorf("%s: operation %q, want %q", path, got, want)
		}
	}
	if got := githubAPIOperation(httpcatalog.GitRequest{Operation: "pr.comment"}, "/graphql"); got != "pr.comment" {
		t.Errorf("a matched route's operation became %q", got)
	}
}
