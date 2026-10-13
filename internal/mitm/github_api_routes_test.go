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

	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/githubapp"
	"github.com/Infisical/agent-vault/internal/httpcatalog"
)

// routesFixture fronts a fake api.github.com for a repository that grants
// every optional github-api route. Each route answers only to a token minted
// with exactly the scope it needs, and the fake records what GitHub received.
type routesFixture struct {
	*apiFixture
	received     []string // "METHOD path?query body" for every request after the scope reads
	downloadAuth string
}

func newRoutesFixture(t *testing.T) *routesFixture {
	t.Helper()
	saved := githubDownloadHosts
	githubDownloadHosts = []string{"com"} // the fake serves every host as example.com
	t.Cleanup(func() { githubDownloadHosts = saved })
	f := &routesFixture{apiFixture: &apiFixture{audit: &adapterAudit{}, minted: map[string]string{}}}
	const pr = `{"contents":"read","metadata":"read","pull_requests":"write"}`
	need := map[string]string{
		"pulls": pr, "issues": pr, "graphql": pr, "compare": pr,
		"dispatches":  `{"contents":"write","metadata":"read"}`,
		"actions":     `{"actions":"read","metadata":"read"}`,
		"deployments": `{"deployments":"read","metadata":"read"}`,
		"check-runs":  `{"checks":"read","metadata":"read"}`,
		"commits":     `{"metadata":"read","statuses":"read"}`,
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
			token := fmt.Sprintf("ghs_syntheticroutetoken%06d", seq)
			perms, _ := json.Marshal(body.Permissions)
			f.minted[token] = string(perms)
			f.mu.Unlock()
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"token": token, "expires_at": time.Now().Add(time.Hour).Format(time.RFC3339),
				"permissions": body.Permissions, "repositories": []map[string]string{{"full_name": "example-org/" + body.Repositories[0]}}})
			return
		}
		if r.URL.Path == "/signed/artifact.zip" {
			f.mu.Lock()
			f.downloadAuth = r.Header.Get("Authorization")
			f.mu.Unlock()
			_, _ = io.WriteString(w, "artifact-bytes")
			return
		}
		kind := "graphql"
		if parts := strings.Split(r.URL.Path, "/"); len(parts) >= 5 {
			kind = parts[4]
		}
		if kind == "commits" && strings.HasSuffix(r.URL.Path, "/check-runs") {
			kind = "check-runs"
		}
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		f.mu.Lock()
		scope := f.minted[token]
		f.mu.Unlock()
		if want, ok := need[kind]; !ok || scope != want {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		// Reads the broker makes to check a target: pull requests 12 (the
		// pool's own), 30 (under the repository's pull request prefix) and 13
		// (another pool's); comments 5 (the App's, on 30), 6 (a person's) and 8
		// (another App's).
		switch r.Method + " " + r.URL.Path {
		case "GET /repos/example-org/example-repo/pulls/12":
			fmt.Fprint(w, `{"number":12,"node_id":"PR_twelve","head":{"ref":"cursor/pool-agent/x","repo":{"full_name":"example-org/example-repo"}}}`)
			return
		case "GET /repos/example-org/example-repo/pulls/30":
			fmt.Fprint(w, `{"number":30,"node_id":"PR_thirty","head":{"ref":"factory/fix","repo":{"full_name":"example-org/example-repo"}}}`)
			return
		case "GET /repos/example-org/example-repo/pulls/13":
			fmt.Fprint(w, `{"number":13,"node_id":"PR_thirteen","head":{"ref":"person/x","repo":{"full_name":"example-org/example-repo"}}}`)
			return
		case "GET /repos/example-org/example-repo/issues/comments/5":
			fmt.Fprint(w, `{"id":5,"issue_url":"https://api.github.com/repos/example-org/example-repo/issues/30","performed_via_github_app":{"id":7}}`)
			return
		case "GET /repos/example-org/example-repo/issues/comments/6":
			fmt.Fprint(w, `{"id":6,"issue_url":"https://api.github.com/repos/example-org/example-repo/issues/30","performed_via_github_app":null}`)
			return
		case "GET /repos/example-org/example-repo/issues/comments/8":
			fmt.Fprint(w, `{"id":8,"issue_url":"https://api.github.com/repos/example-org/example-repo/issues/30","performed_via_github_app":{"id":99}}`)
			return
		case "GET /repos/example-org/example-repo/actions/artifacts/9/zip":
			w.Header().Set("Location", "https://example.com/signed/artifact.zip?sig=abc")
			w.WriteHeader(http.StatusFound)
			return
		case "GET /repos/example-org/example-repo/actions/artifacts/10/zip":
			w.Header().Set("Location", "https://elsewhere.test/signed/artifact.zip")
			w.WriteHeader(http.StatusFound)
			return
		}
		line := r.Method + " " + r.URL.Path
		if r.URL.RawQuery != "" {
			line += "?" + r.URL.RawQuery
		}
		if len(body) > 0 {
			line += " " + string(body)
		}
		f.mu.Lock()
		f.received = append(f.received, line)
		f.mu.Unlock()
		fmt.Fprint(w, `{"ok":true}`)
	}))
	t.Cleanup(github.Close)
	_, portText, _ := net.SplitHostPort(strings.TrimPrefix(github.URL, "https://"))
	f.port, _ = strconv.Atoi(portText)
	catalog, err := httpcatalog.Parse([]byte(fmt.Sprintf(`{"entries":[{"name":"github-api","host":"example.com","port":%d,"kind":"github-api",
		"pools":["pool-agent"],"git":{"appID":7,"installationID":42,"repos":[{"repo":"example-org/example-repo","access":"write",
		"operations":["pr.open","pr.read","pr.list","pr.comment","pr.edit","pr.label","pr.ready","dispatch","actions.read","deployments.read"],
		"pullRequestPrefixes":["factory/"],"labels":["preview"],"dispatchEvents":["preview-build"]}]}},
		{"name":"github","host":"git.example.com","kind":"git","pools":["pool-agent"],"git":{"appID":7,"installationID":42,
		"repos":[{"repo":"example-org/example-repo","access":"write","refPrefixes":["refs/heads/cursor/pool-agent/"]}]}}]}`, f.port)))
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
	addr := strings.TrimPrefix(github.URL, "https://")
	p.upstream.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	f.client = newTrustingClient(proxyURL, url.User("workload-token"), roots)
	t.Cleanup(f.client.CloseIdleConnections)
	return f
}

func (f *routesFixture) last() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.received) == 0 {
		return ""
	}
	return f.received[len(f.received)-1]
}

const routeRepo = "/repos/example-org/example-repo"

func TestGitHubAPIRoutesReachGitHubRebuilt(t *testing.T) {
	f := newRoutesFixture(t)
	for _, tc := range []struct {
		method, path, body, want string
	}{
		{"GET", routeRepo + "/pulls?state=open&head=example-org:factory/fix", "", "GET " + routeRepo + "/pulls?head=example-org%3Afactory%2Ffix&state=open"},
		{"GET", routeRepo + "/issues/30/comments?per_page=100", "", "GET " + routeRepo + "/issues/30/comments?per_page=100"},
		{"POST", routeRepo + "/issues/30/comments", `{"body":"verdict"}`, "POST " + routeRepo + `/issues/30/comments {"body":"verdict"}`},
		{"POST", routeRepo + "/issues/30/comments", `{ "body" : "spaced" }`, "POST " + routeRepo + `/issues/30/comments {"body":"spaced"}`},
		{"POST", routeRepo + "/pulls/30/comments", `{"path":"a.go","line":4,"side":"RIGHT","commit_id":"abc","body":"nit"}`,
			"POST " + routeRepo + `/pulls/30/comments {"body":"nit","commit_id":"abc","line":4,"path":"a.go","side":"RIGHT"}`},
		{"POST", routeRepo + "/pulls/30/comments/77/replies", `{ "body":"done" }`, "POST " + routeRepo + `/pulls/30/comments/77/replies {"body":"done"}`},
		{"PATCH", routeRepo + "/pulls/30", `{ "body" : "filled" }`, "PATCH " + routeRepo + `/pulls/30 {"body":"filled"}`},
		{"PATCH", routeRepo + "/issues/comments/5", `{"body":"updated"}`, "PATCH " + routeRepo + `/issues/comments/5 {"body":"updated"}`},
		{"POST", routeRepo + "/issues/30/labels", `{"labels":["preview"]}`, "POST " + routeRepo + `/issues/30/labels {"labels":["preview"]}`},
		{"POST", routeRepo + "/dispatches", `{"event_type":"preview-build","client_payload":{"pr":30}}`, "POST " + routeRepo + `/dispatches {"client_payload":{"pr":30},"event_type":"preview-build"}`},
		{"GET", routeRepo + "/actions/workflows/eval-replay.yml/runs?branch=main&per_page=5", "", "GET " + routeRepo + "/actions/workflows/eval-replay.yml/runs?branch=main&per_page=5"},
		{"GET", routeRepo + "/deployments?environment=preview-30", "", "GET " + routeRepo + "/deployments?environment=preview-30"},
		{"POST", routeRepo + "/pulls/30/ready", "", `POST /graphql {"query":"` + readyMutation + `","variables":{"id":"PR_thirty"}}`},
		{"POST", routeRepo + "/pulls/12/ready", "{}", `POST /graphql {"query":"` + readyMutation + `","variables":{"id":"PR_twelve"}}`},
		// The reads gh run list, view and watch and the eval preview gates make.
		{"GET", routeRepo + "/actions/workflows/preview-k8s.yml", "", "GET " + routeRepo + "/actions/workflows/preview-k8s.yml"},
		{"GET", routeRepo + "/actions/runs/9?exclude_pull_requests=true", "", "GET " + routeRepo + "/actions/runs/9?exclude_pull_requests=true"},
		{"GET", routeRepo + "/check-runs/9/annotations?per_page=100", "", "GET " + routeRepo + "/check-runs/9/annotations?per_page=100"},
		{"GET", routeRepo + "/commits/0123abc/check-runs?filter=latest", "", "GET " + routeRepo + "/commits/0123abc/check-runs?filter=latest"},
		{"GET", routeRepo + "/commits/0123abc/status", "", "GET " + routeRepo + "/commits/0123abc/status"},
		{"GET", routeRepo + "/compare/staging...0123abc", "", "GET " + routeRepo + "/compare/staging...0123abc"},
		{"GET", routeRepo + "/pulls/30/files?per_page=100", "", "GET " + routeRepo + "/pulls/30/files?per_page=100"},
	} {
		code, body := f.post(t, tc.method, tc.path, "Bearer "+githubTokenPlaceholder, tc.body)
		if code != 200 || f.last() != tc.want || f.audit.last().Outcome != "completed" {
			t.Errorf("%s %s: %d %s\n got  %s\n want %s", tc.method, tc.path, code, body, f.last(), tc.want)
		}
	}
	// Each token carried only the scope its route needs (the fake refuses any other).
	f.mu.Lock()
	scopes := map[string]bool{}
	for _, s := range f.minted {
		scopes[s] = true
	}
	f.mu.Unlock()
	if len(scopes) != 6 {
		t.Errorf("minted scopes %v, want six", scopes)
	}
}

func TestGitHubAPIDownloadsFollowOnlyGitHubsRedirect(t *testing.T) {
	f := newRoutesFixture(t)
	code, body := f.post(t, "GET", routeRepo+"/actions/artifacts/9/zip", "", "")
	f.mu.Lock()
	auth := f.downloadAuth
	f.mu.Unlock()
	if code != 200 || body != "artifact-bytes" || auth != "" {
		t.Fatalf("download: %d %q, Authorization sent to the download host: %q", code, body, auth)
	}
	if code, _ := f.post(t, "GET", routeRepo+"/actions/artifacts/10/zip", "", ""); code != 502 || f.audit.last().Outcome != "download_refused" {
		t.Fatalf("redirect off the download hosts: %d %q", code, f.audit.last().Outcome)
	}
}

// Writes to an existing pull request reach only the pool's own and those under
// the repository's pull request prefixes; a comment edit only the App's own.
func TestGitHubAPIRoutesRefuseOtherTargets(t *testing.T) {
	f := newRoutesFixture(t)
	for _, tc := range []struct {
		method, path, body, outcome string
	}{
		{"POST", routeRepo + "/issues/13/comments", `{"body":"x"}`, "comment_target"},
		{"PATCH", routeRepo + "/pulls/13", `{"body":"x"}`, "pull_request_target"},
		{"POST", routeRepo + "/pulls/13/ready", "", "pull_request_target"},
		{"POST", routeRepo + "/issues/13/labels", `{"labels":["preview"]}`, "pull_request_target"},
		{"PATCH", routeRepo + "/issues/comments/6", `{"body":"x"}`, "comment_target"},
		{"PATCH", routeRepo + "/issues/comments/8", `{"body":"x"}`, "comment_target"},
		{"POST", routeRepo + "/issues/30/labels", `{"labels":["deploy-prod"]}`, "request_shape"},
		{"POST", routeRepo + "/issues/30/labels", `{"labels":[]}`, "request_shape"},
		{"POST", routeRepo + "/issues/30/labels", `["preview"]`, "request_shape"},
		{"POST", routeRepo + "/dispatches", `{"event_type":"deploy"}`, "request_shape"},
		{"POST", routeRepo + "/dispatches", `{"event_type":"preview-build","client_payload":"x"}`, "request_shape"},
		{"PATCH", routeRepo + "/pulls/30", `{"body":"x","state":"closed"}`, "request_shape"},
		{"POST", routeRepo + "/issues/30/comments", `{"body":"x","path":"a.go"}`, "request_shape"},
		{"POST", routeRepo + "/issues/30/comments", `{"body":"x","body":"y"}`, "request_shape"},
		{"POST", routeRepo + "/pulls/30/comments", `{"body":"x","in_reply_to":5}`, "request_shape"},
		{"POST", routeRepo + "/pulls/30/comments", `{"body":"x","line":1.5}`, "request_shape"},
		{"POST", routeRepo + "/pulls/30/comments", `{"body":"x","side":"UP"}`, "request_shape"},
		{"POST", routeRepo + "/pulls/30/comments", `{"path":"a.go","line":4}`, "request_shape"},
		{"POST", routeRepo + "/pulls/30/comments/77/replies", `{"body":"x","commit_id":"abc"}`, "request_shape"},
		{"PATCH", routeRepo + "/pulls/30", `{"title":"x"}`, "request_shape"},
		{"POST", routeRepo + "/pulls/30/ready", `{"draft":true}`, "request_shape"},
		{"POST", routeRepo + "/pulls", `{"head":"factory/fix","base":"main"}`, "head"},
		{"GET", routeRepo + "/actions/runs/9/logs?x=1", "", "unlisted"},
		{"POST", routeRepo + "/actions/runs/9/rerun", "", "unlisted"},
		{"GET", "/repos/example-org/example-repo/actions/secrets", "", "unlisted"},
		{"GET", routeRepo + "/commits/main/status", "", "unlisted"},
		{"GET", routeRepo + "/compare/staging..main", "", "unlisted"},
		{"POST", routeRepo + "/statuses/0123abc", `{"state":"success"}`, "unlisted"},
		{"GET", routeRepo + "/actions/runs/9?exclude_pull_requests=true&x=1", "", "unlisted"},
	} {
		if code, _ := f.post(t, tc.method, tc.path, "", tc.body); code < 400 || f.audit.last().Outcome != tc.outcome {
			t.Errorf("%s %s %s: code=%d outcome=%q, want %q", tc.method, tc.path, tc.body, code, f.audit.last().Outcome, tc.outcome)
		}
	}
	f.mu.Lock()
	received := f.received
	f.mu.Unlock()
	if len(received) != 0 {
		t.Fatalf("GitHub received refused requests: %v", received)
	}
}
