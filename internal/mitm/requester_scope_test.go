package mitm

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
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
	"github.com/Infisical/agent-vault/internal/authorize/authorizetest"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/entitlement"
	"github.com/Infisical/agent-vault/internal/githubapp"
	"github.com/Infisical/agent-vault/internal/httpcatalog"
	"github.com/Infisical/agent-vault/internal/runnerid"
)

// requesterRunner verifies the runner sessions of two people on one pool.
var requesterRunner = fakeRunner{
	"alice": {Kind: runnerid.KindPerson, Subject: "alice@example.com", Pools: []string{"ccpool_abc"}, TokenSHA256: "aa"},
	"bob":   {Kind: runnerid.KindPerson, Subject: "bob@example.com", Pools: []string{"ccpool_abc"}, TokenSHA256: "bb"},
	"agent": {Kind: runnerid.KindAgent, Subject: "agent:helper", Pools: []string{"ccpool_abc"}, TokenSHA256: "cc"},
}

// requesterPool is pool-agent as a person pool: a runner session names who
// stands behind each request.
const requesterPool = `"pools":[{"name":"pool-agent","namespace":"n","serviceAccount":"agent","identity":"claude-session","ccpoolID":"ccpool_abc"}],`

// sessionShim stands in for the in-Pod sidecar: a proxy in front of the
// broker that adds a runner session to each CONNECT, so stock git, which
// cannot set CONNECT headers itself, runs as that person. It returns the
// proxy URL git uses, with the broker's own proxy credential.
func sessionShim(t *testing.T, broker, session string) string {
	t.Helper()
	upstream, err := url.Parse(broker)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			client, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = client.Close() }()
				reader := bufio.NewReader(client)
				req, err := http.ReadRequest(reader)
				if err != nil || req.Method != http.MethodConnect {
					return
				}
				server, err := net.Dial("tcp", upstream.Host)
				if err != nil {
					return
				}
				defer func() { _ = server.Close() }()
				var head strings.Builder
				fmt.Fprintf(&head, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", req.RequestURI, req.Host)
				for name, values := range req.Header {
					for _, v := range values {
						fmt.Fprintf(&head, "%s: %s\r\n", name, v)
					}
				}
				if session != "" {
					fmt.Fprintf(&head, "%s: %s\r\n", SessionHeader, session)
				}
				head.WriteString("\r\n")
				if _, err := io.WriteString(server, head.String()); err != nil {
					return
				}
				done := make(chan struct{}, 2)
				go func() { _, _ = io.Copy(server, reader); done <- struct{}{} }()
				go func() { _, _ = io.Copy(client, server); done <- struct{}{} }()
				<-done
			}()
		}
	}()
	shim := *upstream
	shim.Host = ln.Addr().String()
	return shim.String()
}

// as runs git through the broker as the person whose session it carries.
func (f *gitFixture) as(t *testing.T, session, dir string, args ...string) (string, error) {
	t.Helper()
	full := append([]string{"-c", "http.proxy=" + sessionShim(t, f.proxyURL, session), "-c", "http.proxyAuthMethod=basic", "-c", "http.sslCAInfo=" + f.caFile,
		"-c", "credential.helper=", "-c", "protocol.version=2"}, args...)
	return runGit(t, dir, f.env(), full...)
}

func newRequesterGitFixture(t *testing.T, prefixes string) *gitFixture {
	t.Helper()
	return newGitFixtureCatalog(t, func(port int) string {
		return fmt.Sprintf(`{%s"entries":[{"name":"github","host":"example.com","port":%d,"kind":"git","pools":["pool-agent"],
		"git":{"appID":7,"installationID":42,"repos":[
			{"repo":"example-org/example-app","access":"write",%s},
			{"repo":"example-org/docs","access":"read"}]}}]}`, requesterPool, port, prefixes)
	}, func(a *HeaderAdapter) {
		a.Runner, a.Sessions = requesterRunner, &authorizetest.MemBinder{}
	})
}

// Two people share one pool whose push prefix is cursor/pool-agent/{requester}/.
// Each pushes only under their own segment: a push, force push or delete of
// the other's branch is refused before GitHub receives it, with git's own
// report naming where to push, and the audit row names the requester and the
// ref. A run that names no person may clone but never push.
func TestGitPushesStayOnTheRequestersOwnBranches(t *testing.T) {
	f := newRequesterGitFixture(t, `"poolRefPrefixes":{"pool-agent":["refs/heads/cursor/pool-agent/{requester}/"]}`)
	const alices, bobs = "refs/heads/cursor/pool-agent/alice@example.com/", "refs/heads/cursor/pool-agent/bob@example.com/"
	clone := func(session string) string {
		dir := filepath.Join(f.work, session)
		if out, err := f.as(t, session, f.work, "clone", f.remote("example-org/example-app"), dir); err != nil {
			t.Fatalf("%s clone: %s", session, out)
		}
		if out, err := f.as(t, session, dir, "commit", "--allow-empty", "-m", session+"'s change"); err != nil {
			t.Fatal(out)
		}
		return dir
	}
	alice, bob := clone("alice"), clone("bob")
	if out, err := f.as(t, "alice", alice, "push", "origin", "HEAD:"+alices+"fix"); err != nil {
		t.Fatalf("alice's own branch: %s", out)
	}
	if row := f.audit.last(); row.Requester != "alice@example.com" || row.Branch != alices+"fix" || row.Operation != "git.push" {
		t.Fatalf("alice's push row: %+v", row)
	}
	pushed := f.bareRef(t, "example-org/example-app", alices+"fix")
	f.mu.Lock()
	packsBefore := f.receivePacks
	f.mu.Unlock()
	for name, refspec := range map[string]string{
		"push to alice's branch":       "HEAD:" + alices + "other",
		"force push to alice's branch": "+HEAD:" + alices + "fix",
		"delete of alice's branch":     ":" + alices + "fix",
		"the pool's prefix itself":     "HEAD:refs/heads/cursor/pool-agent/fix",
		"a branch Cursor would name":   "HEAD:refs/heads/cursor/fix-a1b2",
	} {
		out, err := f.as(t, "bob", bob, "push", "origin", refspec)
		row := f.audit.last()
		if err == nil || row.Outcome != "ref_outside_binding" || row.Requester != "bob@example.com" || row.Branch == "" || !strings.Contains(refspec, row.Branch) {
			t.Fatalf("%s: %s %+v", name, out, row)
		}
		// git's own report says why, and where bob may push instead.
		if !strings.Contains(out, "[remote rejected]") || !strings.Contains(out, "cursor/pool-agent/bob@example.com/") {
			t.Errorf("%s: git showed no reason or prefix:\n%s", name, out)
		}
	}
	f.mu.Lock()
	reached := f.receivePacks - packsBefore
	f.mu.Unlock()
	if reached != 0 || f.bareRef(t, "example-org/example-app", alices+"fix") != pushed || f.bareRef(t, "example-org/example-app", alices+"other") != "" {
		t.Fatalf("bob's pushes reached GitHub %d times, or alice's branch changed", reached)
	}
	// Following the report: a local branch named under his prefix, pushed
	// with -u, after which plain git push works.
	own := strings.TrimPrefix(bobs, "refs/heads/") + "topic"
	for _, args := range [][]string{{"switch", "-c", own}, {"push", "-u", "origin", "HEAD"}, {"commit", "--allow-empty", "-m", "more"}, {"push"}} {
		if out, err := f.as(t, "bob", bob, args...); err != nil {
			t.Fatalf("bob %v: %s", args, out)
		}
	}
	if row := f.audit.last(); row.Branch != bobs+"topic" || row.Requester != "bob@example.com" {
		t.Fatalf("bob's plain push row: %+v", row)
	}
	// Bob's own branch, and its delete, go through; so does a push of several
	// refs that are all his, whose row names each one.
	for _, refspec := range []string{"HEAD:" + bobs + "fix", ":" + bobs + "fix"} {
		if out, err := f.as(t, "bob", bob, "push", "origin", refspec); err != nil {
			t.Fatalf("bob's own %s: %s", refspec, out)
		}
	}
	if out, err := f.as(t, "bob", bob, "push", "origin", "HEAD:"+bobs+"a", "HEAD:"+bobs+"b"); err != nil {
		t.Fatalf("bob's two branches: %s", out)
	}
	if row := f.audit.last(); row.Branch != bobs+"a,"+bobs+"b" && row.Branch != bobs+"b,"+bobs+"a" {
		t.Fatalf("two-ref push row: %+v", row)
	}
	// A run with no person behind it has no branch of its own here.
	for _, session := range []string{"", "agent"} {
		dir := filepath.Join(f.work, "none-"+session)
		if out, err := f.as(t, session, f.work, "clone", f.remote("example-org/example-app"), dir); err != nil {
			t.Fatalf("%q clone: %s", session, out)
		}
		if out, err := f.as(t, session, dir, "push", "origin", "HEAD:refs/heads/cursor/pool-agent/x"); err == nil || f.audit.last().Outcome != "no_branch_prefix" {
			t.Fatalf("%q push: %s %+v", session, out, f.audit.last())
		}
	}
}

// A prefix without {requester} is shared on purpose: every person on the pool
// pushes there, beside their own branches.
func TestGitSharedPrefixStaysShared(t *testing.T) {
	f := newRequesterGitFixture(t, `"poolRefPrefixes":{"pool-agent":["refs/heads/cursor/pool-agent/{requester}/","refs/heads/factory/"]}`)
	for _, session := range []string{"alice", "bob"} {
		dir := filepath.Join(f.work, session)
		if out, err := f.as(t, session, f.work, "clone", f.remote("example-org/example-app"), dir); err != nil {
			t.Fatal(out)
		}
		_, _ = f.as(t, session, dir, "commit", "--allow-empty", "-m", session)
		if out, err := f.as(t, session, dir, "push", "--force", "origin", "HEAD:refs/heads/factory/shared"); err != nil {
			t.Fatalf("%s to the shared prefix: %s", session, out)
		}
	}
}

func TestRefsField(t *testing.T) {
	long := "refs/heads/" + strings.Repeat("x", 240)
	for _, tc := range []struct {
		refs []string
		want string
	}{
		{[]string{"refs/heads/a"}, "refs/heads/a"},
		{[]string{"refs/heads/a", "refs/tags/b"}, "refs/heads/a,refs/tags/b"},
		{[]string{long}, long},
		{[]string{long, "refs/heads/a"}, long + ",+1"},
		{[]string{"refs/heads/a", long, "refs/heads/b"}, "refs/heads/a,+2"},
		{[]string{"refs/heads/\"\"", "refs/heads/a"}, "invalid,+1"},
		{[]string{long + strings.Repeat("y", 20)}, "invalid"},
	} {
		got := refsField(tc.refs)
		if got != tc.want || auditchain.BranchField(got) != got {
			t.Errorf("%v: %q, want %q", tc.refs, got, tc.want)
		}
	}
}

// The refusal is git's own report on the side band git asked for, or bare
// when it asked for none.
func TestReceivePackRefusalFormat(t *testing.T) {
	refs := []string{"refs/heads/main", "refs/heads/cursor/p/alice@example.com/x"}
	prefixes := []string{"refs/heads/cursor/p/alice@example.com/", "refs/tags/x/"}
	bare := string(receivePackRefusal([]string{"report-status"}, refs, prefixes))
	want := pktLine("unpack ok\n") + pktLine("ng refs/heads/main outside the branches this run may push to; push to a branch under cursor/p/alice@example.com/\n") +
		pktLine("ng refs/heads/cursor/p/alice@example.com/x not pushed: another ref in this push is outside the branches this run may push to\n") + "0000"
	if bare != want {
		t.Fatalf("bare report:\n%q\nwant\n%q", bare, want)
	}
	banded := string(receivePackRefusal([]string{"report-status-v2", "side-band-64k"}, refs, prefixes))
	message := "Gatehouse refused this push: it changes a ref outside the branches this run may push to.\n" +
		"Push to a branch under cursor/p/alice@example.com/, for example: git switch -c cursor/p/alice@example.com/<topic> && git push -u origin HEAD\n"
	if banded != pktLine("\x02"+message)+pktLine("\x01"+want)+"0000" {
		t.Fatalf("side-band report:\n%q", banded)
	}
	// A report longer than one side-band packet is split across several.
	many := make([]string, 50)
	for i := range many {
		many[i] = "refs/heads/" + strings.Repeat("x", 30) + strconv.Itoa(i)
	}
	small := receivePackRefusal([]string{"report-status", "side-band"}, many, prefixes)
	for rest := string(small); rest != "0000"; {
		n, err := strconv.ParseUint(rest[:4], 16, 16)
		if err != nil || n > 1000 || n < 5 {
			t.Fatalf("side-band packet of %d bytes: %v", n, err)
		}
		rest = rest[n:]
	}
}

// requesterAPI fronts a fake GitHub for pull request writes on one pool that
// two people share. Pull requests: 12 from alice's branch, 13 from bob's, 14
// from the repository's shared pull request prefix. Workflow run 21 is a push
// to alice's branch.
type requesterAPI struct {
	audit    *adapterAudit
	port     int
	proxyURL *url.URL
	roots    *x509.CertPool
	mu       sync.Mutex
	received []string // "METHOD path" of every write GitHub received
}

func newRequesterAPI(t *testing.T) *requesterAPI {
	t.Helper()
	f := &requesterAPI{audit: &adapterAudit{}}
	same := `{"full_name":"example-org/example-repo"}`
	reads := map[string]string{
		"/pulls/12":          `{"number":12,"node_id":"PR_12","head":{"ref":"cursor/pool-agent/alice@example.com/fix","repo":` + same + `}}`,
		"/pulls/13":          `{"number":13,"node_id":"PR_13","head":{"ref":"cursor/pool-agent/bob@example.com/fix","repo":` + same + `}}`,
		"/pulls/14":          `{"number":14,"node_id":"PR_14","head":{"ref":"factory/fix","repo":` + same + `}}`,
		"/actions/runs/21":   `{"event":"push","head_branch":"cursor/pool-agent/alice@example.com/fix","repository":` + same + `,"head_repository":` + same + `}`,
		"/issues/comments/5": `{"issue_url":"https://api.example.com/repos/example-org/example-repo/issues/12","performed_via_github_app":{"id":7}}`,
	}
	github := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/app/installations/42/access_tokens" {
			var body struct {
				Permissions map[string]string `json:"permissions"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"token": "ghs_syntheticrequestertoken1", "expires_at": time.Now().Add(time.Hour).Format(time.RFC3339),
				"permissions": body.Permissions, "repositories": []map[string]string{{"full_name": "example-org/example-repo"}}})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		rest := strings.TrimPrefix(r.URL.Path, restartRepo)
		if r.Method == http.MethodGet {
			if body, ok := reads[rest]; ok {
				_, _ = io.WriteString(w, body)
				return
			}
			w.WriteHeader(http.StatusNotFound)
			return
		}
		f.mu.Lock()
		f.received = append(f.received, r.Method+" "+r.URL.Path)
		f.mu.Unlock()
		if r.URL.Path == "/graphql" {
			_, _ = io.WriteString(w, `{"data":{"markPullRequestReadyForReview":{"pullRequest":{"number":12,"isDraft":false}}}}`)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{}`)
	}))
	t.Cleanup(github.Close)
	_, portText, _ := net.SplitHostPort(strings.TrimPrefix(github.URL, "https://"))
	f.port, _ = strconv.Atoi(portText)
	catalog, err := httpcatalog.Parse([]byte(fmt.Sprintf(`{%s"entries":[
	  {"name":"github-api","host":"api.example.com","port":%d,"kind":"github-api","pools":["pool-agent"],
	   "git":{"appID":7,"installationID":42,"repos":[{"repo":"example-org/example-repo","access":"write",
	   "operations":["pr.open","pr.read","pr.comment","pr.edit","pr.label","pr.ready","pr.update_branch","actions.rerun"],
	   "labels":["preview"],"pullRequestPrefixes":["factory/"]}]}},
	  {"name":"github","host":"example.com","kind":"git","pools":["pool-agent"],
	   "git":{"appID":7,"installationID":42,"repos":[{"repo":"example-org/example-repo","access":"write",
	   "poolRefPrefixes":{"pool-agent":["refs/heads/cursor/pool-agent/{requester}/"]}}]}}]}`, requesterPool, f.port)))
	if err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	scope := &brokercore.ProxyScope{VaultID: "vault-1", AgentID: "pool-agent", Pool: "pool-agent", WorkloadID: "pod-uid-1"}
	proxyURL, roots, p := setupProxy(t, validTokenResolver("workload-token", scope), &fakeCredProvider{}, func(o *Options) {
		o.StrictCredentialProxy = true
		o.HeaderAdapter = &HeaderAdapter{Catalog: catalog, Keys: &adapterKeys{}, Audit: f.audit, Runner: requesterRunner,
			Sessions:     &authorizetest.MemBinder{},
			Entitlements: &entitlement.Cache{Source: directory{"alice@example.com": {}, "bob@example.com": {}}},
			GitTokens:    &githubapp.Minter{Signer: rsaSigner{key}, API: github.URL, Client: github.Client()}}
	})
	p.upstream.TLSClientConfig.RootCAs = github.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	p.upstream.TLSClientConfig.ServerName = "example.com" // the test server's certificate name
	addr := strings.TrimPrefix(github.URL, "https://")
	p.upstream.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	f.proxyURL, f.roots = proxyURL, roots
	return f
}

// send makes one request as the person whose session it carries.
func (f *requesterAPI) send(t *testing.T, session, method, path, body string) int {
	t.Helper()
	client := newTrustingClient(f.proxyURL, url.User("workload-token"), f.roots)
	defer client.CloseIdleConnections()
	client.Transport.(*http.Transport).ProxyConnectHeader = http.Header{SessionHeader: {session}}
	r, _ := http.NewRequest(method, "https://api.example.com:"+strconv.Itoa(f.port)+restartRepo+path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

// Every github-api write on a pull request holds to the requester's own
// branches: bob can open a pull request only from his branch, and can
// comment on, edit, label, mark ready, update or rerun only his own, never
// alice's. A pull request under the repository's shared pull request prefix
// stays open to both. Refused rows name the requester and the branch.
func TestGitHubAPIWritesStayOnTheRequestersOwnPullRequests(t *testing.T) {
	f := newRequesterAPI(t)
	open := func(head string) string { return `{"title":"t","head":"` + head + `","base":"main"}` }
	for _, tc := range []struct {
		name, method, path, body, outcome string
	}{
		{"open from alice's branch", "POST", "/pulls", open("cursor/pool-agent/alice@example.com/fix"), "head"},
		{"open from the pool's prefix", "POST", "/pulls", open("cursor/pool-agent/fix"), "head"},
		{"comment on alice's", "POST", "/issues/12/comments", `{"body":"x"}`, "comment_target"},
		{"edit alice's", "PATCH", "/pulls/12", `{"body":"x"}`, "pull_request_target"},
		{"edit a comment on alice's", "PATCH", "/issues/comments/5", `{"body":"x"}`, "pull_request_target"},
		{"label alice's", "POST", "/issues/12/labels", `{"labels":["preview"]}`, "pull_request_target"},
		{"mark alice's ready", "POST", "/pulls/12/ready", ``, "pull_request_target"},
		{"update alice's branch", "PUT", "/pulls/12/update-branch", ``, "pull_request_target"},
		{"rerun alice's run", "POST", "/actions/runs/21/rerun", ``, "run_target"},
	} {
		code := f.send(t, "bob", tc.method, tc.path, tc.body)
		row := f.audit.last()
		if code != http.StatusForbidden || row.Outcome != tc.outcome || row.Requester != "bob@example.com" || !strings.Contains(row.Branch, "alice@example.com") && tc.name != "open from the pool's prefix" {
			t.Errorf("bob %s: %d %+v", tc.name, code, row)
		}
	}
	f.mu.Lock()
	refused := append([]string(nil), f.received...)
	f.mu.Unlock()
	if len(refused) != 0 {
		t.Fatalf("GitHub received bob's refused writes: %v", refused)
	}
	for _, tc := range []struct {
		session, name, method, path, body string
	}{
		{"bob", "open from his branch", "POST", "/pulls", open("cursor/pool-agent/bob@example.com/fix")},
		{"bob", "comment on his", "POST", "/issues/13/comments", `{"body":"x"}`},
		{"bob", "label his", "POST", "/issues/13/labels", `{"labels":["preview"]}`},
		{"bob", "comment on the shared prefix's", "POST", "/issues/14/comments", `{"body":"x"}`},
		{"alice", "comment on hers", "POST", "/issues/12/comments", `{"body":"x"}`},
		{"alice", "rerun hers", "POST", "/actions/runs/21/rerun", ``},
		{"alice", "comment on the shared prefix's", "POST", "/issues/14/comments", `{"body":"x"}`},
	} {
		if code := f.send(t, tc.session, tc.method, tc.path, tc.body); code >= 400 {
			t.Errorf("%s %s: %d %+v", tc.session, tc.name, code, f.audit.last())
		}
	}
	if row := f.audit.last(); row.Requester != "alice@example.com" || row.Branch != "factory/fix" {
		t.Errorf("alice's comment row: %+v", row)
	}
}

// A GraphQL write holds to the requester's own pull requests exactly as REST
// does: gh pr comment, edit, label, ready, ready --undo and create as bob
// reach only his.
func TestGitHubGraphQLWritesStayOnTheRequestersOwnPullRequests(t *testing.T) {
	f := newGraphQLFixtureFor(t, true)
	f.useRaw(t, `{`+requesterPool+`"entries":[{"name":"github-api","host":"example.com","port":%[1]d,"kind":"github-api","pools":["pool-agent"],
		"git":{"appID":7,"installationID":42,"repos":[{"repo":"example-org/example-repo","access":"write",
		"operations":["graphql","pr.open","pr.read","pr.list","pr.comment","pr.edit","pr.label","pr.ready"],"labels":["preview"]}]}},
		{"name":"github","host":"git.example.com","kind":"git","pools":["pool-agent"],"git":{"appID":7,"installationID":42,
		"repos":[{"repo":"example-org/example-repo","access":"write","poolRefPrefixes":{"pool-agent":["refs/heads/cursor/pool-agent/{requester}/"]}}]}}]}`)
	f.proxy.adapter.Runner = requesterRunner
	f.as(t, "bob")
	comment := func(id string) string {
		return graphqlMutation("addComment", "AddCommentInput", map[string]any{"subjectId": id, "body": "x"})
	}
	ready := func(id string) string {
		return graphqlMutation("markPullRequestReadyForReview", "MarkPullRequestReadyForReviewInput", map[string]any{"pullRequestId": id})
	}
	edit := func(id string) string {
		return graphqlMutation("updatePullRequest", "UpdatePullRequestInput", map[string]any{"pullRequestId": id, "body": "x"})
	}
	label := func(id string) string {
		return graphqlMutation("addLabelsToLabelable", "AddLabelsToLabelableInput", map[string]any{"labelableId": id, "labelIds": []string{preview}})
	}
	draft := func(id string) string {
		return graphqlMutation("convertPullRequestToDraft", "ConvertPullRequestToDraftInput", map[string]any{"pullRequestId": id})
	}
	create := func(head string) string {
		b, _ := json.Marshal(map[string]any{"query": "mutation($input: CreatePullRequestInput!) { createPullRequest(input: $input) { pullRequest { id url } } }",
			"variables": map[string]any{"input": map[string]any{"repositoryId": exampleR, "headRefName": head, "baseRefName": "main", "title": "t", "body": "b", "draft": false}}})
		return string(b)
	}
	for name, tc := range map[string]struct{ body, outcome string }{
		"comment on alice's":   {comment(alicePR), "comment_target"},
		"ready on alice's":     {ready(alicePR), "pull_request_target"},
		"edit alice's":         {edit(alicePR), "pull_request_target"},
		"label alice's":        {label(alicePR), "pull_request_target"},
		"draft alice's":        {draft(alicePR), "pull_request_target"},
		"create from alice's":  {create("cursor/pool-agent/alice@example.com/fix"), "head"},
		"create from the pool": {create("cursor/pool-agent/fix"), "head"},
	} {
		code, _ := f.send(t, http.MethodPost, "/graphql", nil, tc.body)
		row := f.audit.last()
		if code != http.StatusForbidden || row.Outcome != tc.outcome || row.Requester != "bob@example.com" {
			t.Errorf("bob %s: %d %+v", name, code, row)
		}
	}
	if got := f.relayed(); len(got) != 0 {
		t.Fatalf("GitHub received bob's refused writes: %v", got)
	}
	for _, body := range []string{comment(bobPR), ready(bobPR), edit(bobPR), label(bobPR), draft(bobPR), create("cursor/pool-agent/bob@example.com/fix")} {
		if code, reply := f.send(t, http.MethodPost, "/graphql", nil, body); code != http.StatusOK {
			t.Errorf("bob's own: %s: %d %s %+v", body, code, reply, f.audit.last())
		}
	}
	if row := f.audit.last(); row.Branch != "cursor/pool-agent/bob@example.com/fix" || row.Requester != "bob@example.com" {
		t.Errorf("bob's create row: %+v", row)
	}
}
