package mitm

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/auditchain"
	"github.com/Infisical/agent-vault/internal/authorize/authorizetest"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/githubapp"
	"github.com/Infisical/agent-vault/internal/httpcatalog"
	"github.com/Infisical/agent-vault/internal/runnerid"
)

// nodeID builds a current-format GitHub node ID: prefix and base64url
// MessagePack [0, repository, object] with 32-bit integers.
func nodeID(prefix string, repo, object uint32) string {
	b := []byte{0x93, 0x00, 0xce, 0, 0, 0, 0, 0xce, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(b[3:], repo)
	binary.BigEndian.PutUint32(b[8:], object)
	return prefix + "_" + base64.RawURLEncoding.EncodeToString(b)
}

func TestNodeRepositoryID(t *testing.T) {
	for id, want := range map[string]int64{
		"PR_kwDOFb5pX86Z-PaA":           364800351, // shapes of real IDs
		"PR_kwDNA-jNB9A":                1000,
		nodeID("LA", 7, 9):              7,
		nodeID("PR", 1<<31, 1<<31):      1 << 31,
		"PR_kwDNA-jNB9AA":               0, // trailing byte
		"I_kwDNA-jNB9A":                 0, // an issue, not a pull request
		"MDExOlB1bGxSZXF1ZXN0MQ==":      0, // legacy: names no repository
		"PR_kgDNA-g":                    0, // two elements
		"PR_kwHNA-jNB9A":                0, // version 1
		"PR_kwDNA-jNB9A=":               0,
		"PR_" + strings.Repeat("A", 80): 0,
	} {
		got, ok := nodeRepositoryID(id)
		if got != want || ok != (want != 0) {
			t.Errorf("%s: %d %v, want %d", id, got, ok, want)
		}
	}
}

// graphqlFixture fronts a fake api.github.com with three repositories:
// example-repo (ID 1000, listed with every pull request operation),
// read-repo (2000, listed with pr.read and pr.list only) and secret-repo
// (3000, not listed). Each token answers only for the repository it was
// minted for, as GitHub's do, and the fake records what GitHub received.
type graphqlFixture struct {
	client       *http.Client
	port         int
	audit        *adapterAudit
	catalog      *swapCatalog
	mu           sync.Mutex
	minted       map[string]string // token -> repository name
	contents     map[string]string // token -> its contents permission
	received     []string          // relayed GraphQL bodies (not the broker's lookups)
	nextIDs      []string          // X-Github-Next-Global-ID on relayed requests
	lookups      int
	failNode     bool     // the node lookup answers 502
	failRepo     string   // this repository's read answers 502 ("*": every one)
	withContents []string // GraphQL requests made with a token holding contents
	person       bool     // pool-agent is a claude-session pool; requests come as alice
}

type swapCatalog struct {
	mu sync.Mutex
	c  httpcatalog.Catalog
}

func (s *swapCatalog) Current() httpcatalog.Catalog { s.mu.Lock(); defer s.mu.Unlock(); return s.c }

var (
	ownPR      = nodeID("PR", 1000, 12) // head cursor/pool-agent/x: the pool's own branch
	prefixPR   = nodeID("PR", 1000, 30) // head factory/fix: under the repository's pull request prefix
	personPR   = nodeID("PR", 1000, 13) // head person/x
	forkPR     = nodeID("PR", 1000, 14) // head cursor/pool-agent/y, but from a fork
	ghostPR    = nodeID("PR", 1000, 99) // names example-repo, which holds no such node
	readPR     = nodeID("PR", 2000, 5)
	secretPR   = nodeID("PR", 3000, 7)
	preview    = nodeID("LA", 1000, 501)
	deployProd = nodeID("LA", 1000, 502)
	otherLabel = nodeID("LA", 2000, 503)
)

type fakeNode struct{ typ, repo, headRepo, headRef, name string }

var fakeNodes = map[string]fakeNode{
	ownPR:      {"PullRequest", "example-repo", "example-repo", "cursor/pool-agent/x", ""},
	prefixPR:   {"PullRequest", "example-repo", "example-repo", "factory/fix", ""},
	personPR:   {"PullRequest", "example-repo", "example-repo", "person/x", ""},
	forkPR:     {"PullRequest", "example-repo", "someone/example-repo", "cursor/pool-agent/y", ""},
	readPR:     {"PullRequest", "read-repo", "read-repo", "cursor/pool-agent/z", ""},
	secretPR:   {"PullRequest", "secret-repo", "secret-repo", "cursor/pool-agent/x", ""},
	preview:    {"Label", "example-repo", "", "", "preview"},
	deployProd: {"Label", "example-repo", "", "", "deploy-prod"},
	otherLabel: {"Label", "read-repo", "", "", "preview"},
}

const graphqlCatalogTemplate = `{%s"entries":[{"name":"github-api","host":"example.com","port":%d,"kind":"github-api",
	"pools":["pool-agent"],"git":{"appID":7,"installationID":42,"repos":[%s,
	{"repo":"example-org/read-repo","access":"write","operations":["pr.read","pr.list"]}]}},
	{"name":"github","host":"git.example.com","kind":"git","pools":["pool-agent"],"git":{"appID":7,"installationID":42,
	"repos":[{"repo":"example-org/example-repo","access":"write","refPrefixes":["refs/heads/cursor/pool-agent/"]},
	{"repo":"example-org/read-repo","access":"write","refPrefixes":["refs/heads/cursor/pool-agent/"]}]}}]}`

// exampleRepo is example-repo's catalog entry with these operations; labels
// and pull request prefixes come with the operations that need them.
func exampleRepo(ops ...string) string {
	repo := map[string]any{"repo": "example-org/example-repo", "access": "write", "operations": ops}
	for _, op := range ops {
		switch op {
		case "pr.label":
			repo["labels"] = []string{"preview"}
			fallthrough
		case "pr.comment", "pr.edit", "pr.ready":
			repo["pullRequestPrefixes"] = []string{"factory/"}
		}
	}
	b, _ := json.Marshal(repo)
	return string(b)
}

var allPullRequestOps = []string{"pr.open", "pr.read", "pr.list", "pr.comment", "pr.edit", "pr.label", "pr.ready"}

func (f *graphqlFixture) use(t *testing.T, ops ...string) {
	t.Helper()
	pools := ""
	if f.person {
		// pool-agent is a person pool: a Claude runner session names who
		// stands behind each request.
		pools = `"pools":[{"name":"pool-agent","namespace":"n","serviceAccount":"agent","identity":"claude-session","ccpoolID":"ccpool_abc"}],`
	}
	c, err := httpcatalog.Parse([]byte(fmt.Sprintf(graphqlCatalogTemplate, pools, f.port, exampleRepo(ops...))))
	if err != nil {
		t.Fatal(err)
	}
	f.catalog.mu.Lock()
	f.catalog.c = c
	f.catalog.mu.Unlock()
}

func newGraphQLFixture(t *testing.T) *graphqlFixture { return newGraphQLFixtureFor(t, false) }

// newGraphQLFixtureFor serves pool-agent as a person pool when person is set:
// each request carries the runner session of "alice".
func newGraphQLFixtureFor(t *testing.T, person bool) *graphqlFixture {
	t.Helper()
	f := &graphqlFixture{audit: &adapterAudit{}, catalog: &swapCatalog{}, minted: map[string]string{}, contents: map[string]string{}, person: person}
	repoIDs := map[string]int{"example-repo": 1000, "read-repo": 2000, "secret-repo": 3000}
	var seq int
	github := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/app/installations/42/access_tokens" {
			var body struct {
				Repositories []string          `json:"repositories"`
				Permissions  map[string]string `json:"permissions"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if len(body.Repositories) != 1 || body.Permissions["pull_requests"] != "write" {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			f.mu.Lock()
			seq++
			token := fmt.Sprintf("ghs_syntheticgraphqltoken%06d", seq)
			f.minted[token] = body.Repositories[0]
			f.contents[token] = body.Permissions["contents"]
			f.mu.Unlock()
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"token": token, "expires_at": time.Now().Add(time.Hour).Format(time.RFC3339),
				"permissions": body.Permissions, "repositories": []map[string]string{{"full_name": "example-org/" + body.Repositories[0]}}})
			return
		}
		f.mu.Lock()
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		repo, ok := f.minted[token]
		failNode, failRepo := f.failNode, f.failRepo
		if r.URL.Path == "/graphql" && f.contents[token] != "" {
			f.withContents = append(f.withContents, repo)
		}
		f.mu.Unlock()
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/repos/example-org/") {
			name := strings.TrimPrefix(r.URL.Path, "/repos/example-org/")
			switch {
			case failRepo == "*" || failRepo == name:
				w.WriteHeader(http.StatusBadGateway)
			case name == repo:
				_ = json.NewEncoder(w).Encode(map[string]any{"id": repoIDs[repo], "full_name": "example-org/" + repo})
			case strings.HasPrefix(name, repo+"/pulls/"): // gh pr diff
				fmt.Fprint(w, `{"number":12}`)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
			return
		}
		if r.URL.Path != "/graphql" || r.Method != http.MethodPost {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Query     string `json:"query"`
			Variables struct {
				IDs []string `json:"ids"`
			} `json:"variables"`
		}
		_ = json.Unmarshal(body, &req)
		if req.Query == nodesLookup {
			f.mu.Lock()
			f.lookups++
			f.mu.Unlock()
			if failNode {
				w.WriteHeader(http.StatusBadGateway)
				return
			}
			nodes := []any{}
			for _, id := range req.Variables.IDs {
				n, ok := fakeNodes[id]
				if !ok || n.repo != repo { // invisible to this repository's token
					nodes = append(nodes, nil)
					continue
				}
				node := map[string]any{"__typename": n.typ, "repository": map[string]string{"nameWithOwner": "example-org/" + n.repo}}
				if n.typ == "PullRequest" {
					headOwner := "example-org/"
					if strings.Contains(n.headRepo, "/") {
						headOwner = ""
					}
					node["headRefName"], node["headRepository"] = n.headRef, map[string]string{"nameWithOwner": headOwner + n.headRepo}
				} else {
					node["name"] = n.name
				}
				nodes = append(nodes, node)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"nodes": nodes}})
			return
		}
		f.mu.Lock()
		f.received = append(f.received, repo+" "+string(body))
		f.nextIDs = append(f.nextIDs, r.Header.Get("X-Github-Next-Global-ID"))
		f.mu.Unlock()
		fmt.Fprint(w, `{"data":{}}`)
	}))
	t.Cleanup(github.Close)
	_, portText, _ := net.SplitHostPort(strings.TrimPrefix(github.URL, "https://"))
	f.port, _ = strconv.Atoi(portText)
	f.use(t, allPullRequestOps...)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	minter := &githubapp.Minter{Signer: rsaSigner{key}, API: github.URL, Client: github.Client()}
	scope := &brokercore.ProxyScope{VaultID: "vault-1", AgentID: "agent-uuid-1", Pool: "pool-agent", WorkloadID: "pod-uid-1"}
	proxyURL, roots, p := setupProxy(t, validTokenResolver("workload-token", scope), &fakeCredProvider{}, func(o *Options) {
		o.StrictCredentialProxy = true
		o.HeaderAdapter = &HeaderAdapter{Catalog: f.catalog, Keys: &adapterKeys{}, Audit: f.audit, GitTokens: minter,
			Runner:   fakeRunner{"alice": {Kind: runnerid.KindPerson, Subject: "sso|alice", Pools: []string{"ccpool_abc"}, TokenSHA256: "aa"}},
			Sessions: &authorizetest.MemBinder{}}
	})
	p.upstream.TLSClientConfig.RootCAs = github.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	addr := strings.TrimPrefix(github.URL, "https://")
	p.upstream.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	f.client = newTrustingClient(proxyURL, url.User("workload-token"), roots)
	if person {
		f.client.Transport.(*http.Transport).ProxyConnectHeader = http.Header{SessionHeader: {"alice"}}
	}
	t.Cleanup(f.client.CloseIdleConnections)
	return f
}

// send makes one request through the broker, as gh would with the
// placeholder token and its own headers.
func (f *graphqlFixture) send(t *testing.T, method, path string, headers map[string]string, body string) (int, string) {
	t.Helper()
	r, _ := http.NewRequest(method, "https://example.com:"+strconv.Itoa(f.port)+path, strings.NewReader(body))
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	if r.Header.Get("Content-Type") == "" {
		r.Header.Set("Content-Type", "application/json")
	}
	r.Header.Set("Authorization", "token "+githubTokenPlaceholder)
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

func (f *graphqlFixture) relayed() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.received...)
}

func graphqlMutation(name, input string, variables map[string]any) string {
	b, _ := json.Marshal(map[string]any{"query": "mutation($input: " + input + "!) { " + name + "(input: $input) { clientMutationId } }",
		"variables": map[string]any{"input": variables}})
	return string(b)
}

// ghCommands are the recorded gh commands (httpcatalog/testdata/gh) and the
// operations each needs.
var ghCommands = []struct {
	fixture string
	needs   []string
}{
	{"pr-view-number", []string{"pr.read"}},
	{"pr-view-url", []string{"pr.read"}},
	{"pr-view-comments", []string{"pr.read"}},
	{"pr-view-json", []string{"pr.read"}},
	{"pr-view-branch", []string{"pr.read", "pr.list"}},
	{"pr-list", []string{"pr.read", "pr.list"}}, // every query also needs pr.read
	{"pr-list-all-json", []string{"pr.read", "pr.list"}},
	{"pr-list-head", []string{"pr.read", "pr.list"}},
	{"pr-list-limit-200", []string{"pr.read", "pr.list"}},
	{"pr-status", []string{"pr.read", "pr.list"}},
	{"pr-comment", []string{"pr.read", "pr.comment"}},
	{"pr-edit-body", []string{"pr.read", "pr.edit"}},
	{"pr-edit-add-label", []string{"pr.read", "pr.label"}},
	{"pr-ready", []string{"pr.read", "pr.ready"}},
	{"pr-checks", []string{"pr.read"}},
	{"pr-checks-json", []string{"pr.read"}},
	{"pr-diff", []string{"pr.read"}},
}

// replay sends a recorded gh command through the broker, with the pool's own
// pull request and the preview label as the IDs gh read. It returns the first
// refusal's outcome, or "" when every request was served.
func (f *graphqlFixture) replay(t *testing.T, fixture string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "httpcatalog", "testdata", "gh", fixture+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var fx struct {
		Requests []struct {
			Method, Path, Body string
			Headers            map[string]string
		}
	}
	if err := json.Unmarshal(data, &fx); err != nil {
		t.Fatal(err)
	}
	for i, r := range fx.Requests {
		body := strings.NewReplacer("{{PR}}", ownPR, "{{LABEL}}", preview).Replace(r.Body)
		before := len(f.relayed())
		code, reply := f.send(t, r.Method, r.Path, r.Headers, body)
		if code != http.StatusOK {
			return f.audit.last().Outcome
		}
		if r.Path == "/graphql" && strings.Contains(r.Body, "__type(") {
			if len(f.relayed()) != before || !strings.Contains(reply, `"fields"`) {
				t.Errorf("%s request %d: feature detection reached GitHub or was not answered: %s", fixture, i, reply)
			}
		} else if r.Path == "/graphql" && len(f.relayed()) != before+1 {
			t.Errorf("%s request %d: served but not relayed", fixture, i)
		}
	}
	return ""
}

func TestGitHubGraphQLServesRecordedGhCommands(t *testing.T) {
	f := newGraphQLFixture(t)
	for _, c := range ghCommands {
		if outcome := f.replay(t, c.fixture); outcome != "" {
			t.Errorf("%s with every operation: refused %q", c.fixture, outcome)
		}
		// Exactly the operations it needs are enough.
		f.use(t, c.needs...)
		if outcome := f.replay(t, c.fixture); outcome != "" {
			t.Errorf("%s with %v: refused %q", c.fixture, c.needs, outcome)
		}
		// Without any one of them, gh is refused at that step.
		for _, missing := range c.needs {
			var rest []string
			for _, op := range c.needs {
				if op != missing {
					rest = append(rest, op)
				}
			}
			if len(rest) == 0 {
				rest = []string{"pr.open"}
			}
			f.use(t, rest...)
			if outcome := f.replay(t, c.fixture); outcome != "unlisted" {
				t.Errorf("%s without %s: outcome %q, want unlisted", c.fixture, missing, outcome)
			}
		}
		f.use(t, allPullRequestOps...)
	}
	// Every relayed request was the rebuilt document, for example-repo's own
	// token, asking GitHub for IDs that name their repository.
	for i, body := range f.relayed() {
		if !strings.HasPrefix(body, "example-repo ") {
			t.Fatalf("relayed with another repository's token: %s", body)
		}
		if f.nextIDs[i] != "1" {
			t.Fatalf("relayed without X-Github-Next-Global-ID: %s", body)
		}
	}
	// No GraphQL request carried a token with contents: nested fields can
	// reach files and history, which only a git entry grants.
	f.mu.Lock()
	withContents := f.withContents
	f.mu.Unlock()
	if len(withContents) != 0 {
		t.Errorf("GraphQL requests made with a contents token: %v", withContents)
	}
	// The trail names the mapped operation.
	found := false
	for _, e := range f.audit.all() {
		if e.Binding == "github-api/example-org/example-repo#graphql:pr.comment" && e.Outcome == "completed" && e.Agent == "agent-uuid-1" {
			found = true
		}
	}
	if !found {
		t.Error("no completed audit row names pr.comment")
	}
	// gh pr edit --title is refused: pr.edit changes only the body.
	if outcome := f.replay(t, "pr-edit-title"); outcome != "graphql_unmapped" {
		t.Errorf("title edit: %q", outcome)
	}
}

// A mutation acts only on a pull request the pool may write to, in a listed
// repository that grants the operation, whatever node ID it names.
func TestGitHubGraphQLRefusesOtherTargets(t *testing.T) {
	f := newGraphQLFixture(t)
	comment := func(id string) string {
		return graphqlMutation("addComment", "AddCommentInput", map[string]any{"subjectId": id, "body": "x"})
	}
	label := func(pr string, labels ...string) string {
		return graphqlMutation("addLabelsToLabelable", "AddLabelsToLabelableInput", map[string]any{"labelableId": pr, "labelIds": labels})
	}
	read := func(id string) string {
		b, _ := json.Marshal(map[string]any{"query": `query($id: ID!) { node(id: $id) { ... on PullRequest { number } } }`, "variables": map[string]any{"id": id}})
		return string(b)
	}
	for _, tc := range []struct {
		name, body, outcome string
	}{
		{"a person's pull request", comment(personPR), "comment_target"},
		{"a fork's pull request", comment(forkPR), "comment_target"},
		{"a listed repository without pr.comment", comment(readPR), "comment_target"},
		{"an unlisted repository", comment(secretPR), "comment_target"},
		{"an ID the repository does not hold", comment(ghostPR), "comment_target"},
		{"a legacy ID", comment("MDExOlB1bGxSZXF1ZXN0MQ=="), "comment_target"},
		{"a label ID as the pull request", comment(preview), "comment_target"},
		{"a person's pull request ready", graphqlMutation("markPullRequestReadyForReview", "MarkPullRequestReadyForReviewInput",
			map[string]any{"pullRequestId": personPR}), "pull_request_target"},
		{"a person's pull request edited", graphqlMutation("updatePullRequest", "UpdatePullRequestInput",
			map[string]any{"pullRequestId": personPR, "body": "x"}), "pull_request_target"},
		{"an unlisted label", label(ownPR, deployProd), "request_shape"},
		{"another repository's label", label(ownPR, otherLabel), "pull_request_target"},
		{"a person's pull request labelled", label(personPR, preview), "pull_request_target"},
		{"a pull request as the label", label(ownPR, prefixPR), "request_shape"},
		{"reading an unlisted repository", read(secretPR), "pull_request_target"},
		{"reading an unlisted repository by name", `{"query":"query { repository(owner: \"example-org\", name: \"secret-repo\") { pullRequest(number: 7) { id } } }"}`, "unlisted"},
		{"a pull request in one repository read through another", `{"query":"query($id: ID!) { repository(owner: \"example-org\", name: \"read-repo\") { pullRequest(number: 5) { id } } node(id: $id) { ... on PullRequest { number } } }","variables":{"id":"` + ownPR + `"}}`, "pull_request_target"},
	} {
		code, _ := f.send(t, http.MethodPost, "/graphql", nil, tc.body)
		if code < 400 || f.audit.last().Outcome != tc.outcome {
			t.Errorf("%s: %d %q, want %q", tc.name, code, f.audit.last().Outcome, tc.outcome)
		}
	}
	if got := f.relayed(); len(got) != 0 {
		t.Fatalf("GitHub received refused requests: %v", got)
	}
	// The pool's own pull request, and one under the repository's prefix, go
	// ahead; so does reading a pull request in a listed repository.
	for _, body := range []string{comment(ownPR), comment(prefixPR), label(prefixPR, preview), read(readPR),
		graphqlMutation("markPullRequestReadyForReview", "MarkPullRequestReadyForReviewInput", map[string]any{"pullRequestId": prefixPR})} {
		if code, reply := f.send(t, http.MethodPost, "/graphql", nil, body); code != 200 {
			t.Errorf("%s: %d %s %q", body, code, reply, f.audit.last().Outcome)
		}
	}
	if got := f.relayed(); len(got) != 5 || !strings.HasPrefix(got[3], "read-repo ") {
		t.Fatalf("relayed %v", got)
	}
}

// A lookup GitHub does not answer refuses; nothing is sent on a guess.
func TestGitHubGraphQLLookupFailureRefuses(t *testing.T) {
	f := newGraphQLFixture(t)
	body := graphqlMutation("addComment", "AddCommentInput", map[string]any{"subjectId": ownPR, "body": "x"})
	f.mu.Lock()
	f.failRepo = "*"
	f.mu.Unlock()
	if code, _ := f.send(t, http.MethodPost, "/graphql", nil, body); code != 503 || f.audit.last().Outcome != "target_lookup" {
		t.Fatalf("repository lookup failed: %d %q", code, f.audit.last().Outcome)
	}
	f.mu.Lock()
	f.failRepo, f.failNode = "", true
	f.mu.Unlock()
	if code, _ := f.send(t, http.MethodPost, "/graphql", nil, body); code != 503 || f.audit.last().Outcome != "target_lookup" {
		t.Fatalf("node lookup failed: %d %q", code, f.audit.last().Outcome)
	}
	if got := f.relayed(); len(got) != 0 {
		t.Fatalf("GitHub received a request after a failed lookup: %v", got)
	}
	// Once GitHub answers, the request goes ahead, and the answer is kept.
	f.mu.Lock()
	f.failNode = false
	f.mu.Unlock()
	for range 2 {
		if code, _ := f.send(t, http.MethodPost, "/graphql", nil, body); code != 200 {
			t.Fatalf("after recovery: %d %q", code, f.audit.last().Outcome)
		}
	}
	f.mu.Lock()
	lookups := f.lookups
	f.mu.Unlock()
	if lookups != 2 { // one failed, one answered and kept
		t.Fatalf("%d node lookups", lookups)
	}
}

// Refusals of the request itself never reach GitHub, and other methods,
// shapes and pools are refused as for REST.
func TestGitHubGraphQLRefusesShapes(t *testing.T) {
	f := newGraphQLFixture(t)
	for _, tc := range []struct {
		name, method, path, body string
		headers                  map[string]string
		code                     int
		outcome                  string
	}{
		{"introspection", "POST", "/graphql", `{"query":"query { __schema { types { name } } }"}`, nil, 403, "graphql_introspection"},
		{"too many aliases", "POST", "/graphql", `{"query":"query { repository(owner: \"example-org\", name: \"example-repo\") { ` +
			strings.Repeat(`x: pullRequest(number: 1) { id } `, 11) + `} }"}`, nil, 403, "graphql_limit"},
		{"unbounded page", "POST", "/graphql", `{"query":"query { repository(owner: \"example-org\", name: \"example-repo\") { pullRequests(first: 1000) { totalCount } } }"}`, nil, 403, "graphql_limit"},
		{"merge", "POST", "/graphql", graphqlMutation("mergePullRequest", "MergePullRequestInput", map[string]any{"pullRequestId": ownPR}), nil, 403, "graphql_unmapped"},
		{"not JSON", "POST", "/graphql", `query { x }`, nil, 400, "graphql_shape"},
		{"GET", "GET", "/graphql", "", nil, 405, "method"},
		{"query string", "POST", "/graphql?x=1", `{"query":"query { __typename }"}`, nil, 400, "request_shape"},
		{"form body", "POST", "/graphql", `{"query":"x"}`, map[string]string{"Content-Type": "text/plain"}, 400, "request_shape"},
		{"placeholder", "POST", "/graphql", `{"query":"query { repository(owner: \"__vault_x\", name: \"r\") { id } }"}`, nil, 400, "placeholder_misplaced"},
		{"oversized", "POST", "/graphql", `{"query":"` + strings.Repeat("a", 2<<20) + `"}`, nil, 413, "request_too_large"},
	} {
		code, _ := f.send(t, tc.method, tc.path, tc.headers, tc.body)
		if code != tc.code || f.audit.last().Outcome != tc.outcome {
			t.Errorf("%s: %d %q, want %d %q", tc.name, code, f.audit.last().Outcome, tc.code, tc.outcome)
		}
	}
	// A pool granted no github-api repository on the host gets nothing,
	// feature detection included.
	c, err := httpcatalog.Parse([]byte(fmt.Sprintf(`{"entries":[{"name":"github-api","host":"example.com","port":%d,"kind":"github-api",
		"pools":["another-pool"],"git":{"appID":7,"installationID":42,"repos":[{"repo":"example-org/example-repo","access":"write"}]}}]}`, f.port)))
	if err != nil {
		t.Fatal(err)
	}
	f.catalog.mu.Lock()
	f.catalog.c = c
	f.catalog.mu.Unlock()
	feature := `{"query":"query PullRequest_fields2{WorkflowRun: __type(name: \"WorkflowRun\"){fields(includeDeprecated: true){name}}}"}`
	// (The tunnel itself is refused, so the client sees no status.)
	if code, _ := f.send(t, "POST", "/graphql", nil, feature); code == 200 || f.audit.last().Outcome != "pool" {
		t.Errorf("another pool's host: %d %q", code, f.audit.last().Outcome)
	}
	if got := f.relayed(); len(got) != 0 {
		t.Fatalf("GitHub received refused requests: %v", got)
	}
}

// One listed repository GitHub cannot answer for does not stop requests for
// the others.
func TestGitHubGraphQLSkipsAFailedRepository(t *testing.T) {
	f := newGraphQLFixture(t)
	f.mu.Lock()
	f.failRepo = "example-repo"
	f.mu.Unlock()
	read, _ := json.Marshal(map[string]any{"query": `query($id: ID!) { node(id: $id) { ... on PullRequest { number } } }`, "variables": map[string]any{"id": readPR}})
	if code, _ := f.send(t, http.MethodPost, "/graphql", nil, string(read)); code != 200 {
		t.Fatalf("read-repo's pull request with example-repo unreadable: %d %q", code, f.audit.last().Outcome)
	}
	// An ID that matches none of the readable repositories still refuses as
	// unknown, since the unreadable one may hold it.
	ghost, _ := json.Marshal(map[string]any{"query": `query($id: ID!) { node(id: $id) { ... on PullRequest { number } } }`, "variables": map[string]any{"id": ghostPR}})
	if code, _ := f.send(t, http.MethodPost, "/graphql", nil, string(ghost)); code != 503 || f.audit.last().Outcome != "target_lookup" {
		t.Fatalf("unmatched ID with a repository unreadable: %d %q", code, f.audit.last().Outcome)
	}
}

// A GraphQL row names the person behind the request, with the tier and
// decision, exactly as a REST row for the same pool does: on a write that
// reached GitHub, on a refusal, and on the broker's own answer.
func TestGitHubGraphQLAuditNamesThePerson(t *testing.T) {
	f := newGraphQLFixtureFor(t, true)
	sameAuthorization := func(what string, want auditchain.Event) {
		t.Helper()
		got := f.audit.last()
		if got.Requester != want.Requester || got.RequesterKind != want.RequesterKind || got.Tier != want.Tier || got.Decision != want.Decision ||
			got.TokenSHA256 != want.TokenSHA256 || got.Requester != "sso|alice" {
			t.Errorf("%s: requester %q kind %q tier %q decision %q, want %q %q %q %q", what,
				got.Requester, got.RequesterKind, got.Tier, got.Decision, want.Requester, want.RequesterKind, want.Tier, want.Decision)
		}
	}
	if code, _ := f.send(t, http.MethodGet, "/repos/example-org/example-repo/pulls/12", nil, ""); code != 200 {
		t.Fatalf("REST read: %d %q", code, f.audit.last().Outcome)
	}
	rest := f.audit.last()
	comment := graphqlMutation("addComment", "AddCommentInput", map[string]any{"subjectId": ownPR, "body": "x"})
	if code, _ := f.send(t, http.MethodPost, "/graphql", nil, comment); code != 200 {
		t.Fatalf("comment: %d %q", code, f.audit.last().Outcome)
	}
	sameAuthorization("completed comment", rest)
	admitted := f.audit.all()
	admittedRow := admitted[len(admitted)-2]
	if admittedRow.Outcome != "admitted" || admittedRow.Requester != "sso|alice" {
		t.Errorf("admitted row: %q %q", admittedRow.Outcome, admittedRow.Requester)
	}
	if code, _ := f.send(t, http.MethodPost, "/graphql", nil, graphqlMutation("addComment", "AddCommentInput", map[string]any{"subjectId": personPR, "body": "x"})); code != 403 {
		t.Fatalf("refused comment: %d", code)
	}
	sameAuthorization("refused comment", rest)
	if code, _ := f.send(t, http.MethodPost, "/graphql", nil, `{"query":"query { __schema { types { name } } }"}`); code != 403 {
		t.Fatalf("introspection: %d", code)
	}
	sameAuthorization("refused introspection", rest)
	feature := `{"query":"query PullRequest_fields2{WorkflowRun: __type(name: \"WorkflowRun\"){fields(includeDeprecated: true){name}}}"}`
	if code, _ := f.send(t, http.MethodPost, "/graphql", nil, feature); code != 200 {
		t.Fatalf("feature detection: %d %q", code, f.audit.last().Outcome)
	}
	sameAuthorization("feature detection", rest)
}
