package mitm

import (
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
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/authorize/authorizetest"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/entitlement"
	"github.com/Infisical/agent-vault/internal/githubapp"
	"github.com/Infisical/agent-vault/internal/httpcatalog"
	"github.com/Infisical/agent-vault/internal/runnerid"
)

// automationRunsFor names five Automations that run on one Pod, so one claimed
// run serves them all: each token is one Automation's run.
var automationRunsFor = cursorRunner{
	"reader":   automationWriteRun("auto-reader"),
	"writer":   automationWriteRun("auto-writer"),
	"api-only": automationWriteRun("auto-api"),
	"git-only": automationWriteRun("auto-git"),
	"unkeyed":  automationWriteRun("auto-unkeyed"),
}

func automationWriteRun(automation string) runnerid.Session {
	return runnerid.Session{Kind: runnerid.KindPerson, Subject: "owner@example.com", Owner: "user:1", Run: "bc-1", Source: "AUTOMATIONS", Automation: automation}
}

// writeGrantCatalogFor is one Automation pool with a git entry and a github-api
// entry on one repository, where the pool may push factory/ and open, read,
// list, comment on and update the branch of pull requests. Five Automations
// list both entries and differ only in write: an empty list, both entries, the
// github-api entry only, the git entry only, and no write key at all.
const writeGrantCatalogFor = `{"pools":[{"name":"pool-agent","namespace":"n","serviceAccount":"worker","identity":"cursor-automation"}],
 "entries":[
  {"name":"github-api","host":"api.example.com","kind":"github-api","pools":["pool-agent"],"git":{"appID":7,"installationID":42,"repos":[
   {"repo":"example-org/example-repo","access":"write","operations":["pr.open","pr.read","pr.list","pr.comment","pr.update_branch"],
    "poolOperations":{"pool-agent":["pr.open","pr.read","pr.list","pr.comment","pr.update_branch"]}}]}},
  {"name":"github","host":"example.com","kind":"git","pools":["pool-agent"],"git":{"appID":7,"installationID":42,"repos":[
   {"repo":"example-org/example-repo","access":"write","refPrefixes":["refs/heads/factory/"]}]}}],
 "automations":[
  {"id":"auto-reader","name":"reader","owner":"platform-team","entries":["github","github-api"],"write":[]},
  {"id":"auto-writer","name":"writer","owner":"platform-team","entries":["github","github-api"],"write":["github","github-api"]},
  {"id":"auto-api","name":"api-only","owner":"platform-team","entries":["github","github-api"],"write":["github-api"]},
  {"id":"auto-git","name":"git-only","owner":"platform-team","entries":["github","github-api"],"write":["github"]},
  {"id":"auto-unkeyed","name":"unkeyed","owner":"platform-team","entries":["github","github-api"]}]}`

type automationWriteFixture struct {
	proxyURL *url.URL
	roots    *x509.CertPool
	audit    *adapterAudit
	mu       sync.Mutex
	minted   int      // tokens the broker minted
	received []string // every request GitHub received, but the broker's reads of pull request 12 and its token mints
}

func newAutomationWriteFixture(t *testing.T) *automationWriteFixture {
	t.Helper()
	f := &automationWriteFixture{audit: &adapterAudit{}}
	github := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/app/installations/42/access_tokens" {
			var body struct {
				Repositories []string          `json:"repositories"`
				Permissions  map[string]string `json:"permissions"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			f.mu.Lock()
			f.minted++
			token := fmt.Sprintf("ghs_syntheticwritegranttoken%06d", f.minted)
			f.mu.Unlock()
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"token": token, "expires_at": time.Now().Add(time.Hour).Format(time.RFC3339),
				"permissions": body.Permissions, "repositories": []map[string]string{{"full_name": "example-org/example-repo"}}})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet && r.URL.Path == "/repos/example-org/example-repo/pulls/12" {
			// The pool's own pull request: its head is under factory/.
			_, _ = io.WriteString(w, `{"number":12,"node_id":"PR_twelve","head":{"ref":"factory/x","repo":{"full_name":"example-org/example-repo"}}}`)
			return
		}
		_, _ = io.Copy(io.Discard, r.Body)
		f.mu.Lock()
		f.received = append(f.received, r.Method+" "+r.URL.RequestURI())
		f.mu.Unlock()
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	t.Cleanup(github.Close)
	catalog, err := httpcatalog.Parse([]byte(writeGrantCatalogFor))
	if err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	scope := &brokercore.ProxyScope{VaultID: "vault-1", AgentID: "agent-uuid-1", Pool: "pool-agent", WorkloadID: "pod-uid-1", ClaimedRun: "bc-1"}
	var p *Proxy
	f.proxyURL, f.roots, p = setupProxy(t, validTokenResolver("workload-token", scope), &fakeCredProvider{}, func(o *Options) {
		o.StrictCredentialProxy = true
		o.HeaderAdapter = &HeaderAdapter{Catalog: catalog, Keys: &adapterKeys{}, Audit: f.audit, Runner: automationRunsFor, Sessions: &authorizetest.MemBinder{},
			Entitlements: &entitlement.Cache{Source: directory{}},
			GitTokens:    &githubapp.Minter{Signer: rsaSigner{key}, API: github.URL, Client: github.Client()}}
	})
	p.upstream.TLSClientConfig.RootCAs = github.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	p.upstream.TLSClientConfig.ServerName = "example.com" // the test server's certificate name
	addr := strings.TrimPrefix(github.URL, "https://")
	p.upstream.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	return f
}

// send makes one request through the broker as one Automation's run, and
// returns the status and the refusal code the broker answered with, if any.
func (f *automationWriteFixture) send(t *testing.T, automation, method, host, path, body string) (int, string) {
	t.Helper()
	client := newTrustingClient(f.proxyURL, url.User("workload-token"), f.roots)
	defer client.CloseIdleConnections()
	client.Transport.(*http.Transport).ProxyConnectHeader = http.Header{SessionHeader: {automation}}
	r, _ := http.NewRequest(method, "https://"+host+path, strings.NewReader(body))
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(r)
	if err != nil {
		t.Fatalf("%s %s %s: %v", automation, method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, resp.Header.Get(RefusalHeader)
}

func (f *automationWriteFixture) counts() (minted, received int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.minted, len(f.received)
}

// What an Automation may do on GitHub follows its own block, not the pool's:
// every Automation here lists the same two entries on the same pool, yet one
// with an empty write list fetches and reads only, one with write on both
// entries pushes and changes pull requests, and one with write on a single
// entry does only what that entry carries. One whose block has no write key
// keeps everything the pool gives, so a broker that reads write changes
// nothing until a catalog sets it. A CI restart is a branch update that
// reaches no further than a push, so it needs both. A refused request is answered before
// a token is minted and never reaches GitHub, and its audit row names the
// Automation and the entry.
func TestAutomationWriteGrantDecidesGitHubWrites(t *testing.T) {
	f := newAutomationWriteFixture(t)
	const (
		api = "api.example.com"
		git = "example.com"
		app = "/repos/example-org/example-repo"
	)
	type request struct {
		name, host, method, path, body string
		binding                        string // the entry its refusal names
	}
	reads := []request{
		{"read a pull request", api, "GET", app + "/pulls/12", "", ""},
		{"list pull requests", api, "GET", app + "/pulls?state=open", "", ""},
		{"fetch", git, "GET", "/example-org/example-repo.git/info/refs?service=git-upload-pack", "", ""},
	}
	open := request{"open a pull request", api, "POST", app + "/pulls", `{"head":"factory/new","base":"main","title":"t"}`, "github-api"}
	comment := request{"comment", api, "POST", app + "/issues/12/comments", `{"body":"x"}`, "github-api"}
	pushAdvert := request{"push advertisement", git, "GET", "/example-org/example-repo.git/info/refs?service=git-receive-pack", "", "github"}
	push := request{"push", git, "POST", "/example-org/example-repo.git/git-receive-pack", "0000", "github"}
	restart := request{"update a branch", api, "PUT", app + "/pulls/12/update-branch", "", "github-api"}
	// allowed lists, for each Automation, the requests it may make; every other
	// one is refused. A push is tried only where it is refused: allowed, it
	// needs a real pack.
	allowed := map[string][]request{
		"reader":   nil,
		"writer":   {open, comment, pushAdvert, push, restart},
		"api-only": {open, comment},
		"git-only": {pushAdvert, push},
		"unkeyed":  {open, comment, pushAdvert, push, restart},
	}
	ids := map[string]string{"reader": "auto-reader", "writer": "auto-writer", "api-only": "auto-api", "git-only": "auto-git", "unkeyed": "auto-unkeyed"}
	for _, automation := range []string{"reader", "writer", "api-only", "git-only", "unkeyed"} {
		for _, r := range reads {
			if code, refusal := f.send(t, automation, r.method, r.host, r.path, r.body); code != http.StatusOK || refusal != "" {
				t.Errorf("%s: %s: %d %q, want it served", automation, r.name, code, refusal)
			}
		}
		for _, r := range []request{open, comment, pushAdvert, push, restart} {
			may := false
			for _, a := range allowed[automation] {
				may = may || a.name == r.name
			}
			if r.name == "push" && may {
				continue
			}
			mintedBefore, receivedBefore := f.counts()
			code, refusal := f.send(t, automation, r.method, r.host, r.path, r.body)
			minted, received := f.counts()
			last := f.audit.last()
			if may {
				if refusal != "" || code >= 300 || received != receivedBefore+1 {
					t.Errorf("%s: %s: %d %q, received %d new, want it served", automation, r.name, code, refusal, received-receivedBefore)
				}
				continue
			}
			if code != http.StatusForbidden || refusal != "automation_read_only" || last.Outcome != "automation_read_only" {
				t.Errorf("%s: %s: %d %q (audit %q), want refused as automation_read_only", automation, r.name, code, refusal, last.Outcome)
			}
			if minted != mintedBefore || received != receivedBefore {
				t.Errorf("%s: %s: a token was minted (%d) or GitHub was asked (%d) for a refused request", automation, r.name, minted-mintedBefore, received-receivedBefore)
			}
			if last.Automation != ids[automation] || last.RequesterKind != "automation" || !strings.HasPrefix(last.Binding, r.binding+"/") {
				t.Errorf("%s: %s: audit row names %q as %q on %q", automation, r.name, last.Automation, last.RequesterKind, last.Binding)
			}
		}
		if automation == "reader" {
			// The Automation with an empty write list changed nothing: GitHub
			// received its list and its fetch (the read of pull request 12
			// is the fake's own answer) and nothing else.
			f.mu.Lock()
			received := append([]string(nil), f.received...)
			f.mu.Unlock()
			if len(received) != 2 {
				t.Errorf("GitHub received %v for the reader, want its list and its fetch", received)
			}
			for _, line := range received {
				if !strings.HasPrefix(line, "GET ") || strings.Contains(line, "receive-pack") {
					t.Errorf("GitHub received a change from the reader: %s", line)
				}
			}
		}
	}
}

// Over GraphQL, where gh reads and writes through one endpoint, an Automation
// whose write list leaves out the github-api entry is served every recorded gh
// command that only reads (pr view, pr list, pr checks, pr diff, repo view)
// and refused at the first mutation of the rest, or at a read that needs a
// write operation, before any lookup or token; the same pool's Automation
// with the grant, and one with no write key, are served all of them. GitHub
// receives no mutation from the first.
func TestAutomationWriteGrantDecidesGitHubGraphQL(t *testing.T) {
	f := newGraphQLFixture(t)
	ops := append([]string{"graphql"}, allPullRequestOps...)
	repo, err := json.Marshal(map[string]any{"repo": "example-org/example-repo", "access": "write", "operations": ops,
		"labels": []string{"preview"}, "pullRequestPrefixes": []string{"factory/"}, "poolOperations": map[string]any{"pool-agent": ops}})
	if err != nil {
		t.Fatal(err)
	}
	f.useRaw(t, `{"pools":[{"name":"pool-agent","namespace":"n","serviceAccount":"worker","identity":"cursor-automation"}],
	 "entries":[{"name":"github-api","host":"example.com","port":%[1]d,"kind":"github-api","pools":["pool-agent"],"git":{"appID":7,"installationID":42,"repos":[`+string(repo)+`]}},
	  {"name":"github","host":"git.example.com","kind":"git","pools":["pool-agent"],"git":{"appID":7,"installationID":42,
	   "repos":[{"repo":"example-org/example-repo","access":"write","refPrefixes":["refs/heads/cursor/pool-agent/"]}]}}],
	 "automations":[
	  {"id":"auto-reader","name":"reader","owner":"platform-team","entries":["github","github-api"],"write":[]},
	  {"id":"auto-writer","name":"writer","owner":"platform-team","entries":["github","github-api"],"write":["github-api"]},
	  {"id":"auto-unkeyed","name":"unkeyed","owner":"platform-team","entries":["github","github-api"]}]}`)
	f.proxy.sessions = validTokenResolver("workload-token", &brokercore.ProxyScope{VaultID: "vault-1", AgentID: "agent-uuid-1", Pool: "pool-agent", WorkloadID: "pod-uid-1", ClaimedRun: "bc-1"})
	f.proxy.adapter.Runner = automationRunsFor
	f.proxy.adapter.Entitlements = &entitlement.Cache{Source: directory{}}

	f.as(t, "reader")
	// A refused write is answered before any token is minted or GitHub is
	// asked which repository its pull request, named only by node ID, is in:
	// this is the fixture's first request, so nothing is cached.
	f.mu.Lock()
	mintedBefore, lookupsBefore := len(f.mintedFor), f.lookups
	f.mu.Unlock()
	comment := graphqlMutation("addComment", "AddCommentInput", map[string]any{"subjectId": ownPR, "body": "x"})
	code, _ := f.send(t, http.MethodPost, "/graphql", nil, comment)
	f.mu.Lock()
	mintedAfter, lookupsAfter := len(f.mintedFor), f.lookups
	f.mu.Unlock()
	if code != http.StatusForbidden || f.audit.last().Outcome != "automation_read_only" || mintedAfter != mintedBefore || lookupsAfter != lookupsBefore {
		t.Errorf("a comment by the reader: %d %q, %d tokens and %d lookups for it", code, f.audit.last().Outcome, mintedAfter-mintedBefore, lookupsAfter-lookupsBefore)
	}

	var refused int
	for _, c := range ghCommands {
		want := ""
		if slices.ContainsFunc(c.needs, httpcatalog.GitHubOperationWrites) {
			want = "automation_read_only"
			refused++
		}
		if got := f.replay(t, c.fixture); got != want {
			t.Errorf("%s as the reader (needs %v): outcome %q, want %q", c.fixture, c.needs, got, want)
		}
	}
	if refused == 0 || refused == len(ghCommands) {
		t.Fatalf("%d of %d recorded commands write: the test no longer tells reads from writes", refused, len(ghCommands))
	}
	for _, body := range f.relayed() {
		if strings.Contains(body, "mutation") {
			t.Errorf("GitHub received a mutation from the reader: %s", body)
		}
	}
	if len(f.relayed()) == 0 {
		t.Error("the reader's reads never reached GitHub")
	}

	mutations := func() (n int) {
		for _, body := range f.relayed() {
			if strings.Contains(body, "mutation") {
				n++
			}
		}
		return n
	}
	for _, who := range []string{"writer", "unkeyed"} {
		before := mutations()
		f.as(t, who)
		for _, c := range ghCommands {
			if got := f.replay(t, c.fixture); got != "" {
				t.Errorf("%s as the %s: refused %q", c.fixture, who, got)
			}
		}
		if mutations() == before {
			t.Errorf("the %s's mutations never reached GitHub", who)
		}
	}
}
