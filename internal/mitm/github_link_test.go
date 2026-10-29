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
	"github.com/Infisical/agent-vault/internal/githubapp"
	"github.com/Infisical/agent-vault/internal/httpcatalog"
)

// Repository ids the fake GitHub gives the two repositories of the entry.
const (
	appRepoID   = 4001
	otherRepoID = 4002
)

// pageFixture fronts a fake GitHub that lists pull requests a page at a time,
// naming each next page by repository id in its Link header as GitHub does.
// The entry lists two repositories, so a link can name the matched one or
// another, and a header entry on the same fake serves the same Link.
type pageFixture struct {
	client    *http.Client
	port      int // the github-api entry's port
	vendor    int // the header entry's port
	audit     *adapterAudit
	mu        sync.Mutex
	link      map[string]string // request path -> Link header, with {host} for the request's host
	withIDs   bool              // whether the token answer names the repository's id
	received  []string          // each request GitHub received but its token mints
	vendorHit int
}

func newPageFixture(t *testing.T) *pageFixture { return newPageFixtureWith(t, true) }

// newPageFixtureWith is newPageFixture where the token answer names the
// repository's id only when withIDs is set. A minted token is kept for reuse,
// so the choice is made before the first request.
func newPageFixtureWith(t *testing.T, withIDs bool) *pageFixture {
	t.Helper()
	f := &pageFixture{audit: &adapterAudit{}, link: map[string]string{}, withIDs: withIDs}
	ids := map[string]int{"example-app": appRepoID, "other-app": otherRepoID}
	github := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/app/installations/42/access_tokens" {
			var body struct {
				Repositories []string          `json:"repositories"`
				Permissions  map[string]string `json:"permissions"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			repo := map[string]any{"full_name": "example-org/" + body.Repositories[0]}
			f.mu.Lock()
			if f.withIDs {
				repo["id"] = ids[body.Repositories[0]]
			}
			f.mu.Unlock()
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"token": "ghs_syntheticpagetoken000001", "expires_at": time.Now().Add(time.Hour).Format(time.RFC3339),
				"permissions": body.Permissions, "repositories": []map[string]any{repo}})
			return
		}
		f.mu.Lock()
		f.received = append(f.received, r.Method+" "+r.URL.RequestURI())
		link := f.link[r.URL.Path]
		if r.URL.Path == "/v1/pulls" {
			f.vendorHit++
		}
		f.mu.Unlock()
		if link != "" {
			w.Header().Set("Link", strings.ReplaceAll(link, "{host}", r.Host))
		}
		w.Header().Set("Content-Type", "application/json")
		page := r.URL.Query().Get("page")
		fmt.Fprintf(w, `[{"number":%s}]`, map[bool]string{true: "1", false: "2"}[page == "" || page == "1"])
	}))
	t.Cleanup(github.Close)
	_, portText, _ := net.SplitHostPort(strings.TrimPrefix(github.URL, "https://"))
	f.port, _ = strconv.Atoi(portText)
	f.vendor = f.port + 1
	catalog, err := httpcatalog.Parse([]byte(fmt.Sprintf(`{"entries":[
	 {"name":"github-api","host":"example.com","port":%d,"kind":"github-api","pools":["pool-agent"],"git":{"appID":7,"installationID":42,"repos":[
	  {"repo":"example-org/example-app","access":"write","operations":["pr.read","pr.list"]},
	  {"repo":"example-org/other-app","access":"write","operations":["pr.read","pr.list"]}]}},
	 {"name":"vendor","host":"example.com","port":%d,"pathPrefixes":["/v1/"],"methods":["GET"],"header":"Authorization","scheme":"Bearer",
	  "placeholder":"__vault_KEY__","key":{"mount":"gatehouse","path":"vendors/x","field":"key"},"pools":["pool-agent"]}]}`, f.port, f.vendor)))
	if err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	minter := &githubapp.Minter{Signer: rsaSigner{key}, API: github.URL, Client: github.Client()}
	scope := &brokercore.ProxyScope{VaultID: "vault-1", AgentID: "agent-uuid-1", Pool: "pool-agent", WorkloadID: "pod-uid-1", VaultRole: "proxy"}
	proxyURL, roots, p := setupProxy(t, validTokenResolver("workload-token", scope), &fakeCredProvider{}, func(o *Options) {
		o.StrictCredentialProxy = true
		o.HeaderAdapter = &HeaderAdapter{Catalog: catalog, Keys: &adapterKeys{value: adapterKeyV1}, Audit: f.audit, GitTokens: minter}
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

// get sends one GET through the broker and returns the status and the answer's
// Link header values.
func (f *pageFixture) get(t *testing.T, rawURL string) (int, []string) {
	t.Helper()
	r, _ := http.NewRequest(http.MethodGet, rawURL, nil)
	r.Header.Set("Accept", "application/vnd.github+json")
	resp, err := f.client.Do(r)
	if err != nil {
		t.Fatalf("GET %s: %v (audit %+v)", rawURL, err, f.audit.all())
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, resp.Header.Values("Link")
}

func (f *pageFixture) pulls(repo string) string {
	return "https://example.com:" + strconv.Itoa(f.port) + "/repos/example-org/" + repo + "/pulls"
}

// linkFor is a Link header naming a repository's next and last pages by id.
func (f *pageFixture) linkFor(next, last int) string {
	return fmt.Sprintf(`<https://{host}/repositories/%d/pulls?per_page=1&page=2>; rel="next", <https://{host}/repositories/%d/pulls?per_page=1&page=5>; rel="last"`, next, last)
}

// The next page GitHub names by repository id goes back through the route the
// first request took: the Link a worker's client follows names the repository
// as the request did, the follow-up is matched, authorized and audited like
// any request, and it is the same repository's list.
func TestGitHubAPIPaginationFollowsTheMatchedRepository(t *testing.T) {
	f := newPageFixture(t)
	f.link["/repos/example-org/example-app/pulls"] = f.linkFor(appRepoID, appRepoID)
	code, links := f.get(t, f.pulls("example-app")+"?per_page=1")
	host := "example.com:" + strconv.Itoa(f.port)
	want := fmt.Sprintf(`<https://%[1]s/repos/example-org/example-app/pulls?per_page=1&page=2>; rel="next", <https://%[1]s/repos/example-org/example-app/pulls?per_page=1&page=5>; rel="last"`, host)
	if code != http.StatusOK || len(links) != 1 || links[0] != want {
		t.Fatalf("first page: %d, Link %q, want %q (audit %+v)", code, links, want, f.audit.all())
	}
	next := links[0][1:strings.Index(links[0], ">")]
	if code, _ := f.get(t, next); code != http.StatusOK {
		t.Fatalf("next page %s: %d", next, code)
	}
	last := f.audit.last()
	if last.Binding != "github-api/example-org/example-app" || last.Operation != "pr.list" || last.Outcome != "completed" || last.Status != http.StatusOK {
		t.Errorf("the next page's audit row: %+v", last)
	}
	f.mu.Lock()
	received := append([]string(nil), f.received...)
	f.mu.Unlock()
	if len(received) != 2 || received[1] != "GET /repos/example-org/example-app/pulls?page=2&per_page=1" {
		t.Errorf("GitHub received %q, want the second page of the matched repository", received)
	}
}

// A page is never pointed at a repository the request did not match. A link
// naming another repository's id, even one the entry lists, is left as GitHub
// wrote it and is refused when followed; only the link naming the matched
// repository is rewritten.
func TestGitHubAPIPaginationNeverRepointsToAnotherRepository(t *testing.T) {
	f := newPageFixture(t)
	other := fmt.Sprintf(`<https://{host}/repositories/%d/pulls?page=2>; rel="next"`, appRepoID)
	f.link["/repos/example-org/other-app/pulls"] = other
	code, links := f.get(t, f.pulls("other-app"))
	host := "example.com:" + strconv.Itoa(f.port)
	if want := strings.ReplaceAll(other, "{host}", host); code != http.StatusOK || len(links) != 1 || links[0] != want {
		t.Fatalf("a link naming the other repository: %d, Link %q, want it unchanged: %q", code, links, want)
	}
	next := links[0][1:strings.Index(links[0], ">")]
	if code, _ := f.get(t, next); code != http.StatusForbidden || f.audit.last().Outcome != "unlisted" {
		t.Errorf("following it: %d, audit %q, want 403 unlisted", code, f.audit.last().Outcome)
	}

	// One response naming both: only the matched repository's link moves.
	f.link["/repos/example-org/example-app/pulls"] = f.linkFor(appRepoID, otherRepoID)
	_, links = f.get(t, f.pulls("example-app"))
	want := fmt.Sprintf(`<https://%[1]s/repos/example-org/example-app/pulls?per_page=1&page=2>; rel="next", <https://%[1]s/repositories/%d/pulls?per_page=1&page=5>; rel="last"`, host, otherRepoID)
	if len(links) != 1 || links[0] != want {
		t.Errorf("a response naming two repositories: Link %q, want %q", links, want)
	}

}

// Without the repository's id from GitHub, nothing is known to rewrite to, so a
// link is left as GitHub wrote it.
func TestGitHubAPIPaginationNeedsTheRepositoryID(t *testing.T) {
	f := newPageFixtureWith(t, false)
	f.link["/repos/example-org/example-app/pulls"] = f.linkFor(appRepoID, appRepoID)
	code, links := f.get(t, f.pulls("example-app")+"?per_page=1")
	want := strings.ReplaceAll(f.linkFor(appRepoID, appRepoID), "{host}", "example.com:"+strconv.Itoa(f.port))
	if code != http.StatusOK || len(links) != 1 || links[0] != want {
		t.Errorf("a token answer without a repository id: %d, Link %q, want it unchanged: %q", code, links, want)
	}
}

// Only a github-api entry's answers are rewritten: another entry's Link header
// reaches the worker exactly as its server wrote it, repository id and all.
func TestPaginationLinksOfOtherEntriesAreUntouched(t *testing.T) {
	f := newPageFixture(t)
	written := f.linkFor(appRepoID, appRepoID)
	f.link["/v1/pulls"] = written
	code, links := f.get(t, "https://example.com:"+strconv.Itoa(f.vendor)+"/v1/pulls")
	host := "example.com:" + strconv.Itoa(f.vendor)
	if want := strings.ReplaceAll(written, "{host}", host); code != http.StatusOK || len(links) != 1 || links[0] != want {
		t.Fatalf("a header entry's answer: %d, Link %q, want it as written: %q", code, links, want)
	}
	f.mu.Lock()
	hit := f.vendorHit
	f.mu.Unlock()
	if hit != 1 {
		t.Errorf("the vendor path was reached %d times, want once", hit)
	}
}

// Which links are rewritten, form by form.
func TestRepointLinks(t *testing.T) {
	const (
		host = "api.example.test"
		repo = "example-org/example-app"
		id   = 4001
	)
	for name, tc := range map[string]struct{ in, want string }{
		"next and last": {
			`<https://api.example.test/repositories/4001/pulls?page=2>; rel="next", <https://api.example.test/repositories/4001/pulls?page=9>; rel="last"`,
			`<https://api.example.test/repos/example-org/example-app/pulls?page=2>; rel="next", <https://api.example.test/repos/example-org/example-app/pulls?page=9>; rel="last"`,
		},
		"every parameter and a deeper path kept": {
			`<https://api.example.test/repositories/4001/actions/runs?branch=a%2Fb&per_page=50&page=3>; rel="next"`,
			`<https://api.example.test/repos/example-org/example-app/actions/runs?branch=a%2Fb&per_page=50&page=3>; rel="next"`,
		},
		"host in another case": {
			`<https://API.EXAMPLE.TEST/repositories/4001/pulls?page=2>; rel="next"`,
			`<https://API.EXAMPLE.TEST/repos/example-org/example-app/pulls?page=2>; rel="next"`,
		},
		"another repository's id":    {`<https://api.example.test/repositories/4002/pulls?page=2>; rel="next"`, ""},
		"an id with leading zeros":   {`<https://api.example.test/repositories/04001/pulls?page=2>; rel="next"`, ""},
		"an id that only starts so":  {`<https://api.example.test/repositories/40010/pulls?page=2>; rel="next"`, ""},
		"no path after the id":       {`<https://api.example.test/repositories/4001>; rel="next"`, ""},
		"another host":               {`<https://elsewhere.example.test/repositories/4001/pulls?page=2>; rel="next"`, ""},
		"a host that only starts so": {`<https://api.example.test.evil.test/repositories/4001/pulls?page=2>; rel="next"`, ""},
		"plain http":                 {`<http://api.example.test/repositories/4001/pulls?page=2>; rel="next"`, ""},
		"a relative link":            {`</repositories/4001/pulls?page=2>; rel="next"`, ""},
		"user information":           {`<https://user@api.example.test/repositories/4001/pulls?page=2>; rel="next"`, ""},
		"an encoded path":            {`<https://api.example.test/repositories/4001/pulls%2Fx?page=2>; rel="next"`, ""},
		"a fragment":                 {`<https://api.example.test/repositories/4001/pulls?page=2#x>; rel="next"`, ""},
		"a link already by name":     {`<https://api.example.test/repos/example-org/example-app/pulls?page=2>; rel="next"`, ""},
		"a path that climbs":         {`<https://api.example.test/repositories/4001/../4002/pulls?page=2>; rel="next"`, `<https://api.example.test/repos/example-org/example-app/../4002/pulls?page=2>; rel="next"`},
		"no link header at all":      {``, ""},
		"something that is no link":  {`rel="next"`, ""},
	} {
		h := http.Header{}
		if tc.in != "" {
			h.Set("Link", tc.in)
		}
		repointLinks(h, host, repo, id)
		want := tc.want
		if want == "" {
			want = tc.in
		}
		if got := h.Get("Link"); got != want {
			t.Errorf("%s:\n got %q\nwant %q", name, got, want)
		}
	}

	// An unknown id (0) rewrites nothing, and several Link headers are each read.
	h := http.Header{}
	h.Set("Link", `<https://api.example.test/repositories/4001/pulls?page=2>; rel="next"`)
	repointLinks(h, host, repo, 0)
	if got := h.Get("Link"); !strings.Contains(got, "/repositories/4001/") {
		t.Errorf("id 0: %q", got)
	}
	h = http.Header{"Link": {`<https://api.example.test/repositories/4001/pulls?page=2>; rel="next"`, `<https://api.example.test/repositories/4001/pulls?page=9>; rel="last"`}}
	repointLinks(h, host, repo, id)
	if got := h.Values("Link"); len(got) != 2 || strings.Contains(got[0]+got[1], "/repositories/") {
		t.Errorf("two Link headers: %q", got)
	}
}
