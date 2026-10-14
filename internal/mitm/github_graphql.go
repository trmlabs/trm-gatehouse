package mitm

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Infisical/agent-vault/internal/auditchain"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/githubapp"
	"github.com/Infisical/agent-vault/internal/httpcatalog"
)

// graphqlPermissions is every GraphQL token's scope: pull requests, and no
// contents. Below a mapped field GraphQL can reach a repository's files and
// history, which only a git entry grants; without contents GitHub refuses
// those fields. (REST's pull request token carries contents read for opening
// pull requests, which GraphQL here never does.)
var graphqlPermissions = githubapp.Permissions{PullRequests: "write"}

// forwardGitHubGraphQL serves POST /graphql on a github-api host. The request
// is parsed and mapped to repository operations (httpcatalog
// ParseGitHubGraphQL), so one catalog decides REST and GraphQL alike: the
// repository must be listed for the pool and grant every operation, and a
// mutation's pull request must be in reach exactly as for a REST write. Node
// IDs are resolved to their repository with the broker's own lookup before
// anything is sent, and any failed lookup refuses. GitHub receives the
// rebuilt request with a token minted for that one repository.
func (p *Proxy) forwardGitHubGraphQL(w http.ResponseWriter, r *http.Request, target, host string, port int, scope *brokercore.ProxyScope, event auditchain.Event,
	catalog httpcatalog.Catalog, granted []httpcatalog.GitRequest) {
	a := p.adapter
	deny := func(status int, outcome string) { p.adapterDeny(w, event, target, status, outcome) }
	var releases []func()
	switch {
	case len(granted) == 0:
		deny(http.StatusForbidden, "pool")
		return
	case r.Method != http.MethodPost:
		deny(http.StatusMethodNotAllowed, "method")
		return
	case a.GitTokens == nil:
		deny(http.StatusServiceUnavailable, "token_unavailable")
		return
	}
	// GraphQL is opt-in per repository (the graphql operation), so a catalog
	// entry written for REST does not widen when the broker serves GraphQL.
	var optedIn []httpcatalog.GitRequest
	for _, g := range granted {
		if g.Repo.Allows("graphql") {
			optedIn = append(optedIn, g)
		}
	}
	if len(optedIn) == 0 {
		deny(http.StatusForbidden, "unlisted")
		return
	}
	granted = optedIn
	// Only entries the request passes authorization for are considered,
	// before any token is minted or GitHub asked (the rule forwardCatalog
	// states for every credential). The first one authorizes into the logged
	// event straight away, so even a refused request's row names the
	// requester; the entry finally chosen authorizes into it again below.
	var authorized []httpcatalog.GitRequest
	for _, g := range granted {
		probe := event
		if p.authorize(r.Context(), scope, g.Entry, &probe) == "" {
			authorized = append(authorized, g)
		}
	}
	// authorizeInto runs the authorization model into the event this request
	// logs, so its rows name the requester, tier and decision as REST rows do.
	// It refuses (and reports false) when the entry does not authorize.
	authorizeInto := func(entry *httpcatalog.Entry) bool {
		if outcome := p.authorize(r.Context(), scope, entry, &event); outcome != "" {
			event.Binding = entry.Name
			deny(http.StatusForbidden, outcome)
			return false
		}
		return true
	}
	if len(authorized) == 0 {
		if authorizeInto(granted[0].Entry) {
			// Authorization changed since the filter ran: refuse anyway, with
			// a row, rather than answer with nothing.
			deny(http.StatusForbidden, "refused")
		}
		return
	}
	if !authorizeInto(authorized[0].Entry) {
		return
	}
	expected := hostHeaderForScheme("https", target)
	if r.URL.IsAbs() || (r.Host != target && r.Host != expected) || r.URL.User != nil || r.URL.Fragment != "" || r.URL.RawPath != "" ||
		r.URL.RawQuery != "" || r.Header.Get("Upgrade") != "" || r.Header.Get("Content-Encoding") != "" || len(r.Trailer) > 0 ||
		!strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		deny(http.StatusBadRequest, "request_shape")
		return
	}
	switch r.Header.Get("Authorization") {
	case "", "token " + githubTokenPlaceholder, "Bearer " + githubTokenPlaceholder:
	default:
		deny(http.StatusBadRequest, "credential_header")
		return
	}
	var sizeLimit int64
	for _, g := range granted {
		sizeLimit = max(sizeLimit, g.Entry.MaxRequestBytes)
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, sizeLimit+1))
	switch {
	case err != nil:
		deny(http.StatusBadRequest, "request_shape")
		return
	case int64(len(body)) > sizeLimit:
		deny(http.StatusRequestEntityTooLarge, "request_too_large")
		return
	case bytes.Contains(body, []byte(placeholderMarker)):
		deny(http.StatusBadRequest, "placeholder_misplaced")
		return
	}
	req, err := httpcatalog.ParseGitHubGraphQL(body)
	if err != nil {
		var refusal *httpcatalog.GraphQLError
		if !errors.As(err, &refusal) {
			refusal = httpcatalog.ErrGraphQLShape
		}
		deny(refusal.Status, refusal.Outcome)
		return
	}
	if req.Answer != nil {
		p.answerGitHubGraphQL(w, event, authorized[0].Entry, req.Answer)
		return
	}

	// The rate limit applies before any lookup too, per entry as for REST.
	limited := map[string]bool{}
	limit := func(name string) bool {
		if limited[name] {
			return true
		}
		enf := p.rateLimit.EnforceProxy(r.Context(), proxyLimitActor(scope), name)
		if !enf.Allowed {
			return false
		}
		limited[name] = true
		releases = append(releases, enf.Release)
		return true
	}
	defer func() {
		for _, release := range releases {
			release()
		}
	}()

	repo := req.Repo
	if repo == "" {
		var outcome string
		if repo, outcome = p.nodesRepository(r, target, expected, authorized, req, limit); outcome != "" {
			deny(lookupStatus(outcome), outcome)
			return
		}
	}
	api, err := catalog.GitHubAPIRepository(host, port, repo, scope.Pool)
	switch {
	case errors.Is(err, httpcatalog.ErrUnlisted):
		deny(http.StatusForbidden, "unlisted")
		return
	case err != nil:
		deny(http.StatusForbidden, "pool")
		return
	case !authorizeInto(api.Entry):
		return
	}
	entry := api.Entry
	// The binding has exactly the REST form ("<entry>/<owner>/<repo>"), so
	// alerts and dashboards that match on it see GraphQL traffic too. The
	// operation belongs in the row's operation field (req.AuditOperation).
	event.Binding = entry.Name + "/" + api.Repo.Repo
	for _, op := range append([]string{"graphql"}, req.Operations...) {
		if !api.Repo.Allows(op) {
			deny(http.StatusForbidden, "unlisted")
			return
		}
	}
	if int64(len(body)) > entry.MaxRequestBytes {
		deny(http.StatusRequestEntityTooLarge, "request_too_large")
		return
	}
	if !limit(entry.Name) {
		deny(http.StatusTooManyRequests, "rate_limited")
		return
	}
	app := githubapp.App{AppID: entry.Git.AppID, InstallationID: entry.Git.InstallationID}
	permissions := graphqlPermissions
	token, err := a.GitTokens.Token(r.Context(), app, api.Repo.Repo, permissions)
	if err != nil {
		deny(http.StatusServiceUnavailable, "token_unavailable")
		return
	}
	if outcome := p.checkGraphQLTargets(r, target, expected, app, api, token.Value(), req); outcome != "" {
		deny(lookupStatus(outcome), outcome)
		return
	}

	outURL := &url.URL{Scheme: "https", Host: target, Path: "/graphql"}
	out, err := http.NewRequestWithContext(r.Context(), http.MethodPost, outURL.String(), bytes.NewReader(req.Body))
	if err != nil {
		deny(http.StatusBadRequest, "request_shape")
		return
	}
	out.Host = expected
	for _, name := range []string{"Accept", "User-Agent", "X-Github-Api-Version"} {
		if v := r.Header.Values(name); len(v) > 0 {
			out.Header[name] = append([]string(nil), v...)
		}
	}
	// gh asks for the merge queue fields with this one feature flag.
	if r.Header.Get("GraphQL-Features") == "merge_queue" {
		out.Header.Set("GraphQL-Features", "merge_queue")
	}
	out.Header.Set("Content-Type", "application/json")
	// The worker then holds only IDs that name their repository, which the
	// next request's lookup needs (nodeRepositoryID).
	out.Header.Set("X-Github-Next-Global-ID", "1")
	credential := "Bearer " + token.Value()
	out.Header.Set("Authorization", credential)
	out.Header.Set("Accept-Encoding", "identity")

	admitted := event
	admitted.Event, admitted.Outcome = auditchain.EventHTTPRequest, "admitted"
	if err := a.Audit.Record(admitted); err != nil {
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	admittedAt := time.Now()
	finish := func(status int, outcome string) {
		done := event
		done.Event, done.Outcome, done.Status = auditchain.EventHTTPResponse, outcome, status
		done.Duration = time.Since(admittedAt).Milliseconds()
		_ = a.Audit.Record(done)
	}
	needles := secretRepresentations(map[string]string{"token": token.Value(), "credential": credential})
	rejected := func(*http.Response) { a.GitTokens.Invalidate(app, api.Repo.Repo, permissions) }
	p.relayScreened(w, out, needles, entry.MaxResponseBytes, finish, rejected, nil)
}

// answerGitHubGraphQL replies to gh's schema feature detection without
// reaching GitHub, for a pool granted any github-api repository on the host;
// event has already passed authorization for entry.
func (p *Proxy) answerGitHubGraphQL(w http.ResponseWriter, event auditchain.Event, entry *httpcatalog.Entry, answer []byte) {
	event.Binding = entry.Name
	admitted := event
	admitted.Event, admitted.Outcome = auditchain.EventHTTPRequest, "admitted"
	if err := p.adapter.Audit.Record(admitted); err != nil {
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(answer)
	event.Event, event.Outcome, event.Status = auditchain.EventHTTPResponse, "answered", http.StatusOK
	_ = p.adapter.Audit.Record(event)
}

// lookupStatus is the status a refused target answers with: 503 when GitHub
// could not be asked, 400 for a label outside the repository's list (as for
// REST), 403 otherwise.
func lookupStatus(outcome string) int {
	switch outcome {
	case "target_lookup":
		return http.StatusServiceUnavailable
	case "rate_limited":
		return http.StatusTooManyRequests
	case "request_shape":
		return http.StatusBadRequest
	}
	return http.StatusForbidden
}

// targetOutcomeFor names a refused node target in the audit trail, as REST
// names the same refusal.
func targetOutcomeFor(req httpcatalog.GitHubGraphQL) string {
	for _, op := range req.Operations {
		if op == "pr.comment" {
			return "comment_target"
		}
	}
	return "pull_request_target"
}

// nodesRepository finds the one repository a request's node IDs belong to,
// among the pool's repositories that grant every operation it needs. Each ID
// names its repository's database ID (nodeRepositoryID); that is only a hint
// for which token to check with, and checkGraphQLTargets then confirms every
// ID with GitHub. An ID that names no such repository, or IDs naming more
// than one, refuse; with no repository granting the operations at all, the
// request is unlisted, as its REST route would be.
func (p *Proxy) nodesRepository(r *http.Request, target, host string, granted []httpcatalog.GitRequest, req httpcatalog.GitHubGraphQL, limit func(string) bool) (string, string) {
	refusal := targetOutcomeFor(req)
	var want int64
	for _, t := range req.Targets {
		id, ok := nodeRepositoryID(t.ID)
		if !ok || want != 0 && id != want {
			return "", refusal
		}
		want = id
	}
	candidates, failed := 0, false
	for _, g := range granted {
		allowed := true
		for _, op := range req.Operations {
			allowed = allowed && g.Repo.Allows(op)
		}
		if !allowed {
			continue
		}
		candidates++
		// An entry's rate limit is charged before the broker asks GitHub on
		// its behalf, and for the entry that matches; a known ID costs none.
		if _, known := p.graphql.repository(repositoryKey{g.Entry.Git.InstallationID, g.Repo.Repo}); !known && !limit(g.Entry.Name) {
			return "", "rate_limited"
		}
		id, ok := p.repositoryDatabaseID(r, target, host, g)
		if !ok {
			failed = true // another repository may still match
			continue
		}
		if id == want {
			if !limit(g.Entry.Name) {
				return "", "rate_limited"
			}
			return g.Repo.Repo, ""
		}
	}
	switch {
	case candidates == 0:
		return "", "unlisted" // no repository here grants the operation
	case failed:
		return "", "target_lookup" // the one that failed may have been it
	}
	return "", refusal
}

// nodeRepositoryID reads the repository database ID from a GitHub node ID of
// a pull request or label in the current format: "PR_" or "LA_" and base64url
// MessagePack [0, repository ID, object ID]. Older IDs carry no repository
// and are refused; the broker asks GitHub for current IDs on every request it
// relays, so gh holds no other kind.
func nodeRepositoryID(id string) (int64, bool) {
	prefix, payload, ok := strings.Cut(id, "_")
	if !ok || prefix != "PR" && prefix != "LA" || len(payload) > 64 {
		return 0, false
	}
	data, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil || len(data) < 4 || data[0] != 0x93 || data[1] != 0x00 {
		return 0, false
	}
	repo, rest, ok := msgpackUint(data[2:])
	if !ok || repo == 0 {
		return 0, false
	}
	if _, rest, ok = msgpackUint(rest); !ok || len(rest) != 0 {
		return 0, false
	}
	return repo, true
}

// msgpackUint reads one MessagePack unsigned integer.
func msgpackUint(b []byte) (int64, []byte, bool) {
	if len(b) == 0 {
		return 0, nil, false
	}
	switch c := b[0]; {
	case c <= 0x7f:
		return int64(c), b[1:], true
	case c == 0xcc && len(b) >= 2:
		return int64(b[1]), b[2:], true
	case c == 0xcd && len(b) >= 3:
		return int64(binary.BigEndian.Uint16(b[1:])), b[3:], true
	case c == 0xce && len(b) >= 5:
		return int64(binary.BigEndian.Uint32(b[1:])), b[5:], true
	case c == 0xcf && len(b) >= 9:
		if v := binary.BigEndian.Uint64(b[1:]); v <= 1<<62 {
			return int64(v), b[9:], true
		}
	}
	return 0, nil, false
}

// repositoryDatabaseID is a granted repository's GitHub database ID, read
// once with its own token and kept for an hour.
func (p *Proxy) repositoryDatabaseID(r *http.Request, target, host string, g httpcatalog.GitRequest) (int64, bool) {
	key := repositoryKey{g.Entry.Git.InstallationID, g.Repo.Repo}
	if id, ok := p.graphql.repository(key); ok {
		return id, true
	}
	app := githubapp.App{AppID: g.Entry.Git.AppID, InstallationID: g.Entry.Git.InstallationID}
	token, err := p.adapter.GitTokens.Token(r.Context(), app, g.Repo.Repo, graphqlPermissions)
	if err != nil {
		return 0, false
	}
	var repo struct {
		ID       int64  `json:"id"`
		FullName string `json:"full_name"`
	}
	if !p.githubGet(r, target, host, "/repos/"+g.Repo.Repo, token.Value(), &repo) || repo.ID <= 0 || !strings.EqualFold(repo.FullName, g.Repo.Repo) {
		return 0, false
	}
	p.graphql.storeRepository(key, repo.ID)
	return repo.ID, true
}

// nodeFact is what GitHub says one node is.
type nodeFact struct {
	Type     string // "PullRequest" or "Label"
	Repo     string // owner/name
	HeadRepo string // a pull request's head repository
	HeadRef  string // a pull request's head branch
	Name     string // a label's name
}

// nodesLookup reads what each node is, with the request's own repository
// token: a node outside that repository comes back empty.
const nodesLookup = `query($ids: [ID!]!) { nodes(ids: $ids) { __typename ` +
	`... on PullRequest { headRefName repository { nameWithOwner } headRepository { nameWithOwner } } ` +
	`... on Label { name repository { nameWithOwner } } } }`

// checkGraphQLTargets confirms every node ID with GitHub: a pull request in
// the repository (and, for a write, its head in reach), or a label in the
// repository that the catalog lists. It returns the refusal's outcome, or "".
func (p *Proxy) checkGraphQLTargets(r *http.Request, target, host string, app githubapp.App, api httpcatalog.GitRequest, token string, req httpcatalog.GitHubGraphQL) string {
	if len(req.Targets) == 0 {
		return ""
	}
	facts := map[string]nodeFact{}
	var missing []string
	for _, t := range req.Targets {
		if f, ok := p.graphql.node(target, t.ID); ok {
			facts[t.ID] = f
		} else if !containsString(missing, t.ID) {
			missing = append(missing, t.ID)
		}
	}
	if len(missing) > 0 {
		var reply struct {
			Data struct {
				Nodes []*struct {
					Type       string `json:"__typename"`
					HeadRef    string `json:"headRefName"`
					Name       string `json:"name"`
					Repository *struct {
						NameWithOwner string `json:"nameWithOwner"`
					} `json:"repository"`
					HeadRepository *struct {
						NameWithOwner string `json:"nameWithOwner"`
					} `json:"headRepository"`
				} `json:"nodes"`
			} `json:"data"`
		}
		status, ok := p.githubGraphQL(r, target, host, token, nodesLookup, map[string]any{"ids": missing}, &reply)
		if status == http.StatusUnauthorized {
			p.adapter.GitTokens.Invalidate(app, api.Repo.Repo, graphqlPermissions)
		}
		if !ok || len(reply.Data.Nodes) != len(missing) {
			return "target_lookup"
		}
		for i, n := range reply.Data.Nodes {
			if n == nil || n.Repository == nil {
				continue // not visible to this repository's token: refused below
			}
			f := nodeFact{Type: n.Type, Repo: n.Repository.NameWithOwner, HeadRef: n.HeadRef, Name: n.Name}
			if n.HeadRepository != nil {
				f.HeadRepo = n.HeadRepository.NameWithOwner
			}
			facts[missing[i]] = f
			p.graphql.storeNode(target, missing[i], f)
		}
	}
	for _, t := range req.Targets {
		f, ok := facts[t.ID]
		inRepo := ok && strings.EqualFold(f.Repo, api.Repo.Repo)
		switch t.Kind {
		case httpcatalog.TargetLabel:
			if !inRepo || f.Type != "Label" || !containsString(api.Repo.Labels, f.Name) {
				return "request_shape"
			}
		case httpcatalog.TargetPullRequestWrite:
			if !inRepo || f.Type != "PullRequest" || !headInReach(api.Repo.Repo, f.HeadRepo, f.HeadRef, api.HeadPrefixes) {
				return targetOutcomeFor(req)
			}
		default:
			if !inRepo || f.Type != "PullRequest" {
				return "pull_request_target"
			}
		}
	}
	return ""
}

// githubGraphQL makes one of the broker's own GraphQL reads with token. ok
// needs a 200 with data; GitHub's per-node errors (a node the token cannot
// see) leave that node null.
func (p *Proxy) githubGraphQL(r *http.Request, target, host, token, query string, variables map[string]any, v any) (int, bool) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	body, err := json.Marshal(map[string]any{"query": query, "variables": variables})
	if err != nil {
		return 0, false
	}
	u := &url.URL{Scheme: "https", Host: target, Path: "/graphql"}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return 0, false
	}
	req.Host = host
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept-Encoding", "identity")
	resp, err := p.upstream.RoundTrip(req)
	if err != nil {
		return 0, false
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, err == nil && resp.StatusCode == http.StatusOK && json.Unmarshal(data, v) == nil
}

// graphqlLookups caches what the broker learned from GitHub: node facts for
// five minutes (so a renamed label keeps its old name in the check for up to
// that long) and repository database IDs for an hour. Only answers GitHub gave are kept, never a failure, and each map is
// bounded, so a flood of IDs costs lookups, not memory.
type graphqlLookups struct {
	mu    sync.Mutex
	nodes map[nodeKey]cachedNode
	repos map[repositoryKey]cachedRepository
}

// nodeKey is a node ID on one GitHub host (host:port).
type nodeKey struct{ host, id string }

type repositoryKey struct {
	installation int64
	repo         string
}

type cachedNode struct {
	fact    nodeFact
	expires time.Time
}

type cachedRepository struct {
	id      int64
	expires time.Time
}

const (
	nodeFactTTL       = 5 * time.Minute
	repositoryIDTTL   = time.Hour
	maxCachedNodes    = 100000
	maxCachedRepoIDs  = 10000
	graphqlCacheSweep = 1024 // entries examined when a full map needs room
)

func (c *graphqlLookups) node(host, id string) (nodeFact, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n, ok := c.nodes[nodeKey{host, id}]
	if !ok || time.Now().After(n.expires) {
		return nodeFact{}, false
	}
	return n.fact, true
}

func (c *graphqlLookups) storeNode(host, id string, f nodeFact) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.nodes == nil {
		c.nodes = map[nodeKey]cachedNode{}
	}
	makeRoom(c.nodes, maxCachedNodes, func(n cachedNode) time.Time { return n.expires })
	c.nodes[nodeKey{host, id}] = cachedNode{fact: f, expires: time.Now().Add(nodeFactTTL)}
}

func (c *graphqlLookups) repository(key repositoryKey) (int64, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	r, ok := c.repos[key]
	if !ok || time.Now().After(r.expires) {
		return 0, false
	}
	return r.id, true
}

func (c *graphqlLookups) storeRepository(key repositoryKey, id int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.repos == nil {
		c.repos = map[repositoryKey]cachedRepository{}
	}
	makeRoom(c.repos, maxCachedRepoIDs, func(r cachedRepository) time.Time { return r.expires })
	c.repos[key] = cachedRepository{id: id, expires: time.Now().Add(repositoryIDTTL)}
}

// makeRoom keeps a full map under limit: it drops expired entries among the
// first graphqlCacheSweep it visits, and if none had expired, one entry.
func makeRoom[K comparable, V any](m map[K]V, limit int, expires func(V) time.Time) {
	if len(m) < limit {
		return
	}
	now, seen, dropped := time.Now(), 0, false
	var first K
	for k, v := range m {
		if seen == 0 {
			first = k
		}
		if now.After(expires(v)) {
			delete(m, k)
			dropped = true
		}
		if seen++; seen >= graphqlCacheSweep {
			break
		}
	}
	if !dropped {
		delete(m, first)
	}
}
