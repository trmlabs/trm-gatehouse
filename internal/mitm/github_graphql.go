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
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Infisical/agent-vault/internal/auditchain"
	"github.com/Infisical/agent-vault/internal/authorize"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/githubapp"
	"github.com/Infisical/agent-vault/internal/httpcatalog"
)

// graphqlPermissions is every GraphQL token's base scope: pull requests and no contents, since below a mapped field GraphQL can reach files and history that only a git entry grants.
// Ready and create carry contents and read back only id, URL, number and draft state; a check status read does too, only for a pool that may clone the repository.
var graphqlPermissions = githubapp.Permissions{PullRequests: "write"}

// forwardGitHubGraphQL serves POST /graphql on a github-api host: the request is parsed into repository operations so one catalog decides REST and GraphQL alike.
// Node IDs are resolved to their repository by the broker's own lookup before anything is sent, and any failed lookup refuses.
func (p *Proxy) forwardGitHubGraphQL(w http.ResponseWriter, r *http.Request, target, host string, port int, scope *brokercore.ProxyScope, event auditchain.Event,
	catalog httpcatalog.Catalog, granted []httpcatalog.GitRequest) {
	a := p.adapter
	// Every row names one operation: "graphql" until the request is parsed, then the write a mutation makes.
	event.Operation = "graphql"
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
	// GraphQL is opt-in per repository, so a REST catalog entry does not widen.
	var optedIn []httpcatalog.GitRequest
	for _, g := range granted {
		if g.Repo.Allows("graphql") {
			optedIn = append(optedIn, g)
		}
	}
	if len(optedIn) == 0 {
		p.attribute(r.Context(), scope, &event)
		deny(http.StatusForbidden, "unlisted")
		return
	}
	granted = optedIn
	// Only entries the request passes authorization for are considered, before any token is minted or GitHub asked; the first authorizes into the logged event, so even a refused row names the requester.
	var authorized []httpcatalog.GitRequest
	for _, g := range granted {
		probe := event
		if _, outcome := p.authorize(r.Context(), scope, g.Entry, &probe); outcome == "" {
			authorized = append(authorized, g)
		}
	}
	// authorizeInto runs the authorization model into the logged event and reports false when the entry does not authorize; who is the requester it last authorized (ForRequester).
	var who authorize.Requester
	authorizeInto := func(entry *httpcatalog.Entry) bool {
		requester, outcome := p.authorize(r.Context(), scope, entry, &event)
		if outcome != "" {
			event.Binding = entry.Name
			deny(http.StatusForbidden, outcome)
			return false
		}
		who = requester
		return true
	}
	if len(authorized) == 0 {
		if authorizeInto(granted[0].Entry) {
			// Authorization changed since the filter ran: refuse anyway, with a row.
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
	event.Operation = req.AuditOperation()
	event.Route = "graphql"
	if req.Answer != nil {
		p.answerGitHubGraphQL(w, event, authorized[0].Entry, req.Answer)
		return
	}
	// An Automation holds a write grant per entry (Requester.MayWrite). A write is refused before any lookup or token when no candidate entry grants it; when some do, the entry finally chosen is checked again below.
	if slices.ContainsFunc(req.Operations, httpcatalog.GitHubOperationWrites) &&
		!slices.ContainsFunc(authorized, func(g httpcatalog.GitRequest) bool { return who.MayWrite(g.Entry.Name) }) {
		deny(http.StatusForbidden, "automation_read_only")
		return
	}

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
		// A file list needs the clone grant; for a request naming its repository only by node ID, repositories without it are dropped before any token.
		candidates := authorized
		if req.Code {
			candidates = nil
			for _, g := range authorized {
				probe := event
				if clone := catalog.GitHubCloneEntry(host, g.Repo.Repo, scope.Pool); clone != nil {
					if _, outcome := p.authorize(r.Context(), scope, clone, &probe); outcome == "" {
						candidates = append(candidates, g)
					}
				}
			}
			if len(candidates) == 0 {
				deny(http.StatusForbidden, "unlisted")
				return
			}
		}
		var outcome string
		if repo, outcome = p.nodesRepository(r, target, expected, candidates, req, limit); outcome != "" {
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
	api = api.ForRequester(who.BranchSegment())
	if req.Code {
		// A pull request's file list is code-adjacent: only a pool whose git entry may clone the repository, for a requester that entry authorizes.
		clone := catalog.GitHubCloneEntry(host, api.Repo.Repo, scope.Pool)
		if clone == nil {
			deny(http.StatusForbidden, "unlisted")
			return
		}
		if !authorizeInto(clone) {
			return
		}
		event.GitEntry = clone.Name
	}
	entry := api.Entry
	// The binding has exactly the REST form (<entry>/<owner>/<repo>), so alerts matching on it see GraphQL traffic too.
	event.Binding = entry.Name + "/" + api.Repo.Repo
	for _, op := range append([]string{"graphql"}, req.Operations...) {
		if !api.Repo.Allows(op) {
			deny(http.StatusForbidden, "unlisted")
			return
		}
		// An Automation with no write grant reads only: every mutation, and a read needing a write operation, is refused.
		if httpcatalog.GitHubOperationWrites(op) && !who.MayWrite(entry.Name) {
			deny(http.StatusForbidden, "automation_read_only")
			return
		}
	}
	if req.Head != "" {
		// Opening a pull request holds to REST's pr.open: head under the pool's push prefixes, base a plain branch name.
		open, _, err := catalog.GitHubAPIMatch(host, port, http.MethodPost, "/repos/"+api.Repo.Repo+"/pulls", "", scope.Pool)
		open = open.ForRequester(who.BranchSegment())
		event.Branch = auditchain.BranchField(req.Head)
		switch {
		case err != nil || !open.OpensPullRequest:
			deny(http.StatusForbidden, "unlisted")
			return
		case !headInReach(api.Repo.Repo, api.Repo.Repo, req.Head, open.HeadPrefixes):
			deny(http.StatusForbidden, "head")
			return
		case strings.Contains(req.Base, ":") || unsafeBranch(req.Base):
			deny(http.StatusBadRequest, "request_shape")
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
	// Check status needs checks and statuses read, and a check suite's workflow run needs actions read (actions.read); a request that reads none gets the pull request scope alone.
	permissions := graphqlPermissions
	if req.Checks && api.Repo.GrantsScope("checks") && api.Repo.GrantsScope("statuses") {
		permissions.Checks, permissions.Statuses = "read", "read"
	}
	if req.Actions && api.Repo.GrantsScope("actions") {
		permissions.Actions = "read"
	}
	if req.Contents != "" {
		permissions.Contents = req.Contents
	}
	// Check status hangs from a commit, and GitHub serves a pull request's
	// commits only to a token with contents read: without it the commit is
	// refused before any check field is read. Contents read also opens the
	// commit's files and history, so it is added only for a pool whose git
	// entry may clone the repository, for a requester that entry authorizes,
	// as for a file list (req.Code): the clone already reads all of that.
	// Anyone else's status read goes without it, and GitHub refuses it.
	if permissions.Checks != "" && permissions.Contents == "" {
		if clone := catalog.GitHubCloneEntry(host, api.Repo.Repo, scope.Pool); clone != nil {
			probe := event
			if _, outcome := p.authorize(r.Context(), scope, clone, &probe); outcome == "" {
				permissions.Contents = "read"
			}
		}
	}
	token, err := a.GitTokens.Token(r.Context(), app, api.Repo.Repo, permissions)
	if err != nil {
		deny(http.StatusServiceUnavailable, "token_unavailable")
		return
	}
	lookupToken := token // the node lookup needs the pull request scope only
	if permissions != graphqlPermissions {
		if lookupToken, err = a.GitTokens.Token(r.Context(), app, api.Repo.Repo, graphqlPermissions); err != nil {
			deny(http.StatusServiceUnavailable, "token_unavailable")
			return
		}
	}
	outcome, branch := p.checkGraphQLTargets(r, target, expected, app, api, lookupToken.Value(), req)
	if branch != "" {
		event.Branch = auditchain.BranchField(branch)
	}
	if outcome != "" {
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
	// The worker then holds only IDs that name their repository, which the next lookup needs.
	out.Header.Set("X-Github-Next-Global-ID", "1")
	credential := "Bearer " + token.Value()
	out.Header.Set("Authorization", credential)
	out.Header.Set("Accept-Encoding", "identity")

	admitted := event
	admitted.Event, admitted.Outcome = auditchain.EventHTTPRequest, "admitted"
	if err := a.Audit.Record(admitted); err != nil {
		refuse(w, "audit_unavailable")
		return
	}
	admittedAt := time.Now()
	// GitHub answers 200 with a top-level "errors" array when it refuses part
	// of a query, and gh fails on it, so the row says so: outcome graphql_error,
	// with each error's type and path (never its message).
	scan := newGraphQLErrorScan()
	finish := func(status int, outcome string) {
		outcome, cause := splitOutcome(outcome)
		done := event
		done.Event, done.Outcome, done.Cause, done.Status = auditchain.EventHTTPResponse, outcome, cause, status
		done.Duration = time.Since(admittedAt).Milliseconds()
		if summary, ok := scan.result(); ok && outcome == "completed" {
			done.Outcome, done.GraphQLErrors = "graphql_error", summary
		}
		_ = a.Audit.Record(done)
	}
	needles := secretRepresentations(map[string]string{"token": token.Value(), "credential": credential})
	rejected := func(*http.Response) { a.GitTokens.Invalidate(app, api.Repo.Repo, permissions) }
	var screen responseHook
	if req.Write == "" {
		screen = p.screenResponse("graphql", event)
	}
	p.relayScreenedAs(w, out, needles, entry.MaxResponseBytes, finish, rejected, nil, chainAdjust(func(resp *http.Response) {
		if resp.StatusCode == http.StatusOK {
			resp.Body = scan.tee(resp.Body)
		}
	}, screen))
}

// answerGitHubGraphQL answers gh's schema feature detection without reaching GitHub.
func (p *Proxy) answerGitHubGraphQL(w http.ResponseWriter, event auditchain.Event, entry *httpcatalog.Entry, answer []byte) {
	event.Binding = entry.Name
	admitted := event
	admitted.Event, admitted.Outcome = auditchain.EventHTTPRequest, "admitted"
	if err := p.adapter.Audit.Record(admitted); err != nil {
		refuse(w, "audit_unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(answer)
	event.Event, event.Outcome, event.Status = auditchain.EventHTTPResponse, "answered", http.StatusOK
	_ = p.adapter.Audit.Record(event)
}

// lookupStatus is the status a refused target answers with: 503 when GitHub could not be asked, 400 for a label outside the list, 403 otherwise.
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

func targetOutcomeFor(req httpcatalog.GitHubGraphQL) string {
	for _, t := range req.Targets {
		if t.Kind == httpcatalog.TargetRepository {
			return "unlisted" // a repository to open a pull request in, as REST's
		}
	}
	for _, op := range req.Operations {
		if op == "pr.comment" {
			return "comment_target"
		}
	}
	return "pull_request_target"
}

// nodesRepository finds the one repository a request's node IDs belong to among the pool's repositories granting every operation. The ID's repository database ID is only a hint for which token to check with; checkGraphQLTargets confirms every ID.
// An ID naming no such repository, or IDs naming more than one, refuse.
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
		// An entry's rate limit is charged before the broker asks GitHub; a known ID costs none.
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

// nodeRepositoryID reads the repository database ID from a current-format "PR_" or "LA_" node ID (base64url MessagePack [0, repository ID, object ID]); older IDs carry no repository and are refused.
func nodeRepositoryID(id string) (int64, bool) {
	prefix, payload, ok := strings.Cut(id, "_")
	if !ok || prefix != "PR" && prefix != "LA" && prefix != "R" || len(payload) > 64 {
		return 0, false
	}
	// A repository's own ID is [0, repository ID]; the others carry an object
	// ID after it.
	header := byte(0x93)
	if prefix == "R" {
		header = 0x92
	}
	data, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil || len(data) < 3 || data[0] != header || data[1] != 0x00 {
		return 0, false
	}
	repo, rest, ok := msgpackUint(data[2:])
	if !ok || repo == 0 {
		return 0, false
	}
	if prefix != "R" {
		if _, rest, ok = msgpackUint(rest); !ok {
			return 0, false
		}
	}
	if len(rest) != 0 {
		return 0, false
	}
	return repo, true
}

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

// repositoryDatabaseID is a granted repository's database ID, read once and kept for an hour.
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

type nodeFact struct {
	Type     string // "PullRequest", "Label" or "Repository"
	Repo     string // owner/name: the node's repository, or the repository itself
	HeadRepo string // a pull request's head repository
	HeadRef  string // a pull request's head branch
	Name     string // a label's name
}

// nodesLookup reads what each node is with the request's repository token; a node outside that repository comes back empty.
const nodesLookup = `query($ids: [ID!]!) { nodes(ids: $ids) { __typename ` +
	`... on PullRequest { headRefName repository { nameWithOwner } headRepository { nameWithOwner } } ` +
	`... on Label { name repository { nameWithOwner } } ` +
	`... on Repository { nameWithOwner } } }`

// checkGraphQLTargets confirms every node ID with GitHub (a pull request in the repository, with its head in reach for a write, or a listed label) and returns the refusal outcome or "", plus the first written pull request's head branch.
func (p *Proxy) checkGraphQLTargets(r *http.Request, target, host string, app githubapp.App, api httpcatalog.GitRequest, token string, req httpcatalog.GitHubGraphQL) (string, string) {
	if len(req.Targets) == 0 {
		return "", ""
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
					Type          string `json:"__typename"`
					HeadRef       string `json:"headRefName"`
					Name          string `json:"name"`
					NameWithOwner string `json:"nameWithOwner"` // a repository's own
					Repository    *struct {
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
			return "target_lookup", ""
		}
		for i, n := range reply.Data.Nodes {
			repo := ""
			switch {
			case n == nil:
			case n.Type == "Repository":
				repo = n.NameWithOwner
			case n.Repository != nil:
				repo = n.Repository.NameWithOwner
			}
			if repo == "" {
				continue // not visible to this repository's token: refused below
			}
			f := nodeFact{Type: n.Type, Repo: repo, HeadRef: n.HeadRef, Name: n.Name}
			if n.HeadRepository != nil {
				f.HeadRepo = n.HeadRepository.NameWithOwner
			}
			facts[missing[i]] = f
			p.graphql.storeNode(target, missing[i], f)
		}
	}
	var branch string
	for _, t := range req.Targets {
		f, ok := facts[t.ID]
		inRepo := ok && strings.EqualFold(f.Repo, api.Repo.Repo)
		switch t.Kind {
		case httpcatalog.TargetLabel:
			if !inRepo || f.Type != "Label" || !containsString(api.Repo.Labels, f.Name) {
				return "request_shape", branch
			}
		case httpcatalog.TargetRepository:
			if !inRepo || f.Type != "Repository" {
				return "unlisted", branch
			}
		case httpcatalog.TargetPullRequestWrite:
			if inRepo && f.Type == "PullRequest" && branch == "" {
				branch = f.HeadRef
			}
			if !inRepo || f.Type != "PullRequest" || !headInReach(api.Repo.Repo, f.HeadRepo, f.HeadRef, api.HeadPrefixes) {
				return targetOutcomeFor(req), branch
			}
		default:
			if !inRepo || f.Type != "PullRequest" {
				return "pull_request_target", branch
			}
		}
	}
	return "", branch
}

// githubGraphQL makes one of the broker's own GraphQL reads; ok needs a 200 with data, and per-node errors leave that node null.
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

// graphqlLookups caches node facts for five minutes (a renamed label keeps its old name that long) and repository database IDs for an hour.
// Only answers GitHub gave are kept and each map is bounded, so a flood of IDs costs lookups, not memory.
type graphqlLookups struct {
	mu    sync.Mutex
	nodes map[nodeKey]cachedNode
	repos map[repositoryKey]cachedRepository
}

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

// makeRoom keeps a full map under limit by dropping expired entries among the first graphqlCacheSweep it visits, else one entry.
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
