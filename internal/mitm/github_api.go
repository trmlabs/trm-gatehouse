package mitm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Infisical/agent-vault/internal/auditchain"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/githubapp"
	"github.com/Infisical/agent-vault/internal/httpcatalog"
)

// githubTokenPlaceholder is what a worker's GitHub client (gh, an SDK) may hold
// as its token. The broker replaces it; the worker never holds a real one.
const githubTokenPlaceholder = "__vault_GITHUB_TOKEN__"

// githubDownloadHosts are where GitHub redirects a log or artifact download:
// short-lived signed URLs that need no token. The broker follows one redirect
// to them itself, never one the worker names.
var githubDownloadHosts = []string{"actions.githubusercontent.com", "blob.core.windows.net"}

// readyMutation marks one pull request ready for review. GitHub has no REST
// route for it, so the broker sends this mutation, and only this one, for
// POST .../pulls/{n}/ready.
const readyMutation = `mutation($id: ID!) { markPullRequestReadyForReview(input: {pullRequestId: $id}) { pullRequest { number isDraft } } }`

// forwardGitHubAPI serves the GitHub REST routes a github-api entry lists
// (httpcatalog GitHubAPIMatch) for one listed repository, with a token minted
// for that repository and only the scope the route needs. It can never
// approve, review, merge or push: those are unlisted. A write to an existing
// pull request (comment, label, body edit, ready) goes ahead only when its
// head is under the pool's push prefixes or the repository's pull request
// prefixes, and a comment edit only on the App's own comment there.
func (p *Proxy) forwardGitHubAPI(w http.ResponseWriter, r *http.Request, target string, scope *brokercore.ProxyScope, event auditchain.Event, api httpcatalog.GitRequest, matchErr error) {
	a := p.adapter
	if api.Entry != nil {
		event.Binding = api.Entry.Name + "/" + api.Repo.Repo
	}
	deny := func(status int, outcome string) { p.adapterDeny(w, event, target, status, outcome) }
	switch {
	case errors.Is(matchErr, httpcatalog.ErrUnlisted):
		deny(http.StatusForbidden, "unlisted")
		return
	case errors.Is(matchErr, httpcatalog.ErrMethod):
		deny(http.StatusMethodNotAllowed, "method")
		return
	case matchErr != nil:
		deny(http.StatusForbidden, "pool")
		return
	}
	entry := api.Entry
	if a.GitTokens == nil {
		// Waiting does not help: only an operator (a restart, for a minter
		// wired at startup) can give the broker one.
		p.adapterDenyAs(w, event, target, http.StatusServiceUnavailable, "token_unavailable", "broker_misconfigured", 0)
		return
	}
	expected := hostHeaderForScheme("https", target)
	jsonBody := api.Write && api.Route != "ready"
	if r.URL.IsAbs() || (r.Host != target && r.Host != expected) || r.URL.User != nil || r.URL.Fragment != "" || r.URL.RawPath != "" ||
		unsafePath(r.URL.Path) || r.Header.Get("Upgrade") != "" || r.Header.Get("Content-Encoding") != "" || len(r.Trailer) > 0 ||
		(jsonBody && !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json")) {
		deny(http.StatusBadRequest, "request_shape")
		return
	}
	switch r.Header.Get("Authorization") {
	case "", "token " + githubTokenPlaceholder, "Bearer " + githubTokenPlaceholder:
	default:
		deny(http.StatusBadRequest, "credential_header")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, entry.MaxRequestBytes+1))
	switch {
	case err != nil:
		deny(http.StatusBadRequest, "request_shape")
		return
	case int64(len(body)) > entry.MaxRequestBytes:
		deny(http.StatusRequestEntityTooLarge, "request_too_large")
		return
	case bytes.Contains(body, []byte(placeholderMarker)):
		deny(http.StatusBadRequest, "placeholder_misplaced")
		return
	case !api.Write && len(body) > 0:
		deny(http.StatusBadRequest, "request_shape")
		return
	}
	// GitHub receives each write rebuilt from the checked fields, never the
	// worker's bytes, so the two cannot read it differently.
	ok := true
	switch api.Route {
	case "open-pull":
		var rebuilt []byte
		if rebuilt, ok = pullRequestFromPoolBranch(body, api.HeadPrefixes); !ok {
			deny(http.StatusForbidden, "head")
			return
		}
		body = rebuilt
	case "edit-pull", "edit-comment":
		body, ok = onlyBody(body)
	case "comment":
		body, ok = commentFrom(body, r.URL.Path)
	case "label":
		body, ok = labelsFrom(body, api.Repo.Labels)
	case "dispatch":
		body, ok = dispatchFrom(body, api.Repo.DispatchEvents)
	case "ready":
		ok = len(bytes.TrimSpace(body)) == 0 || string(bytes.TrimSpace(body)) == "{}"
	}
	if !ok {
		deny(http.StatusBadRequest, "request_shape")
		return
	}
	enf := p.rateLimit.EnforceProxy(r.Context(), proxyLimitActor(scope), entry.Name)
	if !enf.Allowed {
		p.adapterRateDeny(w, event, target, enf.Decision)
		return
	}
	defer enf.Release()
	app := githubapp.App{AppID: entry.Git.AppID, InstallationID: entry.Git.InstallationID}
	permissions := routePermissions(api.Permissions)
	token, err := a.GitTokens.Token(r.Context(), app, api.Repo.Repo, permissions)
	if err != nil {
		deny(http.StatusServiceUnavailable, "token_unavailable")
		return
	}
	var nodeID string
	if api.CommentID > 0 {
		number, ok := p.ownComment(r, target, expected, api, token.Value())
		if !ok {
			deny(http.StatusForbidden, "comment_target")
			return
		}
		api.Target = number
	}
	if api.Target > 0 {
		id, ok := p.pullRequestInScope(r, target, expected, api, token.Value(), api.Target)
		if !ok {
			deny(http.StatusForbidden, targetOutcome(api.Route))
			return
		}
		nodeID = id
	}
	outURL := &url.URL{Scheme: "https", Host: target, Path: r.URL.Path, RawQuery: api.Query}
	method := api.Method
	if api.Route == "ready" {
		body, _ = json.Marshal(map[string]any{"query": readyMutation, "variables": map[string]string{"id": nodeID}})
		outURL, method = &url.URL{Scheme: "https", Host: target, Path: "/graphql"}, http.MethodPost
	}
	var outBody io.Reader
	if method != http.MethodGet {
		outBody = bytes.NewReader(body)
	}
	out, err := http.NewRequestWithContext(r.Context(), method, outURL.String(), outBody)
	if err != nil {
		deny(http.StatusBadRequest, "request_shape")
		return
	}
	out.Host = expected
	for _, name := range []string{"Accept", "Content-Type", "User-Agent", "X-Github-Api-Version"} {
		if v := r.Header.Values(name); len(v) > 0 {
			out.Header[name] = append([]string(nil), v...)
		}
	}
	if api.Route == "ready" {
		out.Header.Set("Content-Type", "application/json")
	}
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
	finish := func(status int, outcome string) {
		done := event
		done.Event, done.Outcome, done.Status = auditchain.EventHTTPResponse, outcome, status
		done.Duration = time.Since(admittedAt).Milliseconds()
		_ = a.Audit.Record(done)
	}
	needles := secretRepresentations(map[string]string{"token": token.Value(), "credential": credential})
	rejected := func(*http.Response) { a.GitTokens.Invalidate(app, api.Repo.Repo, permissions) }
	if api.Download {
		p.relayDownload(w, out, needles, entry.MaxResponseBytes, finish, rejected)
		return
	}
	p.relayScreened(w, out, needles, entry.MaxResponseBytes, finish, rejected, nil)
}

// routePermissions is the token scope for a matched route's Permissions.
func routePermissions(scope string) githubapp.Permissions {
	switch scope {
	case "contents-write":
		return githubapp.ContentsWrite
	case "actions":
		return githubapp.ActionsRead
	case "deployments":
		return githubapp.DeploymentsRead
	case "checks":
		return githubapp.ChecksRead
	case "statuses":
		return githubapp.StatusesRead
	}
	return githubapp.PullRequestsWrite
}

// targetOutcome names a refused write to a pull request outside the pool's
// reach in the audit trail.
func targetOutcome(route string) string {
	if route == "comment" {
		return "comment_target"
	}
	return "pull_request_target"
}

// relayDownload sends a log or artifact request and, when GitHub answers with
// a redirect to one of githubDownloadHosts, fetches that URL without the token
// and relays it. Any other answer is relayed as it is.
func (p *Proxy) relayDownload(w http.ResponseWriter, out *http.Request, needles [][]byte, limit int64, finish func(int, string), rejected func(*http.Response)) {
	resp, err := p.upstream.RoundTrip(out)
	if err != nil {
		finish(http.StatusBadGateway, "upstream_error")
		http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
		return
	}
	if resp.StatusCode != http.StatusFound && resp.StatusCode != http.StatusTemporaryRedirect {
		p.relayResponse(w, resp, needles, limit, finish, rejected)
		return
	}
	location, err := url.Parse(resp.Header.Get("Location"))
	_ = resp.Body.Close()
	if err != nil || location.Scheme != "https" || location.User != nil || location.Port() != "" || !downloadHost(location.Hostname()) {
		finish(http.StatusBadGateway, "download_refused")
		http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
		return
	}
	next, err := http.NewRequestWithContext(out.Context(), http.MethodGet, location.String(), nil)
	if err != nil {
		finish(http.StatusBadGateway, "download_refused")
		http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
		return
	}
	next.Header.Set("Accept-Encoding", "identity")
	resp, err = p.upstream.RoundTrip(next)
	if err != nil {
		finish(http.StatusBadGateway, "upstream_error")
		http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	p.relayResponse(w, resp, needles, limit, finish, func(*http.Response) {})
}

func downloadHost(host string) bool {
	host = strings.ToLower(host)
	for _, h := range githubDownloadHosts {
		if strings.HasSuffix(host, "."+h) {
			return true
		}
	}
	return false
}

// ownComment reads the comment an edit targets and returns the number of the
// issue or pull request it is on, only when the App made it (so an agent edits
// only its own comments, never a person's) and it is in this repository.
func (p *Proxy) ownComment(r *http.Request, target, host string, api httpcatalog.GitRequest, token string) (int64, bool) {
	var comment struct {
		IssueURL string `json:"issue_url"`
		App      *struct {
			ID int64 `json:"id"`
		} `json:"performed_via_github_app"`
	}
	path := "/repos/" + api.Repo.Repo + "/issues/comments/" + strconv.FormatInt(api.CommentID, 10)
	if !p.githubGet(r, target, host, path, token, &comment) || comment.App == nil || comment.App.ID != api.Entry.Git.AppID {
		return 0, false
	}
	issues := "/repos/" + api.Repo.Repo + "/issues/"
	i := strings.Index(strings.ToLower(comment.IssueURL), issues)
	if i < 0 {
		return 0, false
	}
	number, err := strconv.ParseInt(comment.IssueURL[i+len(issues):], 10, 64)
	if err != nil || number <= 0 {
		return 0, false
	}
	return number, true
}

// githubGet reads one GitHub object with the request's token into v.
func (p *Proxy) githubGet(r *http.Request, target, host, path, token string, v any) bool {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	u := &url.URL{Scheme: "https", Host: target, Path: path}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return false
	}
	req.Host = host
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Accept-Encoding", "identity")
	resp, err := p.upstream.RoundTrip(req)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return err == nil && resp.StatusCode == http.StatusOK && json.Unmarshal(data, v) == nil
}

// pullRequestInScope reads the pull request a write targets, with the same
// one-repository token, and reports whether its head is a branch of this
// repository under one of HeadPrefixes (the pool's push prefixes and the
// repository's pull request prefixes), returning its node ID. An issue that
// is not a pull request, a pull request from a fork or from a branch outside
// those prefixes, or any failed read refuses the write, so an agent acts only
// on the pull requests its pool may, never on people's.
func (p *Proxy) pullRequestInScope(r *http.Request, target, host string, api httpcatalog.GitRequest, token string, number int64) (string, bool) {
	var pr struct {
		NodeID string `json:"node_id"`
		Head   struct {
			Ref  string `json:"ref"`
			Repo *struct {
				FullName string `json:"full_name"`
			} `json:"repo"`
		} `json:"head"`
	}
	path := "/repos/" + api.Repo.Repo + "/pulls/" + strconv.FormatInt(number, 10)
	if !p.githubGet(r, target, host, path, token, &pr) ||
		pr.Head.Repo == nil || !strings.EqualFold(pr.Head.Repo.FullName, api.Repo.Repo) ||
		strings.Contains(pr.Head.Ref, ":") || unsafeBranch(pr.Head.Ref) {
		return "", false
	}
	for _, prefix := range api.HeadPrefixes {
		if strings.HasPrefix(pr.Head.Ref, prefix) && len(pr.Head.Ref) > len(prefix) {
			return pr.NodeID, true
		}
	}
	return "", false
}

// onlyBody rebuilds a body edit: one JSON object with exactly one string
// field, body.
func onlyBody(data []byte) ([]byte, bool) {
	fields, ok := jsonFields(data, map[string]bool{"body": true})
	if !ok || len(fields) != 1 {
		return nil, false
	}
	var text string
	if json.Unmarshal(fields["body"], &text) != nil {
		return nil, false
	}
	out, err := json.Marshal(map[string]string{"body": text})
	return out, err == nil
}

// reviewCommentFields are the only fields a pull request review comment may
// carry. in_reply_to is left out: it would thread the comment under any review
// comment in the repository, on whichever pull request that one belongs to;
// a reply goes through its own route, whose path names the pull request.
var reviewCommentFields = map[string]bool{"body": true, "commit_id": true, "path": true, "line": true, "side": true,
	"start_line": true, "start_side": true, "subject_type": true, "position": true}

// commentFrom rebuilds a comment. An issue comment or a review reply is
// {"body"} alone; a review comment (POST /pulls/{n}/comments) may add GitHub's
// position fields, each checked for its type.
func commentFrom(data []byte, path string) ([]byte, bool) {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) < 3 || parts[len(parts)-3] != "pulls" || parts[len(parts)-1] != "comments" {
		return onlyBody(data)
	}
	fields, ok := jsonFields(data, reviewCommentFields)
	if !ok || fields["body"] == nil {
		return nil, false
	}
	out := make(map[string]any, len(fields))
	for key, raw := range fields {
		switch key {
		case "body", "commit_id", "path", "side", "start_side", "subject_type":
			var text string
			if json.Unmarshal(raw, &text) != nil {
				return nil, false
			}
			switch {
			case (key == "side" || key == "start_side") && text != "LEFT" && text != "RIGHT",
				key == "subject_type" && text != "line" && text != "file":
				return nil, false
			}
			out[key] = text
		default: // line, start_line, position
			var n int64
			if json.Unmarshal(raw, &n) != nil || n <= 0 {
				return nil, false
			}
			out[key] = n
		}
	}
	rebuilt, err := json.Marshal(out)
	return rebuilt, err == nil
}

// labelsFrom rebuilds an add-labels body: {"labels": [...]} with at least one
// label, each one the repository lists.
func labelsFrom(data []byte, allowed []string) ([]byte, bool) {
	fields, ok := jsonFields(data, map[string]bool{"labels": true})
	if !ok || len(fields) != 1 {
		return nil, false
	}
	var labels []string
	if json.Unmarshal(fields["labels"], &labels) != nil || len(labels) == 0 {
		return nil, false
	}
	for _, label := range labels {
		if !containsString(allowed, label) {
			return nil, false
		}
	}
	out, err := json.Marshal(map[string][]string{"labels": labels})
	return out, err == nil
}

// dispatchFrom rebuilds a repository dispatch: an event type the repository
// lists and an optional client_payload object.
func dispatchFrom(data []byte, allowed []string) ([]byte, bool) {
	fields, ok := jsonFields(data, map[string]bool{"event_type": true, "client_payload": true})
	if !ok {
		return nil, false
	}
	var event string
	if json.Unmarshal(fields["event_type"], &event) != nil || !containsString(allowed, event) {
		return nil, false
	}
	out := map[string]any{"event_type": event}
	if raw, ok := fields["client_payload"]; ok {
		var payload map[string]any
		if json.Unmarshal(raw, &payload) != nil || payload == nil {
			return nil, false
		}
		out["client_payload"] = payload
	}
	rebuilt, err := json.Marshal(out)
	return rebuilt, err == nil
}

// jsonFields reads one JSON object whose keys are all in allowed, each at
// most once in exactly that case, with nothing after it.
func jsonFields(data []byte, allowed map[string]bool) (map[string]json.RawMessage, bool) {
	dec := json.NewDecoder(bytes.NewReader(data))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil, false
	}
	fields := map[string]json.RawMessage{}
	seen := map[string]bool{}
	for dec.More() {
		t, err := dec.Token()
		key, isKey := t.(string)
		if err != nil || !isKey || !allowed[key] || seen[strings.ToLower(key)] {
			return nil, false
		}
		seen[strings.ToLower(key)] = true
		var raw json.RawMessage
		if dec.Decode(&raw) != nil || string(raw) == "null" {
			return nil, false
		}
		fields[key] = raw
	}
	if t, err := dec.Token(); err != nil || t != json.Delim('}') {
		return nil, false
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, false
	}
	return fields, true
}

func containsString(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// pullRequestFields are the only fields a pull request may be opened with.
var pullRequestFields = map[string]bool{"title": true, "body": true, "head": true, "base": true, "draft": true}

// pullRequestFromPoolBranch checks a create-pull-request body and returns it
// rebuilt from the checked values alone. The body must be one JSON object with
// only title, body, head and base (strings) and draft (a boolean), each at
// most once, in exactly that case; the head must be a branch of this
// repository under one of the pool's push prefixes. Anything else (an
// owner:branch head, head_repo, issue, a duplicate or unknown key, trailing
// data) is refused.
func pullRequestFromPoolBranch(body []byte, prefixes []string) ([]byte, bool) {
	dec := json.NewDecoder(bytes.NewReader(body))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil, false
	}
	fields := map[string]json.RawMessage{}
	seen := map[string]bool{}
	for dec.More() {
		t, err := dec.Token()
		key, isKey := t.(string)
		if err != nil || !isKey || !pullRequestFields[key] || seen[strings.ToLower(key)] {
			return nil, false
		}
		seen[strings.ToLower(key)] = true
		var raw json.RawMessage
		if dec.Decode(&raw) != nil {
			return nil, false
		}
		fields[key] = raw
	}
	if t, err := dec.Token(); err != nil || t != json.Delim('}') {
		return nil, false
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, false // trailing data
	}
	var req struct {
		Title, Body, Head, Base string
		Draft                   bool
	}
	out := map[string]any{}
	for key, raw := range fields {
		var err error
		switch key {
		case "title":
			err = json.Unmarshal(raw, &req.Title)
			out[key] = req.Title
		case "body":
			err = json.Unmarshal(raw, &req.Body)
			out[key] = req.Body
		case "head":
			err = json.Unmarshal(raw, &req.Head)
			out[key] = req.Head
		case "base":
			err = json.Unmarshal(raw, &req.Base)
			out[key] = req.Base
		case "draft":
			err = json.Unmarshal(raw, &req.Draft)
			out[key] = req.Draft
		}
		if err != nil || string(raw) == "null" {
			return nil, false
		}
	}
	if strings.Contains(req.Head, ":") || unsafeBranch(req.Head) {
		return nil, false
	}
	for _, prefix := range prefixes {
		if strings.HasPrefix(req.Head, prefix) && len(req.Head) > len(prefix) {
			rebuilt, err := json.Marshal(out)
			return rebuilt, err == nil
		}
	}
	return nil, false
}

// unsafeBranch refuses a branch name with a path step that could leave the
// prefix (".."), a control character or a space.
func unsafeBranch(name string) bool {
	if name == "" || strings.Contains(name, "..") {
		return true
	}
	for _, c := range name {
		if c <= ' ' || c == 0x7f {
			return true
		}
	}
	return false
}
