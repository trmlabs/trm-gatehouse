package mitm

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"github.com/Infisical/agent-vault/internal/authorize"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Infisical/agent-vault/internal/auditchain"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/decoy"
	"github.com/Infisical/agent-vault/internal/entitlement"
	"github.com/Infisical/agent-vault/internal/githubapp"
	"github.com/Infisical/agent-vault/internal/httpcatalog"
	"github.com/Infisical/agent-vault/internal/injection"
	"github.com/Infisical/agent-vault/internal/ratelimit"
	"github.com/Infisical/agent-vault/internal/requestlog"
	"github.com/Infisical/agent-vault/internal/runnerid"
)

// HeaderAdapter replaces the strict profile's per-vault services with an operator catalog: bindings, a Vault key injected into one header, and signed audit rows. Workers send at most a placeholder.
type HeaderAdapter struct {
	// Catalog is read per request, so a reloaded catalog applies to the next request.
	Catalog interface{ Current() httpcatalog.Catalog }
	// Runner verifies Claude runner and Cursor run tokens (a runnerid.Verifiers); Entitlements answers live group membership. Without them, entries above T0 are refused on those pools, and every entry on a cursor-automation pool.
	Runner interface {
		Verify(context.Context, string) (runnerid.Session, error)
	}
	Entitlements *entitlement.Cache
	// Sessions pins each runner session to the first Pod presenting it; without it, claude-session and Cursor pools refuse every session.
	Sessions authorize.Binder
	Keys     interface {
		Get(context.Context, httpcatalog.KeyRef) (httpcatalog.Secret, error)
		Invalidate(httpcatalog.KeyRef)
	}
	Audit interface {
		Admit() error
		Record(auditchain.Event) error
	}
	// Injection screens responses that carry outside text; nil screens nothing.
	Injection *injection.Flagger
	// GitTokens mints repository-scoped installation tokens for git and
	// github-api entries. Without it, those requests are refused.
	GitTokens interface {
		Token(ctx context.Context, app githubapp.App, repo string, permissions githubapp.Permissions) (githubapp.Token, error)
		Invalidate(app githubapp.App, repo string, permissions githubapp.Permissions)
	}
	// BrowserTokens logs browser-session test users in; without it, those requests are refused.
	BrowserTokens interface {
		Token(context.Context, *httpcatalog.Entry) (httpcatalog.BrowserToken, error)
		Invalidate(*httpcatalog.Entry)
	}
	// GCPTokens mints per-entry Google tokens; without it, gcp entries are refused.
	GCPTokens interface {
		Token(context.Context, *httpcatalog.Entry) (httpcatalog.GCPToken, error)
		Invalidate(*httpcatalog.Entry)
	}
	// Decoys are the decoy credentials planted in worker sessions (see package decoy), read per request.
	Decoys interface{ Current() *decoy.Set }
	// ClientCertificates reads the client certificates entries present upstream (see clientcert.go); without it, those entries are refused.
	ClientCertificates interface {
		Get(context.Context, httpcatalog.ClientCertificateRef) (*httpcatalog.ClientCertificate, error)
		Invalidate(httpcatalog.ClientCertificateRef)
	}
	// ClientTokens mints the access tokens of clientCredentials entries; without it, those entries are refused.
	ClientTokens interface {
		Token(context.Context, *httpcatalog.Entry) (httpcatalog.Secret, error)
		Invalidate(*httpcatalog.Entry)
	}
}

func (a *HeaderAdapter) valid() bool {
	return a != nil && a.Catalog != nil && a.Keys != nil && a.Audit != nil
}

// injection is the response screener, or nil.
func (a *HeaderAdapter) injection() *injection.Flagger {
	if a == nil {
		return nil
	}
	return a.Injection
}

// decoys is the decoy set in force, or nil.
func (a *HeaderAdapter) decoys() *decoy.Set {
	if a == nil || a.Decoys == nil {
		return nil
	}
	return a.Decoys.Current()
}

const placeholderMarker = "__vault_"

// adapterDeny records a refusal with the target the caller asked for, then answers with its reason (refusal.go). A passing refusal answers 503 or 429 with Retry-After and the row records the status sent; if the row cannot be written, the caller learns only "audit_unavailable".
func (p *Proxy) adapterDeny(w http.ResponseWriter, event auditchain.Event, target string, status int, outcome string) {
	p.adapterDenyAs(w, event, target, status, outcome, refusalCode(outcome), 0)
}

// adapterDenyAs is adapterDeny with the agent-visible code apart from the audit outcome, and a limiter's own wait in place of the fixed Retry-After.
func (p *Proxy) adapterDenyAs(w http.ResponseWriter, event auditchain.Event, target string, status int, outcome, code string, wait time.Duration) {
	code, status, kind := refusalFor(code, status)
	kind = kind.after(wait)
	event.Event, event.Outcome, event.Status = auditchain.EventDenied, outcome, status
	event.Target = auditchain.TargetField(target)
	if p.adapter.Audit.Record(event) != nil {
		code, status, kind = refusalFor("audit_unavailable", status)
	}
	writeRefusal(w, status, code, kind)
}

func (p *Proxy) adapterRateDeny(w http.ResponseWriter, event auditchain.Event, target string, d ratelimit.Decision) {
	p.adapterDenyAs(w, event, target, http.StatusTooManyRequests, "rate_limited", "rate_limited", d.RetryAfter)
}

// outcomeDecoy refuses a request that presented a decoy credential: proof the session went looking for secrets, so the row pages.
const outcomeDecoy = "decoy_credential"

// refuseDecoy records which decoy and where (binding "decoy/<owner pool>/<name>", the surface as the decision), never the value, and never forwards; the caller sees the same 403 as any refusal.
func (p *Proxy) refuseDecoy(w http.ResponseWriter, event auditchain.Event, target string, m decoy.Match) {
	event.Binding, event.Decision, event.Path = "decoy/"+m.Label, m.Surface, ""
	p.adapterDeny(w, event, target, http.StatusForbidden, outcomeDecoy)
}

func (p *Proxy) refuseDecoyBody(w http.ResponseWriter, event auditchain.Event, target string, body []byte) bool {
	m, ok := p.adapter.decoys().Body(body)
	if ok {
		p.refuseDecoy(w, event, target, m)
	}
	return ok
}

// refuseDecoyAtProxy refuses a CONNECT or absolute-form request whose URL or headers carry a decoy; scope is nil before identity, and the row then names no pool.
func (p *Proxy) refuseDecoyAtProxy(w http.ResponseWriter, r *http.Request, target string, scope *brokercore.ProxyScope) bool {
	if !p.strictCredentialProxy || !p.adapter.valid() {
		return false
	}
	m, ok := p.adapter.decoys().Request(r)
	if !ok {
		return false
	}
	event := auditchain.Event{Method: auditMethod(r.Method)}
	if scope != nil {
		event.Pool, event.Agent, event.PodUID = scope.Pool, scope.AgentID, scope.WorkloadID
	}
	p.refuseDecoy(w, event, target, m)
	return true
}

// adapterUnauthenticatedDeny puts refusals that happen before identity is known into the signed trail.
func (p *Proxy) adapterUnauthenticatedDeny(w http.ResponseWriter, r *http.Request, a requestlog.Attempt, status int, wait time.Duration) {
	p.adapterIdentityDeny(w, r, a, status, "refused", "", nil, wait)
}

// adapterIdentityDeny records the identity check that refused as a fixed code in the decision field, plus a signing-key refusal's kid and the connection's peer.
func (p *Proxy) adapterIdentityDeny(w http.ResponseWriter, r *http.Request, a requestlog.Attempt, status int, outcome, reason string, key *brokercore.KeyDenial, wait time.Duration) {
	event := auditchain.Event{Agent: a.ActorID, PodUID: a.WorkloadID, Method: auditMethod(r.Method), Decision: reason}
	if key != nil {
		event.Kid, event.KidSHA256, event.Peer = key.Kid, key.KidSHA256, key.Peer
	}
	p.adapterDenyAs(w, event, requestedTarget(r), status, outcome, identityRefusalCode(status), wait)
}

type connectTargetKey struct{}

func withConnectTarget(ctx context.Context, target string) context.Context {
	return context.WithValue(ctx, connectTargetKey{}, target)
}

// requestedTarget is the host a refusal records: inside a tunnel, its CONNECT target, not the client's Host header.
func requestedTarget(r *http.Request) string {
	if target, ok := r.Context().Value(connectTargetKey{}).(string); ok {
		return target
	}
	return r.Host
}

func gitOperation(git httpcatalog.GitRequest) string {
	switch {
	case git.Entry == nil:
		return ""
	case git.Write:
		return "git.push"
	}
	return "git.fetch"
}

// githubAPIOperation names a github-api request for the audit row: its route's operation, or "graphql" for a GraphQL request no route admits; never the path.
func githubAPIOperation(api httpcatalog.GitRequest, path string) string {
	if api.Operation != "" {
		return api.Operation
	}
	if path == "/graphql" || path == "/api/graphql" {
		return "graphql"
	}
	return ""
}

// auditPath is the path a row records, without its query; empty for a CONNECT and never recorded for a browser-session host.
func auditPath(r *http.Request) string {
	if r.Method == http.MethodConnect || r.URL == nil {
		return ""
	}
	return auditchain.PathField(r.URL.EscapedPath())
}

func auditMethod(m string) string {
	switch m {
	case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "CONNECT":
		return m
	}
	return ""
}

func newRequestID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func (p *Proxy) forwardCatalog(w http.ResponseWriter, r *http.Request, target, host string, port int, useTLS bool, scope *brokercore.ProxyScope) {
	a := p.adapter
	event := auditchain.Event{Session: newRequestID(), Method: auditMethod(r.Method)}
	if scope != nil {
		event.Pool, event.Agent, event.PodUID = scope.Pool, scope.AgentID, scope.WorkloadID
	}
	w.Header().Set("X-Request-Id", event.Session)
	// A refusal before any entry is authorized still names the run's
	// Automation, when its token verifies, as an authorized row does.
	attribute := func() { p.attribute(r.Context(), scope, &event) }
	deny := func(status int, outcome string) {
		attribute()
		p.adapterDeny(w, event, target, status, outcome)
	}
	if scope == nil || scope.AgentID == "" || scope.UserID != "" {
		deny(http.StatusForbidden, "authentication")
		return
	}
	catalog := a.Catalog.Current()
	// A web app's paths can carry one-time sign-in links, so rows for a browser-session host name no path.
	if !catalog.BrowserHost(host, port) {
		event.Path = auditPath(r)
	}
	// A decoy anywhere in the URL or headers is refused before routing, for every entry kind and any host or path.
	if m, ok := a.decoys().Request(r); ok {
		p.refuseDecoy(w, event, target, m)
		return
	}
	if err := a.Audit.Admit(); err != nil {
		deny(http.StatusServiceUnavailable, "audit_unavailable")
		return
	}
	if !useTLS {
		deny(http.StatusBadRequest, "plain_http")
		return
	}
	// The subagent registration route is the broker's own and never goes upstream.
	if subagentRoute(catalog, host, port, scope.Pool) {
		p.registerSubagent(w, r, target, scope, event, catalog)
		return
	}
	// Every matched entry passes the authorization model before any credential is fetched.
	// who is the requester the last check authorized; git and github-api requests are narrowed to that requester's own branches.
	var who authorize.Requester
	refused := func(entry *httpcatalog.Entry, err error) bool {
		if err != nil || entry == nil {
			return false
		}
		requester, outcome := p.authorize(r.Context(), scope, entry, &event)
		if outcome != "" {
			event.Binding = entry.Name
			deny(http.StatusForbidden, outcome)
			return true
		}
		who = requester
		return false
	}
	if git, ok, err := catalog.GitMatch(host, port, r.Method, r.URL.Path, r.URL.RawQuery, scope.Pool); ok {
		event.Operation = gitOperation(git)
		if err != nil {
			attribute()
		}
		if !refused(git.Entry, err) {
			p.forwardGit(w, r, target, scope, event, git.ForRequester(who.BranchSegment()), withWriteGrant(who, git, err))
		}
		return
	}
	if r.URL.Path == "/graphql" {
		if granted, ok := catalog.GitHubAPIRepos(host, port, scope.Pool); ok {
			p.forwardGitHubGraphQL(w, r, target, host, port, scope, event, catalog, granted)
			return
		}
	}
	if api, ok, err := catalog.GitHubAPIMatch(host, port, r.Method, r.URL.Path, r.URL.RawQuery, scope.Pool); ok {
		event.Operation = githubAPIOperation(api, r.URL.Path)
		event.Route, event.PullRequest = api.Route, api.PullRequest
		event.Branch = auditchain.BranchField(api.Branch)
		if api.CloneEntry != nil {
			event.GitEntry = api.CloneEntry.Name
		}
		if err != nil {
			attribute()
		}
		// A code-returning route also needs its git entry to authorize the requester, so it never reaches past a clone.
		// That second check runs last and overwrites the event's tier, decision and groups, so the row shows the git entry's.
		if !refused(api.Entry, err) && (api.CloneEntry == nil || !refused(api.CloneEntry, nil)) {
			p.forwardGitHubAPI(w, r, target, scope, event, api.ForRequester(who.BranchSegment()), withWriteGrant(who, api, err))
		}
		return
	}
	if browser, ok, err := catalog.BrowserMatch(host, port, r.Method, r.URL.Path, scope.Pool); ok {
		if err != nil {
			attribute()
		}
		if !refused(browser.Entry, err) {
			p.forwardBrowser(w, r, target, scope, event, browser, err)
		}
		return
	}
	if gcp, ok, err := catalog.GCPMatch(host, port, r.Method, r.URL.Path, scope.Pool); ok {
		if err != nil {
			attribute()
		}
		if !refused(gcp, err) {
			p.forwardGCP(w, r, target, scope, event, gcp, err)
		}
		return
	}
	entry, err := catalog.Match(host, port, r.Method, r.URL.Path, scope.Pool)
	if entry != nil {
		event.Binding, event.Operation = entry.Name, entry.Operation(r.URL.Path)
	}
	if refused(entry, err) {
		return
	}
	switch {
	case errors.Is(err, httpcatalog.ErrUnlisted):
		deny(http.StatusForbidden, "unlisted")
		return
	case errors.Is(err, httpcatalog.ErrMethod):
		deny(http.StatusMethodNotAllowed, "method")
		return
	case err != nil:
		deny(http.StatusForbidden, "pool")
		return
	}
	expected := hostHeaderForScheme("https", target)
	if r.URL.IsAbs() || !authorityMatches(r, target) || r.URL.User != nil || r.URL.Fragment != "" || r.URL.RawPath != "" ||
		unsafePath(r.URL.Path) || strings.Contains(r.URL.RawQuery, placeholderMarker) || r.Header.Get("Upgrade") != "" ||
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") || r.Header.Get("Content-Encoding") != "" || len(r.Trailer) > 0 ||
		(isGRPC(r) && grpcCompressedRequest(r)) {
		deny(http.StatusBadRequest, "request_shape")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, entry.MaxRequestBytes+1))
	if err == nil && int64(len(body)) <= entry.MaxRequestBytes && isGRPC(r) {
		var outcome string
		if body, outcome = grpcPlainMessages(body, r.Header.Get("Grpc-Encoding"), entry.MaxRequestBytes); outcome != "" {
			deny(grpcBodyStatus(outcome), outcome)
			return
		}
	}
	// A model API's body quotes what the agent read, so only its headers and URL count as presenting a decoy.
	if err == nil && !entry.Transcript && p.refuseDecoyBody(w, event, target, body) {
		return
	}
	switch {
	case err != nil:
		deny(http.StatusBadRequest, "request_shape")
		return
	case int64(len(body)) > entry.MaxRequestBytes:
		deny(http.StatusRequestEntityTooLarge, "request_too_large")
		return
	case len(body) > 0 && (r.Method == http.MethodGet || r.Method == http.MethodHead):
		deny(http.StatusBadRequest, "request_shape")
		return
	case bytes.Contains(body, []byte(placeholderMarker)):
		// Keys go only in the catalog header; a placeholder elsewhere would reach the vendor verbatim.
		deny(http.StatusBadRequest, "placeholder_misplaced")
		return
	case entry.CheckRequestFields(r.URL.Path, r.URL.RawQuery, r.Header.Values("Content-Type"), body) != nil:
		deny(http.StatusForbidden, "request_field")
		return
	case entry.CheckRequestHeaders(r.Header) != nil:
		deny(http.StatusForbidden, "request_header")
		return
	}
	// groundcover's MCP server takes every tool on one path, so the broker reads the message and forwards only allowed methods, tools and arguments (httpcatalog.CheckMCP); the row names the tool.
	if operation, mcpErr := entry.CheckMCP(r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Values("Content-Type"), body); mcpErr != nil {
		status := http.StatusForbidden
		if errors.Is(mcpErr, httpcatalog.ErrMCPShape) {
			status = http.StatusBadRequest
		}
		deny(status, mcpOutcome(mcpErr))
		return
	} else if operation != "" {
		event.Operation = operation
	}
	key, selectedUser := entry.Key, ""
	if len(entry.BasicPairs) > 0 {
		values := r.Header.Values(entry.Header)
		if len(values) != 1 {
			deny(http.StatusBadRequest, "credential_header")
			return
		}
		user, ok := entry.CallerPairUser(values[0])
		if ok {
			for _, pair := range entry.BasicPairs {
				if pair.User == user {
					key, selectedUser = pair.Key, pair.User
					event.Binding += "/" + pair.Name
					break
				}
			}
		}
		if selectedUser == "" {
			deny(http.StatusBadRequest, "credential_header")
			return
		}
	}
	expectedCredential := entry.CallerCredential()
	// A supplied public user must agree with the selected binding before
	// any credential read, and with the stored pair before forwarding.
	var sentUsers []string
	sentUserHeader := false
	forwarded := http.Header{}
	for name, values := range r.Header {
		if name == entry.Header {
			if len(values) != 1 {
				deny(http.StatusBadRequest, "credential_header")
				return
			}
			if values[0] != expectedCredential {
				user, ok := entry.CallerPairUser(values[0])
				if !ok {
					deny(http.StatusBadRequest, "credential_header")
					return
				}
				sentUsers = append(sentUsers, user)
			}
			continue
		}
		for _, v := range values {
			if strings.Contains(v, placeholderMarker) {
				deny(http.StatusBadRequest, "placeholder_misplaced")
				return
			}
		}
		if entry.PairUserHeader != "" && name == entry.PairUserHeader {
			if len(values) != 1 {
				deny(http.StatusBadRequest, "credential_header")
				return
			}
			sentUsers, sentUserHeader = append(sentUsers, values[0]), true
			continue
		}
		if entry.ForwardsHeader(name) {
			forwarded[name] = append([]string(nil), values...)
		}
	}
	for _, sent := range sentUsers {
		if selectedUser != "" && sent != selectedUser {
			deny(http.StatusBadRequest, "credential_header")
			return
		}
	}
	// One rate bucket per Pod, not per pool agent: a pool of many workers
	// shares one agent identity.
	enf := p.rateLimit.EnforceProxy(r.Context(), proxyLimitActor(scope), entry.Name)
	if !enf.Allowed {
		p.adapterRateDeny(w, event, target, enf.Decision)
		return
	}
	defer enf.Release()
	var secret httpcatalog.Secret
	switch {
	case entry.ClientCredentials != nil && a.ClientTokens == nil:
		p.adapterDenyAs(w, event, target, http.StatusServiceUnavailable, "token_unavailable", "broker_misconfigured", 0)
		return
	case entry.ClientCredentials != nil:
		// The key is an access token minted from the client in Vault; a Vault error is refused as for a stored key, a failed mint as token_unavailable.
		if secret, err = a.ClientTokens.Token(r.Context(), entry); err != nil {
			outcome := "token_unavailable"
			if errors.Is(err, httpcatalog.ErrKeyUnavailable) {
				outcome = keyOutcome(err)
			}
			deny(http.StatusServiceUnavailable, outcome)
			return
		}
	case entry.HeaderCredential():
		secret, err = a.Keys.Get(r.Context(), key)
		if err != nil {
			deny(http.StatusServiceUnavailable, keyOutcome(err))
			return
		}
	}
	user, password, pair := httpcatalog.SplitPair(secret.Value())
	if entry.BasicPair && (!pair || (selectedUser != "" && user != selectedUser)) {
		// As for a key no header may carry, only rewriting the stored value
		// clears this, so the refusal is lasting.
		deny(http.StatusServiceUnavailable, "key_not_basic_pair")
		return
	}
	for _, sent := range sentUsers {
		if sent != user {
			deny(http.StatusBadRequest, "credential_header")
			return
		}
	}
	ctx := r.Context()
	if entry.ClientCertificate != nil {
		cert, outcome := p.clientCertificate(ctx, entry)
		if outcome != "" {
			deny(http.StatusServiceUnavailable, outcome)
			return
		}
		ctx = withClientCertificate(ctx, *entry.ClientCertificate, cert)
	}
	outURL := &url.URL{Scheme: "https", Host: target, Path: r.URL.Path, RawQuery: r.URL.RawQuery}
	out, err := http.NewRequestWithContext(ctx, r.Method, outURL.String(), bytes.NewReader(body))
	if err != nil {
		deny(http.StatusBadRequest, "request_shape")
		return
	}
	out.Host = expected
	out.Header = forwarded
	credential := ""
	if entry.HeaderCredential() {
		credential = entry.Credential(secret.Value())
		out.Header.Set(entry.Header, credential)
	}
	if sentUserHeader {
		out.Header.Set(entry.PairUserHeader, user)
	}
	out.Header.Set("Accept-Encoding", "identity")
	if isGRPC(r) {
		prepareGRPC(out)
	}

	admitted := event
	admitted.Event, admitted.Outcome = auditchain.EventHTTPRequest, "admitted"
	if err := a.Audit.Record(admitted); err != nil {
		refuse(w, "audit_unavailable")
		return
	}
	admittedAt := time.Now()
	finish := func(status int, outcome string) {
		outcome, cause := splitOutcome(outcome)
		done := event
		done.Event, done.Outcome, done.Cause, done.Status = auditchain.EventHTTPResponse, outcome, cause, status
		done.Duration = time.Since(admittedAt).Milliseconds()
		_ = a.Audit.Record(done)
	}
	// A client certificate's key signs the handshake in the broker and is sent nowhere, so only a header key is screened.
	values := map[string]string{}
	if entry.HeaderCredential() {
		values["key"], values["credential"] = secret.Value(), credential
	}
	if entry.BasicUser {
		values["basic"] = strings.TrimPrefix(credential, "Basic ")
	}
	if entry.BasicPair {
		// The password alone; the user half is usually a public key and is not screened.
		values["password"] = password
	}
	needles := secretRepresentations(values)
	var screen responseHook
	if injectionOperation(event.Operation) {
		screen = p.screenResponse(event.Operation, event)
	}
	p.relayScreenedAs(w, out, needles, entry.MaxResponseBytes, finish, func(*http.Response) {
		// The vendor may have rotated or revoked the key or certificate; read the newest next.
		// A minted token is minted again, at most once a minute.
		switch {
		case entry.ClientCredentials != nil:
			a.ClientTokens.Invalidate(entry)
		case entry.HeaderCredential():
			a.Keys.Invalidate(key)
		}
		if entry.ClientCertificate != nil {
			a.ClientCertificates.Invalidate(*entry.ClientCertificate)
		}
	}, nil, screen)
}

// relayScreened sends upstream and streams the response back, refusing compressed or upgraded responses and any that carry a needle.
// rejected runs on a 401 or 403; tooLarge reports that the request body was cut off at its limit.
func (p *Proxy) relayScreened(w http.ResponseWriter, out *http.Request, needles [][]byte, limit int64, finish func(int, string), rejected func(*http.Response), tooLarge func() bool) {
	p.relayScreenedAs(w, out, needles, limit, finish, rejected, tooLarge, nil)
}

// relayScreenedAs is relayScreened with adjust changing the upstream response before its headers are screened.
func (p *Proxy) relayScreenedAs(w http.ResponseWriter, out *http.Request, needles [][]byte, limit int64, finish func(int, string), rejected func(*http.Response), tooLarge func() bool, adjust func(*http.Response)) {
	resp, err := p.upstreamFor(out).RoundTrip(out)
	if err != nil {
		if tooLarge != nil && tooLarge() {
			finish(http.StatusRequestEntityTooLarge, "request_too_large")
			refuseWith(w, http.StatusRequestEntityTooLarge, "request_too_large")
			return
		}
		if p.certificateRejected(out, err) {
			finish(http.StatusServiceUnavailable, "client_cert_rejected")
			refuse(w, "client_cert_rejected")
			return
		}
		finish(http.StatusBadGateway, upstreamFailed(err))
		http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	if adjust != nil {
		adjust(resp)
	}
	p.relayResponse(w, resp, needles, limit, finish, rejected)
}

// relayResponse streams an upstream response back as relayScreened does and closes it; over HTTP/2 it also screens the trailers, where a gRPC status arrives.
func (p *Proxy) relayResponse(w http.ResponseWriter, resp *http.Response, needles [][]byte, limit int64, finish func(int, string), rejected func(*http.Response)) {
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		rejected(resp)
	}
	h2 := resp.Request != nil && viaHTTP2(resp.Request.Context())
	grpc, _ := w.(*grpcWriter)
	encoding := resp.Header.Get("Content-Encoding")
	if resp.Header.Get("Upgrade") != "" || (encoding != "" && encoding != "identity") || headersContain(resp.Header, needles) ||
		(grpc != nil && grpcCompressedResponse(resp.Header)) {
		finish(http.StatusBadGateway, "response_refused")
		http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
		return
	}
	for name, values := range resp.Header {
		// ShouldStripResponseHeader also drops RefusalHeader, the broker's own.
		if brokercore.ShouldStripResponseHeader(name) || name == "X-Request-Id" || name == "Trailer" || name == "Content-Length" {
			continue
		}
		w.Header()[name] = append([]string(nil), values...)
	}
	w.WriteHeader(resp.StatusCode)
	var frames *grpcFrames
	if grpc != nil && framesSafe(needles) {
		frames = &grpcFrames{}
	}
	outcome := screenedCopy(w, resp.Body, needles, limit, frames)
	outcome = settleStream(outcome, resp.Request)
	if outcome == "completed" && h2 {
		outcome = relayTrailers(w, resp.Trailer, needles)
	}
	if code := grpcCallStatus(resp); grpc != nil && (code == grpcUnauthenticated || code == grpcPermissionDenied) {
		// A gRPC server refuses a token in its status, not the HTTP status.
		rejected(resp)
	}
	finish(resp.StatusCode, outcome)
	switch {
	case outcome == "completed":
	case grpc != nil && outcome != "client_gone":
		// The status is already sent; end the call with an error status so the client drops what it read.
		grpc.fail(grpcStreamStatus(outcome), "gatehouse: response "+outcome)
	default:
		// The status line is already sent; abort the connection (or HTTP/2 stream) so the worker sees a truncated response.
		// A gRPC call reclassified as client_gone lands here, not in grpc.fail, since no one is left to read a status.
		panic(http.ErrAbortHandler)
	}
}

// settleStream names a failed stream's cause: a worker that closed its request fails the upstream body read too, and the audit row must not blame the vendor.
func settleStream(outcome string, req *http.Request) string {
	if outcome == "upstream_error" && req != nil && req.Context().Err() != nil {
		return "client_gone"
	}
	return outcome
}

// relayTrailers screens an HTTP/2 response's trailers and sends them unless one carries a needle.
func relayTrailers(w http.ResponseWriter, trailer http.Header, needles [][]byte) string {
	if headersContain(trailer, needles) {
		return "secret_echo"
	}
	for name, values := range trailer {
		if !brokercore.ShouldStripResponseHeader(name) {
			w.Header()[http.TrailerPrefix+name] = append([]string(nil), values...)
		}
	}
	return "completed"
}

func unsafePath(path string) bool {
	// ";" carries path parameters that some backends strip before routing, so
	// "/v1/allowed/..;/admin" would leave the granted prefix there.
	if path == "" || !strings.HasPrefix(path, "/") || strings.Contains(path, placeholderMarker) || strings.ContainsAny(path, "\\;") || strings.Contains(path, "//") {
		return true
	}
	for _, segment := range strings.Split(path, "/") {
		if segment == "." || strings.HasPrefix(segment, "..") {
			return true
		}
	}
	return false
}

func headersContain(h http.Header, needles [][]byte) bool {
	for name, values := range h {
		if containsSecret([]byte(name), needles) {
			return true
		}
		for _, v := range values {
			if containsSecret([]byte(v), needles) {
				return true
			}
		}
	}
	return false
}

// screenedCopy streams the body, flushing each chunk and holding back only a tail that could be the start of the key, so a split key is seen before any part reaches the worker.
// With frames (a gRPC body) it releases the tail whenever the bytes end a message (framesSafe); a compressed message ends the copy.
func screenedCopy(w http.ResponseWriter, body io.Reader, needles [][]byte, limit int64, frames *grpcFrames) string {
	flusher, _ := w.(http.Flusher)
	var pending []byte
	var total int64
	buf := make([]byte, 32*1024)
	for {
		n, err := body.Read(buf)
		if n > 0 {
			total += int64(n)
			if total > limit {
				return "response_too_large"
			}
			pending = append(pending, buf[:n]...)
			if containsSecret(pending, needles) {
				return "secret_echo"
			}
			hold := partialSuffix(pending, needles)
			if frames != nil {
				if frames.advance(buf[:n]) {
					hold = 0
				}
				if frames.compressed {
					return "response_refused"
				}
			}
			if release := len(pending) - hold; release > 0 {
				if _, werr := w.Write(pending[:release]); werr != nil {
					return "client_gone"
				}
				pending = append(pending[:0], pending[release:]...)
				if flusher != nil {
					flusher.Flush()
				}
			}
		}
		if errors.Is(err, io.EOF) {
			if _, werr := w.Write(pending); werr != nil {
				return "client_gone"
			}
			return "completed"
		}
		if err != nil {
			return "upstream_error"
		}
	}
}

// partialSuffix is the length of the longest tail of data that is a proper prefix of some needle.
func partialSuffix(data []byte, needles [][]byte) int {
	longest := 0
	for _, needle := range needles {
		for k := min(len(needle)-1, len(data)); k > longest; k-- {
			if bytes.HasSuffix(data, needle[:k]) {
				longest = k
				break
			}
		}
	}
	return longest
}
