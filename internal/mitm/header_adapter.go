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
	"github.com/Infisical/agent-vault/internal/ratelimit"
	"github.com/Infisical/agent-vault/internal/requestlog"
	"github.com/Infisical/agent-vault/internal/runnerid"
)

// HeaderAdapter replaces the strict profile's per-vault services with an
// operator catalog: per-binding hosts, path prefixes and methods, a key from
// Vault injected into one header, and signed audit rows. Workers send at
// most a placeholder; the key exists only inside the broker.
type HeaderAdapter struct {
	// Catalog is read once per request, so a reloaded catalog applies to the
	// next request; an httpcatalog.Catalog or a live *httpcatalog.Source.
	Catalog interface{ Current() httpcatalog.Catalog }
	// Runner verifies Claude runner session tokens for claude-session pools,
	// and Cursor run tokens for cursor-session and cursor-automation pools
	// when it is a runnerid.Verifiers; Entitlements answers live group
	// membership. Without them, entries above T0 are refused on those pools,
	// and every entry on a cursor-automation pool, whose owner check needs
	// the directory at T0 too.
	Runner interface {
		Verify(context.Context, string) (runnerid.Session, error)
	}
	Entitlements *entitlement.Cache
	// Sessions pins each runner session to the first Pod presenting it.
	// Without it, claude-session and Cursor pools refuse every session.
	Sessions authorize.Binder
	Keys     interface {
		Get(context.Context, httpcatalog.KeyRef) (httpcatalog.Secret, error)
		Invalidate(httpcatalog.KeyRef)
	}
	Audit interface {
		Admit() error
		Record(auditchain.Event) error
	}
	// GitTokens mints repository-scoped installation tokens for git and
	// github-api entries. Without it, those requests are refused.
	GitTokens interface {
		Token(ctx context.Context, app githubapp.App, repo string, permissions githubapp.Permissions) (githubapp.Token, error)
		Invalidate(app githubapp.App, repo string, permissions githubapp.Permissions)
	}
	// BrowserTokens logs browser-session test users in. Without it, those
	// requests are refused.
	BrowserTokens interface {
		Token(context.Context, *httpcatalog.Entry) (httpcatalog.BrowserToken, error)
		Invalidate(*httpcatalog.Entry)
	}
	// GCPTokens mints per-entry Google tokens for gcp entries. Without it,
	// those requests are refused.
	GCPTokens interface {
		Token(context.Context, *httpcatalog.Entry) (httpcatalog.GCPToken, error)
		Invalidate(*httpcatalog.Entry)
	}
	// Decoys are the decoy credentials planted in worker sessions (see
	// package decoy), read per request. Without them, none is recognized.
	Decoys interface{ Current() *decoy.Set }
}

func (a *HeaderAdapter) valid() bool {
	return a != nil && a.Catalog != nil && a.Keys != nil && a.Audit != nil
}

// decoys is the decoy set in force, or nil.
func (a *HeaderAdapter) decoys() *decoy.Set {
	if a == nil || a.Decoys == nil {
		return nil
	}
	return a.Decoys.Current()
}

const placeholderMarker = "__vault_"

// adapterDeny records a refusal, with the target the caller asked for, before
// answering with its reason (refusal.go). A passing refusal answers 503 or
// 429 with Retry-After whatever status the caller chose, and the row records
// the status sent. If the row cannot be written the caller still learns
// nothing beyond "audit_unavailable".
func (p *Proxy) adapterDeny(w http.ResponseWriter, event auditchain.Event, target string, status int, outcome string) {
	p.adapterDenyAs(w, event, target, status, outcome, refusalCode(outcome), 0)
}

// adapterDenyAs is adapterDeny with the code the agent sees given apart from
// the audit outcome, and, from a rate limiter, its own wait (0 for none) in
// place of the code's fixed Retry-After.
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

// adapterRateDeny refuses a request over its workload's rate for an entry,
// with the limiter's own wait as Retry-After.
func (p *Proxy) adapterRateDeny(w http.ResponseWriter, event auditchain.Event, target string, d ratelimit.Decision) {
	p.adapterDenyAs(w, event, target, http.StatusTooManyRequests, "rate_limited", "rate_limited", d.RetryAfter)
}

// outcomeDecoy refuses a request that presented a decoy credential: proof the
// session went looking for secrets, so the row pages.
const outcomeDecoy = "decoy_credential"

// refuseDecoy refuses a request that presented a decoy credential and records
// which decoy and where: binding "decoy/<owner pool>/<name>" and the surface
// as the decision. It never forwards, and the row never holds the value. The
// caller sees the same 403 as any refusal.
func (p *Proxy) refuseDecoy(w http.ResponseWriter, event auditchain.Event, target string, m decoy.Match) {
	event.Binding, event.Decision = "decoy/"+m.Label, m.Surface
	p.adapterDeny(w, event, target, http.StatusForbidden, outcomeDecoy)
}

// refuseDecoyBody refuses a request whose body, already read, holds a decoy
// credential, and reports whether it did.
func (p *Proxy) refuseDecoyBody(w http.ResponseWriter, event auditchain.Event, target string, body []byte) bool {
	m, ok := p.adapter.decoys().Body(body)
	if ok {
		p.refuseDecoy(w, event, target, m)
	}
	return ok
}

// refuseDecoyAtProxy refuses a CONNECT or absolute-form request whose own URL
// or headers carry a decoy credential, such as one sent as the proxy
// password, and reports whether it did. scope is nil when identity was not
// established, and the row then names no pool.
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

// adapterUnauthenticatedDeny replaces the SQL audit for refusals that happen
// before identity is known, so every refusal lands in the signed trail. wait
// is a rate limiter's own wait, or 0.
func (p *Proxy) adapterUnauthenticatedDeny(w http.ResponseWriter, r *http.Request, a requestlog.Attempt, status int, wait time.Duration) {
	p.adapterIdentityDeny(w, r, a, status, "", nil, wait)
}

// adapterIdentityDeny records a refusal with the identity check that refused
// it, as a fixed code in the row's decision field ("" when none applies), and
// for a signing-key refusal the token's kid and the connection's peer.
func (p *Proxy) adapterIdentityDeny(w http.ResponseWriter, r *http.Request, a requestlog.Attempt, status int, reason string, key *brokercore.KeyDenial, wait time.Duration) {
	event := auditchain.Event{Agent: a.ActorID, PodUID: a.WorkloadID, Method: auditMethod(r.Method), Decision: reason}
	if key != nil {
		event.Kid, event.KidSHA256, event.Peer = key.Kid, key.KidSHA256, key.Peer
	}
	p.adapterDenyAs(w, event, requestedTarget(r), status, "refused", identityRefusalCode(status), wait)
}

type connectTargetKey struct{}

// withConnectTarget marks a request inside a tunnel with the tunnel's CONNECT
// target, the host and port the broker checked.
func withConnectTarget(ctx context.Context, target string) context.Context {
	return context.WithValue(ctx, connectTargetKey{}, target)
}

// requestedTarget is the host a refusal records: inside a tunnel, its CONNECT
// target rather than the Host header the client chose for this request.
func requestedTarget(r *http.Request) string {
	if target, ok := r.Context().Value(connectTargetKey{}).(string); ok {
		return target
	}
	return r.Host
}

// gitOperation names a matched git request for the audit row: "git.push"
// for the receive-pack service, "git.fetch" for upload-pack, or "" when no
// repository matched.
func gitOperation(git httpcatalog.GitRequest) string {
	switch {
	case git.Entry == nil:
		return ""
	case git.Write:
		return "git.push"
	}
	return "git.fetch"
}

// githubAPIOperation names a github-api request for the audit row: the
// repository operation its route belongs to, or "graphql" for a GraphQL
// request no route admits, so those refusals can be counted apart from other
// unlisted paths. Never the path itself.
func githubAPIOperation(api httpcatalog.GitRequest, path string) string {
	if api.Operation != "" {
		return api.Operation
	}
	if path == "/graphql" || path == "/api/graphql" {
		return "graphql"
	}
	return ""
}

func auditMethod(m string) string {
	switch m {
	case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE":
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
	deny := func(status int, outcome string) { p.adapterDeny(w, event, target, status, outcome) }
	if scope == nil || scope.AgentID == "" || scope.UserID != "" {
		deny(http.StatusForbidden, "authentication")
		return
	}
	// A decoy anywhere in the URL or headers is refused before routing, so
	// every entry kind, and a host or path no entry lists, is covered.
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
	catalog := a.Catalog.Current()
	// Every matched entry passes the authorization model before any credential
	// is fetched: pool ceiling, then the verified requester's entitlements.
	refused := func(entry *httpcatalog.Entry, err error) bool {
		if err != nil || entry == nil {
			return false
		}
		if outcome := p.authorize(r.Context(), scope, entry, &event); outcome != "" {
			event.Binding = entry.Name
			deny(http.StatusForbidden, outcome)
			return true
		}
		return false
	}
	if git, ok, err := catalog.GitMatch(host, port, r.Method, r.URL.Path, r.URL.RawQuery, scope.Pool); ok {
		event.Operation = gitOperation(git)
		if !refused(git.Entry, err) {
			p.forwardGit(w, r, target, scope, event, git, err)
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
		// A code-returning route also needs the git entry it relies on to
		// authorize this requester, so it never reaches past a clone. That
		// second check runs last and overwrites the event's tier, decision and
		// groups, so a files or compare audit row names the github-api binding
		// with the git entry's tier and groups. That is intended: both entries
		// admitted the request, and the git entry is what guards the code.
		if !refused(api.Entry, err) && (api.CloneEntry == nil || !refused(api.CloneEntry, nil)) {
			p.forwardGitHubAPI(w, r, target, scope, event, api, err)
		}
		return
	}
	if browser, ok, err := catalog.BrowserMatch(host, port, r.Method, r.URL.Path, scope.Pool); ok {
		if !refused(browser.Entry, err) {
			p.forwardBrowser(w, r, target, scope, event, browser, err)
		}
		return
	}
	if gcp, ok, err := catalog.GCPMatch(host, port, r.Method, r.URL.Path, scope.Pool); ok {
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
	if r.URL.IsAbs() || (r.Host != target && r.Host != expected) || r.URL.User != nil || r.URL.Fragment != "" || r.URL.RawPath != "" ||
		unsafePath(r.URL.Path) || strings.Contains(r.URL.RawQuery, placeholderMarker) || r.Header.Get("Upgrade") != "" ||
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") || r.Header.Get("Content-Encoding") != "" || len(r.Trailer) > 0 {
		deny(http.StatusBadRequest, "request_shape")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, entry.MaxRequestBytes+1))
	// A model API's body quotes whatever the agent read, so only its headers
	// and URL count as presenting a decoy.
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
		// Keys go only in the catalog header; a placeholder elsewhere would
		// reach the vendor verbatim.
		deny(http.StatusBadRequest, "placeholder_misplaced")
		return
	case entry.CheckRequestFields(r.URL.Path, r.URL.RawQuery, r.Header.Values("Content-Type"), body) != nil:
		// A limited parameter (a Slack channel) missing, repeated, placed
		// twice or not listed, or a key the method does not take.
		deny(http.StatusForbidden, "request_field")
		return
	}
	expectedCredential := entry.CallerCredential()
	forwarded := http.Header{}
	for name, values := range r.Header {
		if name == entry.Header {
			if len(values) != 1 || values[0] != expectedCredential {
				deny(http.StatusBadRequest, "credential_header")
				return
			}
			continue
		}
		for _, v := range values {
			if strings.Contains(v, placeholderMarker) {
				deny(http.StatusBadRequest, "placeholder_misplaced")
				return
			}
		}
		if entry.ForwardsHeader(name) {
			forwarded[name] = append([]string(nil), values...)
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
	secret, err := a.Keys.Get(r.Context(), entry.Key)
	if err != nil {
		deny(http.StatusServiceUnavailable, keyOutcome(err))
		return
	}
	password, pair := httpcatalog.PairPassword(secret.Value())
	if entry.BasicPair && !pair {
		// As for a key no header may carry, only rewriting the stored value
		// clears this, so the refusal is lasting.
		deny(http.StatusServiceUnavailable, "key_not_basic_pair")
		return
	}
	outURL := &url.URL{Scheme: "https", Host: target, Path: r.URL.Path, RawQuery: r.URL.RawQuery}
	out, err := http.NewRequestWithContext(r.Context(), r.Method, outURL.String(), bytes.NewReader(body))
	if err != nil {
		deny(http.StatusBadRequest, "request_shape")
		return
	}
	out.Host = expected
	out.Header = forwarded
	credential := entry.Credential(secret.Value())
	out.Header.Set(entry.Header, credential)
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
	values := map[string]string{"key": secret.Value(), "credential": credential}
	if entry.BasicUser {
		// The encoded user name alone, as a vendor might echo it.
		values["basic"] = strings.TrimPrefix(credential, "Basic ")
	}
	if entry.BasicPair {
		// The password alone; the encoded pair is already one of the key's
		// screened encodings. The user half is usually a public key, so it is
		// not screened.
		values["password"] = password
	}
	needles := secretRepresentations(values)
	p.relayScreened(w, out, needles, entry.MaxResponseBytes, finish, func(*http.Response) {
		// The vendor may have rotated or revoked the key; read the newest next.
		a.Keys.Invalidate(entry.Key)
	}, nil)
}

// relayScreened sends out upstream and streams the response back, refusing
// compressed or upgraded responses and any that carry a needle. rejected runs
// on a 401 or 403 and may look at the response to decide what it means. tooLarge, when set, reports that the request body was cut
// off at its limit.
func (p *Proxy) relayScreened(w http.ResponseWriter, out *http.Request, needles [][]byte, limit int64, finish func(int, string), rejected func(*http.Response), tooLarge func() bool) {
	resp, err := p.upstream.RoundTrip(out)
	if err != nil {
		if tooLarge != nil && tooLarge() {
			finish(http.StatusRequestEntityTooLarge, "request_too_large")
			refuseWith(w, http.StatusRequestEntityTooLarge, "request_too_large")
			return
		}
		finish(http.StatusBadGateway, "upstream_error")
		http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	p.relayResponse(w, resp, needles, limit, finish, rejected)
}

// relayResponse streams an upstream response back as relayScreened does, and
// closes it.
func (p *Proxy) relayResponse(w http.ResponseWriter, resp *http.Response, needles [][]byte, limit int64, finish func(int, string), rejected func(*http.Response)) {
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		rejected(resp)
	}
	encoding := resp.Header.Get("Content-Encoding")
	if resp.Header.Get("Upgrade") != "" || (encoding != "" && encoding != "identity") || headersContain(resp.Header, needles) {
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
	outcome := screenedCopy(w, resp.Body, needles, limit)
	finish(resp.StatusCode, outcome)
	if outcome != "completed" {
		// The status line is already sent; abort the connection so the worker
		// sees a truncated response rather than a clean end.
		panic(http.ErrAbortHandler)
	}
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

// screenedCopy streams the body, flushing each chunk for server-sent events.
// It holds back only a tail that could be the start of the key, so a key
// split across reads is still seen before any part of it reaches the worker,
// while ordinary events pass through at once.
func screenedCopy(w http.ResponseWriter, body io.Reader, needles [][]byte, limit int64) string {
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
			if release := len(pending) - partialSuffix(pending, needles); release > 0 {
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

// partialSuffix is the length of the longest tail of data that is a proper
// prefix of some needle.
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
