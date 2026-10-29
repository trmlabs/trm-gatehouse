package mitm

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Infisical/agent-vault/internal/auditchain"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/httpcatalog"
)

// forwardGCP serves a gcp entry: the worker holds at most the placeholder,
// and the broker adds a token minted for this entry alone: downscoped to one
// bucket prefix, impersonating the entry's own service account, or that
// account's ID token for the entry's audience.
func (p *Proxy) forwardGCP(w http.ResponseWriter, r *http.Request, target string, scope *brokercore.ProxyScope, event auditchain.Event, entry *httpcatalog.Entry, matchErr error) {
	a := p.adapter
	if entry != nil {
		event.Binding = entry.Name
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
	if a.GCPTokens == nil {
		// An adapter built without a minter never gets one; the broker wires
		// a GCPMinter, which refuses through the token path below instead.
		p.adapterDenyAs(w, event, target, http.StatusServiceUnavailable, "token_unavailable", "broker_misconfigured", 0)
		return
	}
	expected := hostHeaderForScheme("https", target)
	if r.URL.IsAbs() || !authorityMatches(r, target) || r.URL.User != nil || r.URL.Fragment != "" ||
		unsafePath(r.URL.Path) || containsPlaceholder(r.URL.RawQuery) || r.Header.Get("Upgrade") != "" ||
		r.Header.Get("Content-Encoding") != "" || len(r.Trailer) > 0 || (isGRPC(r) && grpcCompressedRequest(r)) {
		deny(http.StatusBadRequest, "request_shape")
		return
	}
	if got := r.Header.Values("Authorization"); len(got) > 1 || (len(got) == 1 && got[0] != "Bearer "+entry.Placeholder) {
		deny(http.StatusBadRequest, "credential_header")
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
	if err == nil && p.refuseDecoyBody(w, event, target, body) {
		return
	}
	switch {
	case err != nil:
		deny(http.StatusBadRequest, "request_shape")
		return
	case int64(len(body)) > entry.MaxRequestBytes:
		deny(http.StatusRequestEntityTooLarge, "request_too_large")
		return
	case containsPlaceholder(string(body)):
		deny(http.StatusBadRequest, "placeholder_misplaced")
		return
	}
	enf := p.rateLimit.EnforceProxy(r.Context(), proxyLimitActor(scope), entry.Name)
	if !enf.Allowed {
		p.adapterRateDeny(w, event, target, enf.Decision)
		return
	}
	defer enf.Release()
	token, err := a.GCPTokens.Token(r.Context(), entry)
	if err != nil {
		deny(http.StatusServiceUnavailable, "token_unavailable")
		return
	}
	// RawPath keeps percent-encoded object names (a/b as a%2Fb) as sent.
	outURL := &url.URL{Scheme: "https", Host: target, Path: r.URL.Path, RawPath: r.URL.RawPath, RawQuery: r.URL.RawQuery}
	out, err := http.NewRequestWithContext(r.Context(), r.Method, outURL.String(), bytes.NewReader(body))
	if err != nil {
		deny(http.StatusBadRequest, "request_shape")
		return
	}
	out.Host = expected
	for name, values := range r.Header {
		if entry.GCPForwardsHeader(name) {
			out.Header[http.CanonicalHeaderKey(name)] = append([]string(nil), values...)
		}
	}
	credential := "Bearer " + token.Value()
	out.Header.Set("Authorization", credential)
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
	values := map[string]string{"token": token.Value(), "credential": credential}
	rejected := func(*http.Response) { a.GCPTokens.Invalidate(entry) }
	if entry.GCP.Audience != "" {
		// An ID token's header and claims can be rebuilt from what a service
		// echoes after decoding it; its signature cannot, so screen for that too.
		if parts := strings.Split(token.Value(), "."); len(parts) == 3 && len(parts[2]) >= 32 {
			values["signature"] = parts[2]
		}
		// A service of the operator's own answers 403 for its own denials, so
		// only a refused token (401, or gRPC Unauthenticated) mints again.
		rejected = func(resp *http.Response) {
			if resp.StatusCode == http.StatusUnauthorized || grpcCallStatus(resp) == grpcUnauthenticated {
				a.GCPTokens.Invalidate(entry)
			}
		}
	}
	needles := secretRepresentations(values)
	p.relayScreened(w, out, needles, entry.MaxResponseBytes, finish, rejected, nil)
}
