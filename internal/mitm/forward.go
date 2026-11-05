package mitm

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/ratelimit"
	"github.com/Infisical/agent-vault/internal/requestlog"
)

type flushingWriter struct {
	w io.Writer
	f http.Flusher
}

func (fw *flushingWriter) Write(p []byte) (int, error) {
	n, err := fw.w.Write(p)
	if n > 0 {
		fw.f.Flush()
	}
	return n, err
}

// actorFromScope returns the (type, id) pair used in request log rows.
// Empty strings when neither principal is set on the scope.
func actorFromScope(scope *brokercore.ProxyScope) (string, string) {
	if scope == nil {
		return "", ""
	}
	if scope.UserID != "" {
		return brokercore.ActorTypeUser, scope.UserID
	}
	if scope.AgentID != "" {
		return brokercore.ActorTypeAgent, scope.AgentID
	}
	return "", ""
}

// isAbsoluteForwardProxyRequest reports whether r is an absolute-form http:// request handleForward can serve.
// https:// is rejected (clients must CONNECT, no silent TLS strip), as are origin-form and other schemes.
func isAbsoluteForwardProxyRequest(r *http.Request) bool {
	if r.URL == nil {
		return false
	}
	if !strings.EqualFold(r.URL.Scheme, "http") {
		return false
	}
	if r.URL.Host == "" {
		return false
	}
	// url.ParseRequestURI rejects fragments in the request line, but be
	// belt-and-braces — RFC 7230 §5.3.2 forbids them.
	if r.URL.Fragment != "" {
		return false
	}
	return true
}

// handleForward serves an absolute-form http:// forward-proxy request without hijacking; scope is resolved per request.
func (p *Proxy) handleForward(w http.ResponseWriter, r *http.Request) {
	// Pre-gate on the IP's TierAuth budget (shared with CONNECT, loopback exempt); only auth failures are recorded.
	if p.preAuthGated(r) {
		if d := p.rateLimit.Check(ratelimit.TierAuth, mitmIPKey(r)); !d.Allow {
			if p.strictCredentialProxy {
				p.strictAuthLimitDeny(w, r, d)
				return
			}
			ratelimit.WriteDenial(w, d, "Too many proxy requests")
			return
		}
	}

	// Use Hostname()/Port() (default port 80) rather than net.SplitHostPort, which fails on bracketed IPv6 hosts without a port.
	// Keeps event.Host and outURL.Host as host:port, matching CONNECT.
	host := r.URL.Hostname()
	portStr := r.URL.Port()
	if portStr == "" {
		portStr = "80"
	}
	portNum, err := strconv.Atoi(portStr)
	if err != nil {
		if p.strictCredentialProxy {
			p.strictUnauthenticatedDeny(w, r, http.StatusBadRequest)
			return
		}
		http.Error(w, "invalid port", http.StatusBadRequest)
		return
	}
	target := net.JoinHostPort(host, portStr)

	if !isValidHost(host) {
		if p.strictCredentialProxy {
			p.strictUnauthenticatedDeny(w, r, http.StatusBadRequest)
			return
		}
		http.Error(w, "invalid host", http.StatusBadRequest)
		return
	}

	// Normalise an empty path to "/" since some upstreams reject empty request-targets.
	if r.URL.Path == "" {
		r.URL.Path = "/"
	}

	// r.URL.Host is authoritative for an absolute-form request; r.Host is deliberately not read.

	token, hint, err := brokercore.ParseProxyAuth(r)
	if err != nil {
		p.recordAuthFailure(r)
		if p.refuseDecoyAtProxy(w, r, target, nil) {
			return
		}
		if p.strictCredentialProxy {
			p.strictUnauthenticatedDeny(w, r, http.StatusProxyAuthRequired)
			return
		}
		writeProxyAuthChallenge(w, "Proxy-Authorization required")
		return
	}
	peer, peerErr := peerFromContext(r.Context())
	// An admitted request is checked for decoys with its identity in the catalog adapter; a refused one is checked here.
	scope, err := p.resolveScope(r.Context(), token, hint, peer, peerErr, false)
	if err != nil {
		p.recordIdentityFailure(r, err)
		if p.refuseDecoyAtProxy(w, r, target, nil) {
			return
		}
		if p.strictCredentialProxy {
			p.strictIdentityDeny(w, r, err)
			return
		}
		writeAuthError(w, err)
		return
	}

	p.forwardRequest(w, r, target, host, portNum, false, scope)
}

// hostHeaderForScheme strips target's port when it is the scheme default so SigV4/GCS/Azure-SAS signatures match; other ports are kept.
func hostHeaderForScheme(scheme, target string) string {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return target
	}
	var defaultPort string
	switch strings.ToLower(scheme) {
	case "https":
		defaultPort = "443"
	case "http":
		defaultPort = "80"
	default:
		return target
	}
	if port != defaultPort {
		return target
	}
	if strings.ContainsRune(host, ':') {
		return "[" + host + "]"
	}
	return host
}

// forwardHandler forwards to the CONNECT-time target rather than r.Host, which defeats post-tunnel host rewriting.
func (p *Proxy) forwardHandler(target, host string, port int, scope *brokercore.ProxyScope) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.forwardRequest(w, r, target, host, port, true, scope)
	})
}

// forwardRequest is the shared body for the CONNECT and plain-HTTP paths; target is host:port, host is port-stripped for credential lookup.
func (p *Proxy) forwardRequest(
	w http.ResponseWriter,
	r *http.Request,
	target, host string,
	port int,
	useTLSUpstream bool,
	scope *brokercore.ProxyScope,
) {
	if p.strictCredentialProxy {
		p.forwardStrict(w, r, target, host, port, useTLSUpstream, scope)
		return
	}
	start := time.Now()
	authScheme, authHeader := detectAuthFromHeaders(r.Header)
	event := brokercore.ProxyEvent{
		Ingress:    brokercore.IngressMITM,
		Method:     r.Method,
		Host:       target,
		Path:       r.URL.Path,
		AuthScheme: authScheme,
		AuthHeader: authHeader,
	}
	actorType, actorID := actorFromScope(scope)
	emit := func(status int, errCode string) {
		event.Emit(p.logger, start, status, errCode)
		p.logSink.Record(r.Context(), requestlog.FromEvent(event, scope.VaultID, actorType, actorID))
	}

	enf := p.rateLimit.EnforceProxy(r.Context(), proxyLimitActor(scope), scope.VaultID)
	if !enf.Allowed {
		ratelimit.WriteDenial(w, enf.Decision, enf.Message)
		emit(http.StatusTooManyRequests, enf.ErrCode)
		return
	}
	defer enf.Release()

	r.Body = http.MaxBytesReader(w, r.Body, p.maxRequestBytes)

	scheme := "http"
	if useTLSUpstream {
		scheme = "https"
	}
	outURL := &url.URL{
		Scheme:   scheme,
		Host:     target,
		Path:     r.URL.Path,
		RawPath:  r.URL.RawPath,
		RawQuery: r.URL.RawQuery,
	}

	if r.ContentLength > 0 && r.ContentLength > p.maxRequestBytes {
		http.Error(w, http.StatusText(http.StatusRequestEntityTooLarge), http.StatusRequestEntityTooLarge)
		emit(http.StatusRequestEntityTooLarge, "request_too_large")
		return
	}

	inject, err := p.creds.Inject(r.Context(), scope.VaultID, host, port, r.URL.Path)
	if inject != nil {
		event.MatchedService = inject.MatchedName
		event.MatchedHost = inject.MatchedHost
		event.MatchedPath = inject.MatchedPath
		event.MatchedPort = inject.MatchedPort
		event.CredentialKeys = inject.CredentialKeys
		event.Passthrough = inject.Passthrough
	}
	if err != nil {
		errCode := "no_match"
		status := http.StatusForbidden
		if errors.Is(err, brokercore.ErrCredentialMissing) {
			errCode = "credential_not_found"
			status = http.StatusBadGateway
			brokercore.LogCredentialMissing(p.logger, scope.VaultID, event.MatchedService, event.CredentialKeys)
		}
		brokercore.WriteInjectError(w, err, target, scope.VaultName, p.baseURL)
		emit(status, errCode)
		return
	}

	// Fixed-query services require the strict no-parameters request boundary.
	if inject.FixedQuery != nil {
		http.Error(w, "strict credential proxy required", http.StatusForbidden)
		emit(http.StatusForbidden, "strict_profile_required")
		return
	}

	var body io.ReadCloser
	var contentLength int64

	hasSubs := brokercore.HasBodySubstitutions(inject.Substitutions)
	canStream := !hasSubs && r.ContentLength >= 0

	if canStream {
		body = r.Body
		contentLength = r.ContentLength
	} else {
		r.Body = http.MaxBytesReader(w, r.Body, brokercore.MaxMaterializeBytes)
		body, contentLength, err = brokercore.MaterializeRequestBody(r.Body)
		if err != nil {
			status, code := brokercore.RequestBodyErrorCode(err)
			http.Error(w, http.StatusText(status), status)
			emit(status, code)
			return
		}
	}

	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, outURL.String(), body)
	if err != nil {
		http.Error(w, "bad gateway", http.StatusBadGateway)
		emit(http.StatusBadGateway, "internal")
		return
	}
	outReq.Host = hostHeaderForScheme(scheme, target)
	outReq.ContentLength = contentLength

	wsUpgrade := isWebSocketUpgrade(r)

	if wsUpgrade {
		copyWebSocketHandshakeHeaders(r.Header, outReq.Header)
		brokercore.ApplyInjection(r.Header, outReq.Header, inject, websocketHandshakeHeaderNames...)
	} else {
		brokercore.ApplyInjection(r.Header, outReq.Header, inject)
	}

	if err := brokercore.ApplySubstitutions(outReq.URL, outReq.Header, inject.Substitutions); err != nil {
		http.Error(w, "bad gateway", http.StatusBadGateway)
		emit(http.StatusBadGateway, "substitution_error")
		return
	}

	if ce := outReq.Header.Get("Content-Encoding"); ce != "" {
		p.logger.Debug("skipping body substitution for compressed request",
			slog.String("content_encoding", ce),
			slog.String("host", host),
		)
	} else {
		newBody, newLen, modified, bErr := brokercore.ApplyBodySubstitutions(
			outReq.Body, outReq.ContentLength,
			outReq.Header.Get("Content-Type"), inject.Substitutions)
		if bErr != nil {
			http.Error(w, "bad gateway", http.StatusBadGateway)
			emit(http.StatusBadGateway, "substitution_error")
			return
		}
		outReq.Body = newBody
		if modified {
			outReq.ContentLength = newLen
			outReq.Header.Set("Content-Length", fmt.Sprintf("%d", newLen))
		}
	}

	if wsUpgrade {
		wsSubs := filterWebSocketSubs(inject.Substitutions)
		if len(wsSubs) > 0 {
			outReq.Header.Del("Sec-Websocket-Extensions")
		}
		p.forwardWebSocket(w, r, outReq, wsSubs, emit)
		return
	}

	resp, err := p.upstream.RoundTrip(outReq)
	if err != nil {
		p.logger.Debug("upstream request failed",
			slog.String("vault_id", scope.VaultID),
			slog.String("vault_name", scope.VaultName),
			slog.String("target_host", target),
			slog.String("error", err.Error()),
		)
		http.Error(w, "bad gateway", http.StatusBadGateway)
		emit(http.StatusBadGateway, "upstream_error")
		return
	}

	// Retry once with a forced OAuth refresh on 401, GET/HEAD only since the body cannot be replayed.
	if resp.StatusCode == http.StatusUnauthorized && inject != nil && !inject.Passthrough &&
		(r.Method == http.MethodGet || r.Method == http.MethodHead) {
		_ = resp.Body.Close()
		retryInject, retryErr := p.creds.Inject(r.Context(), scope.VaultID, host, port, r.URL.Path)
		if retryErr == nil && retryInject != nil && retryInject.Headers != nil && retryInject.FixedQuery == nil {
			retryReq := outReq.Clone(outReq.Context())
			for k, v := range retryInject.Headers {
				retryReq.Header.Set(k, v)
			}
			retryReq.Body = http.NoBody
			retryReq.ContentLength = 0
			if retryResp, retryRTErr := p.upstream.RoundTrip(retryReq); retryRTErr == nil {
				resp = retryResp
				p.logger.Debug("oauth 401 retry succeeded",
					slog.String("host", host),
					slog.String("path", r.URL.Path),
					slog.Int("status", resp.StatusCode),
				)
			}
		}
	}

	defer func() { _ = resp.Body.Close() }()

	if p.maxResponseBytes > 0 && resp.ContentLength > 0 && resp.ContentLength > p.maxResponseBytes {
		_ = resp.Body.Close()
		p.logger.Warn("response body exceeds limit",
			slog.String("host", target),
			slog.String("path", r.URL.Path),
			slog.Int64("content_length", resp.ContentLength),
			slog.Int64("max_response_bytes", p.maxResponseBytes),
		)
		brokercore.WriteProxyError(w, http.StatusBadGateway, "response_too_large",
			fmt.Sprintf("Upstream response body (%d bytes) exceeds the proxy response-size limit (%d bytes).",
				resp.ContentLength, p.maxResponseBytes))
		emit(http.StatusBadGateway, "response_too_large")
		return
	}

	for k, vv := range resp.Header {
		if brokercore.ShouldStripResponseHeader(k) {
			continue
		}
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)

	var src io.Reader = resp.Body
	if p.maxResponseBytes > 0 {
		src = io.LimitReader(resp.Body, p.maxResponseBytes)
	}
	var dst io.Writer = w
	if f, ok := w.(http.Flusher); ok {
		dst = &flushingWriter{w: w, f: f}
	}
	n, _ := io.Copy(dst, src)

	if p.maxResponseBytes > 0 && n == p.maxResponseBytes {
		var probe [1]byte
		if extra, _ := resp.Body.Read(probe[:]); extra > 0 {
			p.logger.Warn("response body truncated mid-stream, aborting connection",
				slog.String("host", target),
				slog.String("path", r.URL.Path),
				slog.Int64("bytes_streamed", n),
				slog.Int64("max_response_bytes", p.maxResponseBytes),
			)
			emit(resp.StatusCode, "response_truncated")
			panic(http.ErrAbortHandler)
		}
	}

	emit(resp.StatusCode, "")
}

// knownAPIKeyHeaders are non-Authorization headers that commonly carry
// API keys. Checked by exact canonical match -- no heuristic scanning.
var knownAPIKeyHeaders = []string{"X-Api-Key", "Api-Key"}

// detectAuthFromHeaders returns the auth scheme and header name, or ("", "") if none is recognizable.
func detectAuthFromHeaders(h http.Header) (scheme, header string) {
	if auth := h.Get("Authorization"); auth != "" {
		switch {
		case strings.HasPrefix(auth, "Bearer ") || strings.HasPrefix(auth, "bearer "):
			return "bearer", "Authorization"
		case strings.HasPrefix(auth, "Basic ") || strings.HasPrefix(auth, "basic "):
			return "basic", "Authorization"
		default:
			return "api-key", "Authorization"
		}
	}
	for _, name := range knownAPIKeyHeaders {
		if h.Get(name) != "" {
			return "api-key", http.CanonicalHeaderKey(name)
		}
	}
	return "", ""
}
