package mitm

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Infisical/agent-vault/internal/auditchain"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/ratelimit"
)

// mitmIPKey is the per-IP flood-gate key shared by CONNECT and forward-proxy paths; only the direct peer IP is meaningful here.
func mitmIPKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || host == "" {
		host = r.RemoteAddr
	}
	key := "mitm:" + host
	// On a listener admitting only proxy-attested identities, the auth-failure budget is the attested sandbox's, since every sandbox arrives from the proxy's address; elsewhere it stays per address.
	if kinds := connKinds(r.Context()); len(kinds) == 1 && kinds[0] == brokercore.KindProxyAttested {
		if sandbox := brokercore.AttestedSandbox(r.Header.Get(brokercore.AttestationHeader)); sandbox != "" {
			key += "/sandbox:" + sandbox
		}
	}
	// A static-token listener keys failures on the peer the TLS front named in its PROXY header, never on anything the caller wrote, which would be a lockout lever or an unbounded set of budgets.
	if onlyStaticToken(connKinds(r.Context())) {
		key = "mitm:static-token"
		if peer, err := peerFromContext(r.Context()); err == nil {
			key += "/peer:" + peer.String()
		}
	}
	return key
}

// preAuthGated reports whether a failure budget applies. Loopback peers are exempt (see isLoopbackPeer), except on the static-token listener, where the budget only slows failed attempts: a verifying token is never held back by anyone's failures.
func (p *Proxy) preAuthGated(r *http.Request) bool {
	if p.rateLimit == nil {
		return false
	}
	if onlyStaticToken(connKinds(r.Context())) {
		return !p.staticTokenVerifies(r)
	}
	return !isLoopbackPeer(r)
}

func (p *Proxy) staticTokenVerifies(r *http.Request) bool {
	if p.agentTokens == nil {
		return false
	}
	token, hint, err := brokercore.ParseProxyAuth(r)
	if err != nil || hint != "" {
		return false
	}
	_, err = p.agentTokens.Verify(r.Context(), token)
	return err == nil
}

// proxyLimitActor is the per-actor rate-limit key: the actor, plus the Pod for a verified workload, so Pods sharing one agent identity each get their own budget.
func proxyLimitActor(scope *brokercore.ProxyScope) string {
	if scope.WorkloadID != "" {
		return scope.ActorID() + "/" + scope.WorkloadID
	}
	return scope.ActorID()
}

// isLoopbackPeer reports whether the request came from loopback, which skips the flood gate for local `vault run` clients.
func isLoopbackPeer(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || host == "" {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// handleConnect terminates a CONNECT tunnel; the target is captured from r.Host so later Host rewrites cannot redirect it.
func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	// Counts pending authentication and the whole tunnel lifetime; the per-actor limit inside a tunnel does not bound idle TLS connections.
	if p.strictCredentialProxy {
		select {
		case p.strictTunnels <- struct{}{}:
			defer func() { <-p.strictTunnels }()
		default:
			p.strictUnauthenticatedDeny(w, r, http.StatusTooManyRequests)
			return
		}
	}

	// Read-only pre-gate on the auth-failure budget; loopback is exempt.
	if p.preAuthGated(r) {
		if d := p.rateLimit.Check(ratelimit.TierAuth, mitmIPKey(r)); !d.Allow {
			if p.strictCredentialProxy {
				p.strictAuthLimitDeny(w, r, d)
				return
			}
			ratelimit.WriteDenial(w, d, "Too many CONNECT attempts")
			return
		}
	}

	target := r.Host
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		if p.strictCredentialProxy {
			p.strictUnauthenticatedDeny(w, r, http.StatusBadRequest)
			return
		}
		http.Error(w, "CONNECT target must be host:port", http.StatusBadRequest)
		return
	}
	port, portErr := strconv.Atoi(portStr)
	if p.strictCredentialProxy && (portErr != nil || port < 1 || port > 65535) {
		p.strictUnauthenticatedDeny(w, r, http.StatusBadRequest)
		return
	}
	if !isValidHost(host) {
		if p.strictCredentialProxy {
			p.strictUnauthenticatedDeny(w, r, http.StatusBadRequest)
			return
		}
		http.Error(w, "invalid host", http.StatusBadRequest)
		return
	}

	// Error responses must be written BEFORE the hijack, after which no HTTP status can be sent.
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
	// The runner session token is set by the sidecar on CONNECT only; requests inside the tunnel cannot supply or replace it.
	session := r.Header.Get(SessionHeader)
	// A shared proxy's attestation of the agent Pod, on CONNECT only.
	attested := brokercore.WithAttestation(r.Context(), r.Header.Get(brokercore.AttestationHeader))
	connectScope, err := p.resolveScope(attested, token, hint, peer, peerErr, false)
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
	if p.refuseDecoyAtProxy(w, r, target, connectScope) {
		return
	}
	// With a catalog, refuse a host the caller's pool is not granted before minting a certificate or opening a tunnel; the caller gets the same 403 whichever pools may reach the host, and only the audit row tells them apart.
	if p.strictCredentialProxy && p.adapter.valid() {
		if catalog := p.adapter.Catalog.Current(); !catalog.HasHostForPool(host, port, connectScope.Pool) && !subagentRoute(catalog, host, port, connectScope.Pool) {
			outcome := "unlisted"
			if catalog.HasHost(host, port) {
				outcome = "pool"
			}
			refused := auditchain.Event{Method: auditMethod(r.Method), Pool: connectScope.Pool, Agent: connectScope.AgentID, PodUID: connectScope.WorkloadID}
			p.attribute(withSessionToken(r.Context(), session), connectScope, &refused)
			p.adapterDeny(w, refused, target, http.StatusForbidden, outcome)
			return
		}
	}

	// A replica shutting down takes no new tunnels; the client retries on another.
	release, ok := p.reserveTunnel()
	if !ok {
		w.Header().Set("Connection", "close")
		if p.strictCredentialProxy {
			p.strictUnauthenticatedDeny(w, r, http.StatusServiceUnavailable)
			return
		}
		http.Error(w, "proxy shutting down", http.StatusServiceUnavailable)
		return
	}
	defer release()

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hj.Hijack()
	if err != nil {
		http.Error(w, "hijack failed", http.StatusInternalServerError)
		return
	}

	if _, err := io.WriteString(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		_ = clientConn.Close()
		return
	}

	// A web app's host gets a leaf from the browser CA, which signs nothing else; its SNI must be that host.
	browser := p.adapter.valid() && p.adapter.Catalog.Current().BrowserHost(host, port)
	// HTTP/2, which gRPC needs, only to a host whose catalog entries take it.
	protos := []string{"http/1.1"}
	h2 := p.strictCredentialProxy && p.adapter.valid() && p.adapter.Catalog.Current().HTTP2Host(host, port)
	if h2 {
		protos = []string{"h2", "http/1.1"}
	}
	tlsConf := &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: protos,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			sni := hello.ServerName
			if sni == "" {
				sni = host
			}
			if browser {
				if !strings.EqualFold(sni, host) {
					return nil, errors.New("browser host SNI differs from the CONNECT host")
				}
				return p.ca.MintBrowserLeaf(sni)
			}
			return p.ca.MintLeaf(sni)
		},
	}

	tlsConn := tls.Server(clientConn, tlsConf)
	_ = tlsConn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		// err may carry TLS alert detail from the client — diagnostic, not secret.
		if !p.strictCredentialProxy {
			p.logger.Warn("mitm TLS handshake failed", "host", host, "err", err.Error())
		}
		_ = tlsConn.Close()
		return
	}
	_ = tlsConn.SetDeadline(time.Time{})

	// The listener yields the connection once; ConnState closes it when the connection leaves the hijacked state so Serve returns.
	listener := newOneShotListener(tlsConn)
	connDone := make(chan struct{})
	var connDoneOnce sync.Once
	// Requests inside the tunnel take the listener's identity kinds from the CONNECT.
	kinds := connKinds(r.Context())
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r = r.WithContext(withConnectTarget(r.Context(), target))
			if r.ProtoMajor == 2 {
				r = r.WithContext(withHTTP2(r.Context()))
				// Every answer a gRPC client gets, refusals included, is readable as a gRPC status.
				if isGRPC(r) {
					w = &grpcWriter{ResponseWriter: w}
				}
			}
			// A tunnel can outlive its token or grant: recheck each request against the original proxy identity before injecting credentials.
			scope, err := p.resolveScope(withKinds(brokercore.WithAttestation(r.Context(), brokercore.AttestationFrom(attested)), kinds), token, hint, peer, peerErr, true)
			if err != nil {
				w.Header().Set("Connection", "close")
				if p.strictCredentialProxy {
					p.strictIdentityDeny(w, r, err)
					return
				}
				writeAuthError(w, err)
				return
			}
			r.Header.Del(SessionHeader)
			r.Header.Del(brokercore.AttestationHeader)
			p.forwardHandler(target, host, port, scope).ServeHTTP(w, r.WithContext(withSessionToken(r.Context(), session)))
		}),
		// WriteTimeout is 30 min to allow long streaming transfers (git clone, SSE).
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      30 * time.Minute,
		IdleTimeout:       2 * time.Minute,
		// HTTP/2 tunnels apply the same timeouts per request (stream); a gRPC body ends with its last message.
		HTTP2: &http.HTTP2Config{MaxConcurrentStreams: p.http2MaxStreams},
		ConnState: func(c net.Conn, state http.ConnState) {
			// http.Server or the hijack handler owns the conn; do not close it here.
			if state == http.StateHijacked || state == http.StateClosed {
				_ = listener.Close()
				connDoneOnce.Do(func() { close(connDone) })
			}
		},
	}
	// A tunnel, including a response still streaming, must not outlive the worker Pod's deadline.
	if !connectScope.NotAfter.IsZero() {
		deadline := time.AfterFunc(time.Until(connectScope.NotAfter), func() { _ = tlsConn.Close() })
		defer deadline.Stop()
	}
	defer p.trackTunnel(srv, h2)()
	_ = srv.Serve(listener)
	// Serve can stop before taking the connection (a forced close during shutdown); once it took it, the tunnel lasts until the connection ends.
	select {
	case c := <-listener.yield:
		_ = c.Close()
	default:
		<-connDone
	}
}

// recordAuthFailure counts one failure against the per-IP TierAuth budget; loopback peers are exempt.
func (p *Proxy) recordAuthFailure(r *http.Request) {
	if p.preAuthGated(r) {
		p.rateLimit.Allow(ratelimit.TierAuth, mitmIPKey(r))
	}
}

// recordIdentityFailure is recordAuthFailure for a refused identity, except a check the broker could not complete, which is no failed sign-in.
func (p *Proxy) recordIdentityFailure(r *http.Request, err error) {
	if !brokercore.DenialUnavailable(err) {
		p.recordAuthFailure(r)
	}
}

// writeProxyAuthChallenge writes a 407 with a Proxy-Authenticate header so
// well-behaved clients re-issue the CONNECT with credentials.
func writeProxyAuthChallenge(w http.ResponseWriter, msg string) {
	w.Header().Set("Proxy-Authenticate", `Basic realm="agent-vault"`)
	http.Error(w, msg, http.StatusProxyAuthRequired)
}

// writeAuthError maps a brokercore session-resolution error to an HTTP
// response at tunnel admission or before forwarding a tunneled request.
func writeAuthError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, brokercore.ErrInvalidSession):
		writeProxyAuthChallenge(w, "invalid or expired session")
	case errors.Is(err, brokercore.ErrAgentVaultAmbiguous),
		errors.Is(err, brokercore.ErrNoVaultContext):
		http.Error(w, "set vault via HTTPS_PROXY=http://<token>:<vault>@host:port", http.StatusBadRequest)
	case errors.Is(err, brokercore.ErrVaultHintMismatch),
		errors.Is(err, brokercore.ErrVaultAccessDenied):
		http.Error(w, "forbidden", http.StatusForbidden)
	case errors.Is(err, brokercore.ErrVaultNotFound):
		http.Error(w, "vault not found", http.StatusNotFound)
	default:
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

// isValidHost is a local alias for brokercore.IsValidHost so existing
// callers and the #nosec G706 justification below stay readable.
func isValidHost(h string) bool { return brokercore.IsValidHost(h) }

// oneShotListener yields a single conn to http.Serve, then blocks Accept until Close.
type oneShotListener struct {
	conn   net.Conn
	yield  chan net.Conn
	closed chan struct{}
}

func newOneShotListener(c net.Conn) *oneShotListener {
	l := &oneShotListener{
		conn:   c,
		yield:  make(chan net.Conn, 1),
		closed: make(chan struct{}),
	}
	l.yield <- c
	return l
}

var errListenerClosed = errors.New("mitm: one-shot listener closed")

func (l *oneShotListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.yield:
		return c, nil
	case <-l.closed:
		return nil, errListenerClosed
	}
}

func (l *oneShotListener) Close() error {
	select {
	case <-l.closed:
	default:
		close(l.closed)
	}
	return nil
}

func (l *oneShotListener) Addr() net.Addr { return l.conn.LocalAddr() }
