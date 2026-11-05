// Package mitm implements an HTTP/1.1 forward-proxy ingress for agent traffic, via CONNECT tunnels and absolute-form requests.
// HTTPS upstreams must use CONNECT; the forward path rejects https:// URLs to avoid silently TLS-stripping.
package mitm

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Infisical/agent-vault/internal/agenttoken"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/ca"
	"github.com/Infisical/agent-vault/internal/netguard"
	"github.com/Infisical/agent-vault/internal/ratelimit"
	"github.com/Infisical/agent-vault/internal/requestlog"
)

// Proxy is a transparent MITM proxy. It is safe to start at most once;
// reuse across Shutdown is not supported.
type Proxy struct {
	ca                    ca.Provider
	sessions              brokercore.SessionResolver
	creds                 brokercore.CredentialProvider
	httpServer            *http.Server
	upstream              *http.Transport
	isListening           atomic.Bool
	baseURL               string // externally-reachable control-plane URL for help links
	logger                *slog.Logger
	refusals              refusalLog
	rateLimit             *ratelimit.Registry // shared with the HTTP server; nil = no-op
	logSink               requestlog.Sink     // never nil (Nop default); shared with the HTTP server
	maxResponseBytes      int64               // 0 = unlimited
	maxRequestBytes       int64
	strictCredentialProxy bool
	durableAudit          requestlog.Durable
	strictTunnels         chan struct{}
	adapter               *HeaderAdapter
	attestor              brokercore.Attestor
	agentTokens           agenttoken.Verifier
	peerReader            PeerReader
	graphql               graphqlLookups // what GitHub said about node IDs (github_graphql.go)
	http2MaxStreams       int
	identityRetry         time.Duration                  // Retry-After when an identity check could not complete
	h2Upstream            atomic.Pointer[http.Transport] // built from upstream on first HTTP/2 request (grpc.go)
	certificatesMu        sync.Mutex
	certificateTransports map[certificateTransportKey]certificateTransport // per client certificate (clientcert.go)

	// Tunnel drain (opt-in): Shutdown lets each tunnel finish its current request.
	drainTunnels bool
	tunnelsMu    sync.Mutex
	tunnels      map[*http.Server]bool // true for an HTTP/2 tunnel
	tunnelWG     sync.WaitGroup
	draining     bool
}

// DefaultMaxTunnels bounds pending or active CONNECT tunnels per replica; AGENT_VAULT_MITM_MAX_TUNNELS overrides it.
const DefaultMaxTunnels = 10000

// DefaultMaxIdleUpstreamConns bounds idle upstream connections kept for reuse, in total and per host; it applies only where keep-alives are on.
const DefaultMaxIdleUpstreamConns = 10000

// Options carries the dependencies a Proxy needs. BaseURL is the externally-reachable control-plane URL for help links; Logger must be non-nil.
// RateLimit is shared with the HTTP server so proxy and control-plane limits live in one registry; nil disables it on the MITM path.
type Options struct {
	MaxIdleUpstreamConns      int                // <=0 defaults to DefaultMaxIdleUpstreamConns idle upstream connections, in total and per host
	MaxCredentialProxyTunnels int                // <=0 defaults to DefaultMaxTunnels pending or active CONNECT tunnels
	HTTP2MaxStreams           int                // <=0 defaults to DefaultHTTP2MaxStreams concurrent requests per HTTP/2 tunnel
	IdentityRetrySeconds      int                // <=0 defaults to DefaultIdentityRetry, at most MaxIdentityRetry: the Retry-After when an identity check could not complete
	StrictCredentialProxy     bool               // bounded header-placeholder release path
	DurableAudit              requestlog.Durable // mandatory when strict mode is enabled, unless HeaderAdapter is set
	HeaderAdapter             *HeaderAdapter     // strict mode only: catalog destinations with signed audit
	// Attestor, when set, admits workers by projected token and real peer address instead of Sessions, which remains the token-review fallback.
	Attestor   brokercore.Attestor
	PeerReader PeerReader // nil: the TCP remote address
	// AgentTokens verifies a static agent token on the listener admitting only that kind; nil means such a listener refuses every caller.
	AgentTokens agenttoken.Verifier
	// DrainTunnels makes Shutdown stop taking tunnels and wait, within its context, for each open tunnel's current request; off, tunnels end with the process.
	DrainTunnels     bool
	CA               ca.Provider
	Sessions         brokercore.SessionResolver
	Credentials      brokercore.CredentialProvider
	BaseURL          string
	Logger           *slog.Logger
	RateLimit        *ratelimit.Registry
	LogSink          requestlog.Sink // nil → Nop
	MaxResponseBytes int64           // 0 = unlimited (default); >0 = cap in bytes
	MaxRequestBytes  int64           // 0 → DefaultMaxRequestBytes (1 GiB)
}

// New builds a Proxy bound to addr. The returned Proxy does not begin
// listening until ListenAndServe is called.
func New(addr string, opts Options) *Proxy {
	maxIdle := opts.MaxIdleUpstreamConns
	if maxIdle <= 0 {
		maxIdle = DefaultMaxIdleUpstreamConns
	}
	upstream := &http.Transport{
		DialContext:           netguard.SafeDialContext(netguard.AllowPrivateFromEnv()),
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		DisableCompression:    opts.StrictCredentialProxy,
		DisableKeepAlives:     opts.StrictCredentialProxy, // avoid transport retries on reused connections
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          maxIdle,
		MaxIdleConnsPerHost:   maxIdle, // the default of 2 re-handshakes TLS for nearly every request to one popular host
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 5 * time.Minute,
	}

	sink := opts.LogSink
	if sink == nil {
		sink = requestlog.Nop{}
	}

	maxReq := opts.MaxRequestBytes
	if maxReq <= 0 {
		maxReq = brokercore.DefaultMaxRequestBytes
	}

	tunnelLimit := opts.MaxCredentialProxyTunnels
	if tunnelLimit <= 0 {
		tunnelLimit = DefaultMaxTunnels
	}
	streams := opts.HTTP2MaxStreams
	if streams <= 0 {
		streams = DefaultHTTP2MaxStreams
	}
	identityRetry := DefaultIdentityRetry
	if opts.IdentityRetrySeconds > 0 {
		identityRetry = time.Duration(min(opts.IdentityRetrySeconds, int(MaxIdentityRetry/time.Second))) * time.Second
	}
	p := &Proxy{
		ca:                    opts.CA,
		strictCredentialProxy: opts.StrictCredentialProxy,
		durableAudit:          opts.DurableAudit,
		adapter:               opts.HeaderAdapter,
		attestor:              opts.Attestor,
		agentTokens:           opts.AgentTokens,
		peerReader:            opts.PeerReader,
		drainTunnels:          opts.DrainTunnels,
		tunnels:               make(map[*http.Server]bool),
		strictTunnels:         make(chan struct{}, tunnelLimit),
		sessions:              opts.Sessions,
		creds:                 opts.Credentials,
		upstream:              upstream,
		baseURL:               opts.BaseURL,
		logger:                opts.Logger,
		rateLimit:             opts.RateLimit,
		logSink:               sink,
		maxResponseBytes:      opts.MaxResponseBytes, // 0 = unlimited
		maxRequestBytes:       maxReq,
		http2MaxStreams:       streams,
		identityRetry:         identityRetry,
	}

	p.httpServer = &http.Server{
		Addr:              addr,
		Handler:           http.HandlerFunc(p.dispatch),
		ReadHeaderTimeout: 10 * time.Second,
		ConnContext:       withPeerConn,
	}
	return p
}

// Addr returns the listener address the Proxy was configured with.
func (p *Proxy) Addr() string { return p.httpServer.Addr }

// RootPEM returns the root CA certificate in PEM form, safe to distribute.
func (p *Proxy) RootPEM() []byte { return p.ca.RootPEM() }

// IsListening reports whether the listener is bound; check it rather than nil-checking the Proxy, since a bind failure leaves it alive.
func (p *Proxy) IsListening() bool { return p.isListening.Load() }

// ListenAndServe binds eagerly so callers see bind failures, then blocks until Shutdown (http.ErrServerClosed).
func (p *Proxy) ListenAndServe() error {
	l, err := net.Listen("tcp", p.httpServer.Addr)
	if err != nil {
		return err
	}
	return p.Serve(l)
}

// Serve accepts connections on the given plain-HTTP listener until Shutdown, useful for tests binding :0.
func (p *Proxy) Serve(l net.Listener) error {
	// A PROXY header names the worker, so it is accepted only on a loopback listener, where the sole peers are the broker Pod's own containers.
	if p.peerReader != nil {
		if addr, ok := l.Addr().(*net.TCPAddr); !ok || !addr.IP.IsLoopback() {
			_ = l.Close()
			return errors.New("PROXY header peers require a loopback listener")
		}
	}
	p.isListening.Store(true)
	defer p.isListening.Store(false)
	return p.httpServer.Serve(peerListener{Listener: l, reader: p.peerReader})
}

// Shutdown gracefully stops the listener. Hijacked CONNECT tunnels are not tracked by http.Server's shutdown, so without DrainTunnels they die with the process.
// With DrainTunnels, Shutdown refuses new tunnels, closes idle ones, lets active requests finish with Connection: close, and force-closes the rest when ctx ends.
func (p *Proxy) Shutdown(ctx context.Context) error {
	p.upstream.CloseIdleConnections()
	if h2 := p.h2Upstream.Load(); h2 != nil {
		h2.CloseIdleConnections()
	}
	p.closeCertificateUpstreams()
	// Cached GitHub installation tokens are revoked however the stop goes.
	defer p.revokeGitTokens()
	if !p.drainTunnels {
		return p.httpServer.Shutdown(ctx)
	}
	p.tunnelsMu.Lock()
	p.draining = true
	for srv, h2 := range p.tunnels {
		stopTunnel(srv, h2)
	}
	p.tunnelsMu.Unlock()
	outer := make(chan error, 1)
	go func() { outer <- p.httpServer.Shutdown(ctx) }()
	done := make(chan struct{})
	go func() { p.tunnelWG.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		p.tunnelsMu.Lock()
		for srv := range p.tunnels {
			_ = srv.Close()
		}
		p.tunnelsMu.Unlock()
	}
	return <-outer
}

// reserveTunnel counts a tunnel before its CONNECT is answered so Shutdown waits for it; false once draining.
func (p *Proxy) reserveTunnel() (release func(), ok bool) {
	if !p.drainTunnels {
		return func() {}, true
	}
	p.tunnelsMu.Lock()
	defer p.tunnelsMu.Unlock()
	if p.draining {
		return nil, false
	}
	p.tunnelWG.Add(1)
	return p.tunnelWG.Done, true
}

// trackTunnel registers a tunnel's request server; one registered after Shutdown began serves its current request and closes.
func (p *Proxy) trackTunnel(srv *http.Server, h2 bool) (untrack func()) {
	if !p.drainTunnels {
		return func() {}
	}
	p.tunnelsMu.Lock()
	defer p.tunnelsMu.Unlock()
	p.tunnels[srv] = h2
	if p.draining {
		stopTunnel(srv, h2)
	}
	return func() {
		p.tunnelsMu.Lock()
		delete(p.tunnels, srv)
		p.tunnelsMu.Unlock()
	}
}

// stopTunnel lets a draining tunnel finish what it is serving, then close; an HTTP/2 tunnel also sends GOAWAY, since keep-alives alone would leave it idle until the drain deadline.
func stopTunnel(srv *http.Server, h2 bool) {
	srv.SetKeepAlivesEnabled(false)
	if h2 {
		go func() { _ = srv.Shutdown(context.Background()) }()
	}
}

// revokeGitTokens revokes every cached GitHub installation token, which GitHub would honour for up to an hour after the broker stops.
func (p *Proxy) revokeGitTokens() {
	if p.adapter == nil {
		return
	}
	if tokens, ok := p.adapter.GitTokens.(interface{ RevokeAll() }); ok {
		tokens.RevokeAll()
	}
}

func (p *Proxy) dispatch(w http.ResponseWriter, r *http.Request) {
	// The static-token listener carries CONNECT only: a refused CONNECT leaves the connection open, so any other method is refused and ends it.
	if r.Method != http.MethodConnect && onlyStaticToken(connKinds(r.Context())) {
		w.Header().Set("Connection", "close")
		if p.strictCredentialProxy {
			p.strictUnauthenticatedDeny(w, r, http.StatusBadRequest)
			return
		}
		http.Error(w, "this listener takes CONNECT only", http.StatusBadRequest)
		return
	}
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}
	if isAbsoluteForwardProxyRequest(r) {
		p.handleForward(w, r)
		return
	}
	if p.isSettingsRequest(r) {
		p.handleSettings(w, r)
		return
	}
	if p.strictCredentialProxy {
		p.strictUnauthenticatedDeny(w, r, http.StatusBadRequest)
		return
	}
	// Anything other than CONNECT or absolute-form forward is a malformed request, not a method-not-allowed.
	http.Error(w, "this endpoint is an HTTP forward proxy; non-CONNECT requests must use absolute-form URLs (http://host/path). Use CONNECT for https:// upstreams.", http.StatusBadRequest)
}
