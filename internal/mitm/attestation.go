package mitm

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/Infisical/agent-vault/internal/agenttoken"
	"github.com/Infisical/agent-vault/internal/brokercore"
)

// PeerReader returns the worker's address for an accepted connection; it must read no further than the PROXY header.
type PeerReader func(net.Conn) (netip.Addr, error)

var errNoPeer = errors.New("connection peer unavailable")

// peerListener resolves each peer lazily on the connection's goroutine, so a stalled client cannot block Accept.
type peerListener struct {
	net.Listener
	reader PeerReader
}

func (l peerListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &peerConn{Conn: c, reader: l.reader}, nil
}

type peerConn struct {
	net.Conn
	reader PeerReader
	once   sync.Once
	peer   netip.Addr
	err    error

	mu       sync.Mutex
	deadline time.Time // the read deadline the HTTP server last set
}

// SetReadDeadline and SetDeadline record the deadline so it can be restored after the PROXY header is read.
func (c *peerConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	c.mu.Unlock()
	return c.Conn.SetReadDeadline(t)
}

func (c *peerConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	c.mu.Unlock()
	return c.Conn.SetDeadline(t)
}

func (c *peerConn) resolve() {
	c.once.Do(func() {
		remote, err := netip.ParseAddrPort(c.Conn.RemoteAddr().String())
		if err != nil {
			c.err = errNoPeer
			return
		}
		if c.reader == nil {
			c.peer = remote.Addr().Unmap()
			return
		}
		// A PROXY header is trusted only from a loopback terminator.
		if !remote.Addr().Unmap().IsLoopback() {
			c.err = errNoPeer
			return
		}
		// The header gets at most 5s, capped by the server's header timeout; the deadline is restored afterwards.
		c.mu.Lock()
		restore := c.deadline
		c.mu.Unlock()
		header := time.Now().Add(5 * time.Second)
		if !restore.IsZero() && restore.Before(header) {
			header = restore
		}
		_ = c.Conn.SetReadDeadline(header)
		c.peer, c.err = c.reader(c.Conn)
		_ = c.Conn.SetReadDeadline(restore)
		if c.err != nil {
			c.err = errNoPeer
		}
	})
}

func (c *peerConn) Read(b []byte) (int, error) {
	c.resolve()
	if c.err != nil {
		return 0, c.err
	}
	return c.Conn.Read(b)
}

// Peer is valid only after the first read, which the HTTP server does before any handler.
func (c *peerConn) Peer() (netip.Addr, error) {
	c.resolve()
	return c.peer, c.err
}

type peerContextKey struct{}

func withPeerConn(ctx context.Context, c net.Conn) context.Context {
	if pc, ok := c.(*peerConn); ok {
		return context.WithValue(ctx, peerContextKey{}, pc)
	}
	return ctx
}

func peerFromContext(ctx context.Context) (netip.Addr, error) {
	pc, ok := ctx.Value(peerContextKey{}).(*peerConn)
	if !ok {
		return netip.Addr{}, errNoPeer
	}
	return pc.Peer()
}

// resolveScope admits a worker via the Attestor when set, else the SessionResolver; a tunnel recheck uses Reattest if available.
func (p *Proxy) resolveScope(ctx context.Context, token, hint string, peer netip.Addr, peerErr error, recheck bool) (*brokercore.ProxyScope, error) {
	scope, err := p.resolveAnyScope(ctx, token, hint, peer, peerErr, recheck)
	if err != nil {
		return nil, err
	}
	// Each listener admits only the identity kinds it was opened for; a scope of another kind is refused.
	kinds := connKinds(ctx)
	if !brokercore.KindAdmitted(kinds, scope.IdentityKind) || (scope.IdentityKind == brokercore.KindStaticToken && !onlyStaticToken(kinds)) {
		p.logRefusal("listener_kind", nil)
		return nil, brokercore.Denied("listener_kind")
	}
	return scope, nil
}

type kindsKey struct{}

// withKinds carries the CONNECT listener's identity kinds into its tunnel's requests.
func withKinds(ctx context.Context, kinds []string) context.Context {
	return context.WithValue(ctx, kindsKey{}, kinds)
}

func connKinds(ctx context.Context) []string {
	if kinds, ok := ctx.Value(kindsKey{}).([]string); ok {
		return kinds
	}
	if pc, ok := ctx.Value(peerContextKey{}).(*peerConn); ok {
		return brokercore.ConnKinds(pc.Conn)
	}
	return brokercore.ConnKinds(nil)
}

func (p *Proxy) resolveAnyScope(ctx context.Context, token, hint string, peer netip.Addr, peerErr error, recheck bool) (*brokercore.ProxyScope, error) {
	if onlyStaticToken(connKinds(ctx)) {
		return p.resolveAgentToken(ctx, token, hint, peer, recheck)
	}
	if p.attestor == nil {
		return p.sessions.ResolveForProxy(ctx, token, hint)
	}
	if peerErr != nil || !peer.IsValid() {
		return nil, brokercore.ErrInvalidSession
	}
	var scope *brokercore.ProxyScope
	var err error
	if again, ok := p.attestor.(brokercore.Reattestor); ok && recheck {
		scope, err = again.Reattest(ctx, token, peer)
	} else {
		scope, err = p.attestor.Attest(ctx, token, peer)
	}
	if err != nil || scope == nil {
		reason := brokercore.DenialReason(err)
		p.logRefusal(reason, brokercore.DenialKey(err))
		if reason == "" {
			return nil, brokercore.ErrInvalidSession
		}
		// The refusal itself, so its kid and peer reach the audit row.
		return nil, err
	}
	if !scope.NotAfter.IsZero() && !time.Now().Before(scope.NotAfter) {
		p.logRefusal("deadline", nil)
		return nil, brokercore.Denied("deadline")
	}
	return scope, nil
}

func onlyStaticToken(kinds []string) bool {
	return len(kinds) == 1 && kinds[0] == brokercore.KindStaticToken
}

const (
	reasonAgentRemoved = "agent_removed"
	reasonNoVerifier   = "token_unverifiable"
)

// resolveAgentToken admits a static agent token on the static-token listener, rechecked on every tunnel request; a vault hint is refused.
func (p *Proxy) resolveAgentToken(ctx context.Context, token, hint string, peer netip.Addr, recheck bool) (*brokercore.ProxyScope, error) {
	refuse := func(err error) (*brokercore.ProxyScope, error) {
		if brokercore.DenialReason(err) == "" {
			err = brokercore.Denied(reasonNoVerifier)
		}
		reason := brokercore.DenialReason(err)
		if recheck && reason == agenttoken.ReasonUnknown {
			if k := brokercore.DenialKey(err); k != nil {
				err = brokercore.DeniedKey(reasonAgentRemoved, k.Kid)
				reason = reasonAgentRemoved
			}
		}
		err = brokercore.WithPeer(err, peer)
		p.logRefusal(reason, brokercore.DenialKey(err))
		return nil, err
	}
	if p.agentTokens == nil {
		return refuse(brokercore.Denied(reasonNoVerifier))
	}
	if hint != "" {
		return refuse(brokercore.Denied(agenttoken.ReasonMalformed))
	}
	session, err := p.agentTokens.Verify(ctx, token)
	if err != nil {
		return refuse(err)
	}
	if !session.Expires.IsZero() && !time.Now().Before(session.Expires) {
		return refuse(brokercore.DeniedKey(agenttoken.ReasonExpired, session.Automation))
	}
	return &brokercore.ProxyScope{
		AgentID:      session.Automation,
		Automation:   session.Automation,
		Pool:         session.Pool,
		TokenSource:  session.Source,
		TokenOwner:   session.Owner,
		IdentityKind: brokercore.KindStaticToken,
		NotAfter:     session.Expires,
	}, nil
}

// refusalLogEvery bounds the refusal log to one line per reason per interval.
const refusalLogEvery = 10 * time.Second

type refusalLog struct {
	mu     sync.Mutex
	last   map[string]time.Time
	counts map[string]int
}

// logRefusal logs a fixed code, never a token or name.
func (p *Proxy) logRefusal(reason string, key *brokercore.KeyDenial) {
	if reason == "" {
		reason = "unspecified"
	}
	l := &p.refusals
	l.mu.Lock()
	if l.last == nil {
		l.last, l.counts = map[string]time.Time{}, map[string]int{}
	}
	l.counts[reason]++
	now := time.Now()
	if now.Sub(l.last[reason]) < refusalLogEvery {
		l.mu.Unlock()
		return
	}
	count := l.counts[reason]
	l.last[reason], l.counts[reason] = now, 0
	l.mu.Unlock()
	if p.logger == nil {
		return
	}
	args := []any{"reason", reason, "count", count}
	if key != nil {
		args = append(args, "kid", key.Kid)
		if key.KidSHA256 != "" {
			args = append(args, "kid_sha256", key.KidSHA256)
		}
		args = append(args, "peer", key.Peer)
	}
	p.logger.Warn("workload identity refused", args...)
}
