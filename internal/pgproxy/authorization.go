package pgproxy

import (
	"context"
	"net/netip"
	"time"
)

// authorizationLoop bounds the lifetime of an already-open session after token
// revocation/expiry, grant removal, or a binding change. Store unavailability
// fails closed. Capacity changes alone affect admission, not existing sessions.
func (b *Broker) authorizationLoop(ctx context.Context, token, hint, requested string, scope AgentScope, svc DatabaseService, terminate func(), peer netip.Addr) {
	b.authorizationLoopWith(ctx, token, hint, scope, svc.Name, func(ctx context.Context, current AgentScope) bool {
		next, err := b.opts.Databases.ResolveDatabase(ctx, current, requested)
		return err == nil && next != nil && sameBinding(svc, *next)
	}, terminate, peer)
}

// authorizationLoopWith is authorizationLoop for any destination: confirm
// resolves it again for the rechecked scope and reports whether it is still
// the same binding.
func (b *Broker) authorizationLoopWith(ctx context.Context, token, hint string, scope AgentScope, service string, confirm func(context.Context, AgentScope) bool, terminate func(), peer netip.Addr) {
	defer func() {
		if recover() != nil {
			terminate()
		}
	}()
	ticker := time.NewTicker(b.opts.AuthorizationInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		checkCtx, cancel := context.WithTimeout(WithRecheck(ctx), b.opts.AuthorizationTimeout)
		// A dependency must honor context, but cannot postpone terminating access
		// simply by returning late. A fired watchdog cannot revive the session.
		watchdog := time.AfterFunc(b.opts.AuthorizationTimeout, terminate)
		current, err := b.renewalAuthenticator(peer).Authenticate(checkCtx, token, hint)
		valid := err == nil && current != nil && current.ActorID == scope.ActorID && current.VaultID == scope.VaultID && current.WorkloadID == scope.WorkloadID
		if valid {
			valid = confirm(checkCtx, *current)
		}
		stopped := watchdog.Stop()
		valid = valid && stopped && checkCtx.Err() == nil
		cancel()
		if !valid {
			if ctx.Err() == nil {
				b.logger.Warn("pgproxy: authorization no longer confirmed; terminating session", "service", service, "actor", scope.ActorID)
			}
			terminate()
			return
		}
	}
}

func sameBinding(a, b DatabaseService) bool {
	a.MaxConns, b.MaxConns = 0, 0
	return a == b
}

// peerAuth adapts a PeerAuthenticator to the plain interface for one connection.
type peerAuth struct {
	auth    PeerAuthenticator
	peer    netip.Addr
	renewal bool
}

func (p peerAuth) Authenticate(ctx context.Context, token, hint string) (*AgentScope, error) {
	return p.auth.AuthenticatePeer(ctx, token, hint, p.peer, p.renewal)
}

// authenticator binds admission to the connection's peer when the configured
// authenticator supports it; otherwise it is the plain token check.
func (b *Broker) authenticator(peer netip.Addr) AgentAuthenticator {
	if auth, ok := b.opts.Auth.(PeerAuthenticator); ok && peer.IsValid() {
		return peerAuth{auth: auth, peer: peer}
	}
	return b.opts.Auth
}

func (b *Broker) renewalAuthenticator(peer netip.Addr) AgentAuthenticator {
	if auth, ok := b.opts.Auth.(PeerAuthenticator); ok && peer.IsValid() {
		return peerAuth{auth: auth, peer: peer, renewal: true}
	}
	return b.opts.Auth
}

type recheckKey struct{}

// WithRecheck marks a context as the periodic recheck of an open session.
func WithRecheck(ctx context.Context) context.Context {
	return context.WithValue(ctx, recheckKey{}, true)
}

// IsRecheck reports whether a DatabaseResolver call is the periodic recheck of
// an open session rather than an admission.
func IsRecheck(ctx context.Context) bool { v, _ := ctx.Value(recheckKey{}).(bool); return v }
