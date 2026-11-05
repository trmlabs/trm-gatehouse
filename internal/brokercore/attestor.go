package brokercore

import (
	"context"
	"net/netip"
)

// Attestor admits a worker by a Pod-bound service-account token and returns NotAfter, at which adapters must end the session.
// It fails closed, and peer comes from the connection or a loopback PROXY header, never a client field.
type Attestor interface {
	Attest(ctx context.Context, token string, peer netip.Addr) (*ProxyScope, error)
}

// Reattestor rechecks an open session like Attest but accepts the original token's expiry, since sessions outlive the ten-minute token.
type Reattestor interface {
	Reattest(ctx context.Context, token string, peer netip.Addr) (*ProxyScope, error)
}

// PodRef locates an admitted pool worker Pod (empty Domain is the broker's cluster, empty Container is none) for later liveness checks.
type PodRef struct {
	Domain, Namespace, Name, UID, Container string
}

// IsZero reports a ref that names no Pod.
func (p PodRef) IsZero() bool { return p.UID == "" || p.Name == "" || p.Namespace == "" }

// LivePods reports a Pod live only if UID, Running, not deleting, worker container running and run annotation all match; a read that fails other than not-found returns an error, not false.
type LivePods interface {
	PodRunning(ctx context.Context, pod PodRef, run string) (bool, error)
}
