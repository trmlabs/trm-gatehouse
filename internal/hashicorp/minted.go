package hashicorp

import (
	"errors"
	"log/slog"
	"strings"
	"sync"
)

// ErrNotMinted marks a revocation the broker refused because it did not mint
// the lease or token: Vault's policy cannot limit a revoke to the broker's own,
// so the broker does.
var ErrNotMinted = errors.New("revoke refused: not minted by this broker")

// Revocation kinds named in a refusal.
const (
	RevokeKindLease   = "lease"
	RevokeKindSession = "session"
)

// mintedSet is what this broker minted and has not yet revoked: database lease
// IDs and child token accessors. It is shared by a client and its sessions.
type mintedSet struct {
	mu        sync.Mutex
	leases    map[string]struct{}
	accessors map[string]struct{}
}

func (m *mintedSet) add(set *map[string]struct{}, id string) {
	if id == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if *set == nil {
		*set = map[string]struct{}{}
	}
	(*set)[id] = struct{}{}
}

func (m *mintedSet) has(set map[string]struct{}, id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := set[id]
	return ok
}

func (m *mintedSet) drop(set map[string]struct{}, id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(set, id)
}

// minted returns the client's minted set, shared with every session it opens.
func (c *Client) mintedSet() *mintedSet {
	if m := c.minted.Load(); m != nil {
		return m
	}
	c.minted.CompareAndSwap(nil, &mintedSet{})
	return c.minted.Load()
}

// AdoptLease records a lease this broker minted in an earlier run and kept in
// its own cleanup journal, so a restarted replica can still revoke it.
func (c *Client) AdoptLease(leaseID string) {
	m := c.mintedSet()
	m.add(&m.leases, leaseID)
}

// AdoptSession is AdoptLease for a child token's accessor.
func (c *Client) AdoptSession(accessor string) {
	m := c.mintedSet()
	m.add(&m.accessors, accessor)
}

func (c *Client) noteLease(leaseID string) {
	m := c.mintedSet()
	m.add(&m.leases, leaseID)
}

func (c *Client) noteSession(accessor string) {
	m := c.mintedSet()
	m.add(&m.accessors, accessor)
}

func (c *Client) forgetLease(leaseID string) {
	m := c.mintedSet()
	m.drop(m.leases, leaseID)
}

func (c *Client) forgetSession(accessor string) {
	m := c.mintedSet()
	m.drop(m.accessors, accessor)
}

// SetRevokeRefusal sets what runs when a revocation is refused, with its kind.
// The server records an audit row; no identifier is passed, since the refused
// ID belongs to someone else.
func (c *Client) SetRevokeRefusal(fn func(kind string)) {
	c.refusal.Store(&fn)
}

// gatehouseOnlyRole reports whether a lease ID is under a Gatehouse-only role
// (<mount>/creds/gatehouse-...). Only the broker leases from those roles, so a
// lease there is the broker's even when its request was lost before it could be
// recorded (the orphan sweep revokes those).
func gatehouseOnlyRole(leaseID string) bool {
	_, rest, ok := strings.Cut(leaseID, "/creds/")
	return ok && strings.HasPrefix(rest, "gatehouse-")
}

// allowLeaseRevoke is nil for a lease the broker minted, kept in its journal or
// leased under a Gatehouse-only role; else it refuses and reports.
func (c *Client) allowLeaseRevoke(leaseID string) error {
	m := c.mintedSet()
	if m.has(m.leases, leaseID) || gatehouseOnlyRole(leaseID) {
		return nil
	}
	return c.refuseRevoke(RevokeKindLease)
}

func (c *Client) allowSessionRevoke(accessor string) error {
	m := c.mintedSet()
	if m.has(m.accessors, accessor) {
		return nil
	}
	return c.refuseRevoke(RevokeKindSession)
}

func (c *Client) refuseRevoke(kind string) error {
	if c.logger != nil {
		c.logger.Warn("vault revoke refused: not minted by this broker", slog.String("kind", kind))
	}
	if fn := c.refusal.Load(); fn != nil && *fn != nil {
		(*fn)(kind)
	}
	return ErrNotMinted
}
