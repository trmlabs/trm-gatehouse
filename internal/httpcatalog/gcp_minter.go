package httpcatalog

import (
	"context"
	"sync/atomic"
)

// GCPMinter keeps the Google token minter in step with the catalog: it builds
// the minter when the catalog first holds a gcp entry and drops it when the
// last one goes, so neither takes a restart. With no minter, a gcp request is
// refused with ErrGCPToken. Follow is its Source.OnChange hook and runs once
// for the catalog the broker starts with; it is never called concurrently.
type GCPMinter struct {
	// Build makes the minter from the broker's own identity.
	Build func() (*GCPTokens, error)
	// Failed, if set, is told why a Build failed. A failed Build leaves the
	// minter unset, so gcp requests are refused until the next catalog change
	// builds it. The error must not carry secrets.
	Failed func(error)

	cur atomic.Pointer[GCPTokens]
}

// Follow builds the minter if the catalog holds a gcp entry and there is none
// yet, and drops it if the catalog holds none.
func (m *GCPMinter) Follow(c Catalog) {
	gcp := false
	for _, e := range c.Entries() {
		if e.Kind == "gcp" {
			gcp = true
			break
		}
	}
	switch {
	case !gcp:
		m.cur.Store(nil)
	case m.cur.Load() == nil && m.Build != nil:
		g, err := m.Build()
		if err != nil {
			if m.Failed != nil {
				m.Failed(err)
			}
			return
		}
		m.cur.Store(g)
	}
}

// Token mints through the current minter, or refuses if there is none.
func (m *GCPMinter) Token(ctx context.Context, e *Entry) (GCPToken, error) {
	g := m.cur.Load()
	if g == nil {
		return GCPToken{}, ErrGCPToken
	}
	return g.Token(ctx, e)
}

// Invalidate drops an entry's token after Google refused it.
func (m *GCPMinter) Invalidate(e *Entry) {
	if g := m.cur.Load(); g != nil {
		g.Invalidate(e)
	}
}
