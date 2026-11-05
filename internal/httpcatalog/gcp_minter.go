package httpcatalog

import (
	"context"
	"sync/atomic"
)

// GCPMinter builds the Google token minter when the catalog first holds a gcp entry and drops it when the last goes, so neither takes a restart. With no minter a gcp request is refused (ErrGCPToken).
// Follow is its Source.OnChange hook and is never called concurrently. Building never fails the broker: a minter whose identity is missing refuses requests until it appears.
type GCPMinter struct {
	Build func() *GCPTokens

	cur atomic.Pointer[GCPTokens]
}

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
		m.cur.Store(m.Build())
	}
}

func (m *GCPMinter) Token(ctx context.Context, e *Entry) (GCPToken, error) {
	g := m.cur.Load()
	if g == nil {
		return GCPToken{}, ErrGCPToken
	}
	return g.Token(ctx, e)
}

func (m *GCPMinter) Invalidate(e *Entry) {
	if g := m.cur.Load(); g != nil {
		g.Invalidate(e)
	}
}
