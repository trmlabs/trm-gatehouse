package server

import (
	"context"
	"time"
)

// The readiness gate reads a background reachability check, not a per-probe ping, which would queue behind store traffic under load and pull a healthy replica out of the Service.
const (
	storePingEvery   = 2 * time.Second
	storePingTimeout = 2 * time.Second
	// storeStaleAfter is several missed pings, not one.
	storeStaleAfter = 10 * time.Second
)

func (s *Server) watchStore(ctx context.Context) {
	ticker := time.NewTicker(storePingEvery)
	defer ticker.Stop()
	for {
		pingCtx, cancel := context.WithTimeout(ctx, storePingTimeout)
		if s.store.Ping(pingCtx) == nil {
			s.storeOK.Store(time.Now().UnixMilli())
		}
		cancel()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *Server) storeReachable(now time.Time) bool {
	last := s.storeOK.Load()
	return last != 0 && now.Sub(time.UnixMilli(last)) <= storeStaleAfter
}
