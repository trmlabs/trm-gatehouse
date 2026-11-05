package taskrelay

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"
)

// logOutput is the structured log (JSON on stderr), separate from the audit trail; tests swap it.
var logOutput io.Writer = os.Stderr

func newRelayLog() *slog.Logger {
	return slog.New(slog.NewJSONHandler(logOutput, nil)).With("component", "gatehouse-relay")
}

// The first cause recorded wins: a later error on the other side is the consequence.
const (
	endClientClosed   = "client_closed"   // the agent closed its side
	endClientReset    = "client_reset"    // the agent's side failed
	endUpstreamClosed = "upstream_closed" // the broker side closed cleanly
	endUpstreamReset  = "upstream_reset"  // the broker side failed: reset, truncated TLS, a dead front
	endDeadline       = "deadline"        // the session's deadline passed
	endWithdrawn      = "agent_withdrawn" // the agent Pod stopped qualifying
	endRelayStopping  = "relay_stopping"  // the relay itself is stopping
)

type ending struct {
	mu     sync.Mutex
	reason string
}

func (e *ending) set(reason string) {
	if reason == "" {
		return
	}
	e.mu.Lock()
	if e.reason == "" {
		e.reason = reason
	}
	e.mu.Unlock()
}

func (e *ending) get() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.reason == "" {
		return "closed"
	}
	return e.reason
}

// readCause is the end reason for a read error, or "" when the relay closed that side itself.
func readCause(upstream bool, e error) string {
	var timeout net.Error
	switch {
	case e == nil || errors.Is(e, net.ErrClosed):
		return ""
	case errors.As(e, &timeout) && timeout.Timeout():
		return endDeadline
	case errors.Is(e, io.EOF) && upstream:
		return endUpstreamClosed
	case errors.Is(e, io.EOF):
		return endClientClosed
	case upstream:
		return endUpstreamReset
	default:
		return endClientReset
	}
}

type watchedReader struct {
	r    io.Reader
	once sync.Once
	on   func(error)
}

func (w *watchedReader) Read(p []byte) (int, error) {
	n, e := w.r.Read(p)
	if e != nil {
		w.once.Do(func() { w.on(e) })
	}
	return n, e
}

func watch(r io.Reader, upstream bool, end *ending) io.Reader {
	return &watchedReader{r: r, on: func(e error) { end.set(readCause(upstream, e)) }}
}

func stopCause(ctx context.Context) string {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return endDeadline
	}
	return endRelayStopping
}

// normalEnds are counted, not logged one by one; every other end gets its own line.
var normalEnds = map[string]bool{endClientClosed: true, endUpstreamClosed: true, endDeadline: true, endRelayStopping: true, "closed": true}

var sessionSummaryWindow = time.Minute

// logClose logs an abnormal end on its own line and counts a normal one into a periodic summary.
func (r *relay) logClose(protocol, peer string, agent agentIdentity, upstream, target string, started time.Time, end *ending) {
	reason := end.get()
	individually := true
	if reason == endUpstreamReset || reason == endUpstreamClosed {
		individually = r.upstreams.ended(r.log, upstream, reason)
	}
	if normalEnds[reason] {
		r.closes.count(r.log, protocol, reason)
		return
	}
	if !individually {
		return // counted into this window's upstream_dropped_sessions
	}
	level := slog.LevelInfo
	if reason == endUpstreamReset {
		level = slog.LevelWarn
	}
	r.log.LogAttrs(context.Background(), level, "session_closed", slog.String("protocol", protocol), slog.String("reason", reason),
		slog.String("peer", peer), slog.String("pod", agent.pod), slog.String("target", target), slog.String("upstream", upstream),
		slog.Int64("durationMs", time.Since(started).Milliseconds()))
}

type closeCounts struct {
	mu      sync.Mutex
	counts  map[string]int
	pending bool
}

func (c *closeCounts) count(log *slog.Logger, protocol, reason string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.counts == nil {
		c.counts = map[string]int{}
	}
	c.counts[protocol+":"+reason]++
	if c.pending {
		return
	}
	c.pending = true
	window := sessionSummaryWindow
	time.AfterFunc(window, func() {
		c.mu.Lock()
		counts := c.counts
		c.counts, c.pending = nil, false
		c.mu.Unlock()
		if len(counts) != 0 {
			log.Info("sessions_closed", "counts", counts, "windowMs", window.Milliseconds())
		}
	})
}

func (c *closeCounts) flush(log *slog.Logger) {
	c.mu.Lock()
	counts := c.counts
	c.counts, c.pending = nil, false
	c.mu.Unlock()
	if len(counts) != 0 {
		log.Info("sessions_closed", "counts", counts, "final", true)
	}
}

// This many broker-side ends within the window are one event (an upstream dropping connections together), logged once with the count.
const (
	massCloseWindow  = time.Second
	massCloseMinimum = 5
)

type upstreamWatch struct {
	mu    sync.Mutex
	state map[string]*upstreamState
}

type upstreamState struct {
	down       bool
	downSince  time.Time
	windowEnds int
	resets     int
	suppressed int // ends in this window logged only in the window's count
	windowOpen bool
}

func (w *upstreamWatch) get(address string) *upstreamState {
	if w.state == nil {
		w.state = map[string]*upstreamState{}
	}
	s := w.state[address]
	if s == nil {
		s = &upstreamState{}
		w.state[address] = s
	}
	return s
}

// ended says whether the end gets its own log line: the first massCloseMinimum per window do,
// and the rest of a burst are counted as suppressed.
func (w *upstreamWatch) ended(log *slog.Logger, address, reason string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	s := w.get(address)
	s.windowEnds++
	if reason == endUpstreamReset {
		s.resets++
	}
	individually := s.windowEnds <= massCloseMinimum
	if !individually {
		s.suppressed++
	}
	if s.windowOpen {
		return individually
	}
	s.windowOpen = true
	time.AfterFunc(massCloseWindow, func() {
		w.mu.Lock()
		ends, resets, suppressed := s.windowEnds, s.resets, s.suppressed
		s.windowEnds, s.resets, s.suppressed, s.windowOpen = 0, 0, 0, false
		w.mu.Unlock()
		if ends >= massCloseMinimum {
			log.Warn("upstream_dropped_sessions", "upstream", address, "sessions", ends, "resets", resets,
				"suppressed", suppressed, "windowMs", massCloseWindow.Milliseconds())
		}
	})
	return individually
}

func (w *upstreamWatch) dialed(log *slog.Logger, address string, e error) {
	w.mu.Lock()
	s := w.get(address)
	wasDown, since := s.down, s.downSince
	if e != nil && !s.down {
		s.down, s.downSince = true, time.Now()
	}
	if e == nil {
		s.down = false
	}
	w.mu.Unlock()
	switch {
	case e != nil && !wasDown:
		log.Warn("upstream_unreachable", "upstream", address, "error", e.Error())
	case e == nil && wasDown:
		log.Info("upstream_restored", "upstream", address, "downMs", time.Since(since).Milliseconds())
	}
}

// refusalWatch logs refused new connections once per window with their count.
type refusalWatch struct {
	mu      sync.Mutex
	count   int
	pending bool
}

func (w *refusalWatch) refused(log *slog.Logger, limit, reason string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.count++
	if w.pending {
		return
	}
	w.pending = true
	time.AfterFunc(massCloseWindow, func() {
		w.mu.Lock()
		n := w.count
		w.count, w.pending = 0, false
		w.mu.Unlock()
		log.Warn("connections_refused", "reason", reason, "limit", limit, "refused", n, "windowMs", massCloseWindow.Milliseconds())
	})
}
