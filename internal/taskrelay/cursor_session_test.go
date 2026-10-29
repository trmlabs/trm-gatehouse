package taskrelay

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// identitySocket is a fake claim socket serving Cursor's mint API. It answers
// with status and a token ending in the mint count; with gate set, each mint
// first takes a value from it, and asked receives one per mint request.
type identitySocket struct {
	mints  atomic.Int32
	status atomic.Int32
	gate   chan struct{}
	asked  chan struct{}
}

func serveIdentitySocket(t *testing.T, dir, name string, s *identitySocket, expires func() int64) {
	t.Helper()
	l, err := net.Listen("unix", filepath.Join(dir, name+".sock"))
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct{ Aud string }
		if r.Method != http.MethodPost || r.URL.Path != "/v1/tokens/oidc" || r.Header.Get("Content-Type") != "application/json" ||
			json.NewDecoder(r.Body).Decode(&body) != nil || body.Aud != "gatehouse-broker" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		n := s.mints.Add(1)
		if s.asked != nil {
			s.asked <- struct{}{}
		}
		if s.gate != nil {
			<-s.gate
		}
		w.WriteHeader(int(s.status.Load()))
		_ = json.NewEncoder(w).Encode(map[string]any{"token": fmt.Sprintf("h.p.%s%d", name, n), "expires_at": expires()})
	}), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
}

// fakeIdentitySocket serves Cursor's mint API on dir/<name>.sock, answering
// with status and a token ending in the mint count.
func fakeIdentitySocket(t *testing.T, dir, name string, status int, expires func() int64) *atomic.Int32 {
	t.Helper()
	s := &identitySocket{}
	s.status.Store(int32(status))
	serveIdentitySocket(t, dir, name, s, expires)
	return &s.mints
}

var quiet = slog.New(slog.NewJSONHandler(io.Discard, nil))

// socketDir is short: a Unix socket path must fit in about 100 bytes.
func socketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "cid")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func TestCursorTokenIsMintedFromTheClaimSocketAndCached(t *testing.T) {
	dir := socketDir(t)
	now := time.Now()
	m := &cursorMinter{now: func() time.Time { return now }}
	mints := fakeIdentitySocket(t, dir, "bc-1", http.StatusOK, func() int64 { return now.Add(5 * time.Minute).Unix() })
	if got := m.token(quiet, dir, "gatehouse-broker"); got != "h.p.bc-11" {
		t.Fatalf("first: %q", got)
	}
	if got := m.token(quiet, dir, "gatehouse-broker"); got != "h.p.bc-11" || mints.Load() != 1 {
		t.Fatalf("cached: %q after %d mints", got, mints.Load())
	}
	// Within a minute of expiry the relay mints a fresh one.
	now = now.Add(4*time.Minute + time.Second)
	if got := m.token(quiet, dir, "gatehouse-broker"); got != "h.p.bc-12" || mints.Load() != 2 {
		t.Fatalf("refreshed: %q after %d mints", got, mints.Load())
	}
}

// A refresh that fails keeps sending the token in hand until it expires, and
// the socket is not asked again for a moment.
func TestCursorFailedRefreshKeepsTheValidToken(t *testing.T) {
	sink := captureLog(t)
	log := newRelayLog()
	dir := socketDir(t)
	var clock atomic.Int64
	clock.Store(time.Now().UnixNano())
	now := func() time.Time { return time.Unix(0, clock.Load()) }
	m := &cursorMinter{now: now}
	s := &identitySocket{}
	s.status.Store(http.StatusOK)
	serveIdentitySocket(t, dir, "bc-1", s, func() int64 { return now().Add(5 * time.Minute).Unix() })
	if got := m.token(log, dir, "gatehouse-broker"); got != "h.p.bc-11" {
		t.Fatalf("first: %q", got)
	}
	clock.Add(int64(4*time.Minute + time.Second))
	s.status.Store(http.StatusServiceUnavailable)
	if got := m.token(log, dir, "gatehouse-broker"); got != "h.p.bc-11" || s.mints.Load() != 2 {
		t.Fatalf("failed refresh: %q after %d mints", got, s.mints.Load())
	}
	if got := m.token(log, dir, "gatehouse-broker"); got != "h.p.bc-11" || s.mints.Load() != 2 {
		t.Fatalf("right after: %q after %d mints", got, s.mints.Load())
	}
	clock.Add(int64(cursorRetryAfter))
	s.status.Store(http.StatusOK)
	if got := m.token(log, dir, "gatehouse-broker"); got != "h.p.bc-13" || s.mints.Load() != 3 {
		t.Fatalf("retried: %q after %d mints", got, s.mints.Load())
	}
	lines := sink.lines(t, "cursor_mint_failed")
	if len(lines) != 1 || lines[0]["status"] != float64(http.StatusServiceUnavailable) || lines[0]["kept"] != true || lines[0]["level"] != "WARN" {
		t.Fatalf("failure lines %v", lines)
	}
	// An expired token is not sent, and neither is any token logged.
	clock.Add(int64(5 * time.Minute))
	s.status.Store(http.StatusForbidden)
	if got := m.token(log, dir, "gatehouse-broker"); got != "" {
		t.Fatalf("expired: %q", got)
	}
	if lines := sink.lines(t, "cursor_mint_failed"); len(lines) != 2 || lines[1]["kept"] != false || lines[1]["status"] != float64(http.StatusForbidden) {
		t.Fatalf("failure lines %v", lines)
	}
	sink.mu.Lock()
	logged := sink.b.String()
	sink.mu.Unlock()
	if strings.Contains(logged, "h.p.") {
		t.Fatalf("a token reached the log: %s", logged)
	}
}

// Connections that open together share one mint.
func TestCursorConnectionsShareOneMint(t *testing.T) {
	dir := socketDir(t)
	s := &identitySocket{gate: make(chan struct{}, 1), asked: make(chan struct{}, 16)}
	s.status.Store(http.StatusOK)
	serveIdentitySocket(t, dir, "bc-1", s, func() int64 { return time.Now().Add(5 * time.Minute).Unix() })
	defer close(s.gate)
	m := &cursorMinter{now: time.Now}
	const n = 8
	got := make(chan string, n)
	for range n {
		go func() { got <- m.token(quiet, dir, "gatehouse-broker") }()
	}
	<-s.asked
	time.Sleep(100 * time.Millisecond) // the rest reach the mint in flight
	s.gate <- struct{}{}
	for range n {
		if v := <-got; v != "h.p.bc-11" {
			t.Errorf("%q", v)
		}
	}
	if s.mints.Load() != 1 {
		t.Fatalf("%d mints for %d connections", s.mints.Load(), n)
	}
}

// While one connection refreshes the token, the others send the one in hand
// without waiting.
func TestCursorRefreshUnderWayServesTheHeldToken(t *testing.T) {
	dir := socketDir(t)
	var clock atomic.Int64
	clock.Store(time.Now().UnixNano())
	now := func() time.Time { return time.Unix(0, clock.Load()) }
	s := &identitySocket{gate: make(chan struct{}, 1), asked: make(chan struct{}, 4)}
	s.status.Store(http.StatusOK)
	serveIdentitySocket(t, dir, "bc-1", s, func() int64 { return now().Add(5 * time.Minute).Unix() })
	defer close(s.gate)
	m := &cursorMinter{now: now}
	s.gate <- struct{}{}
	if got := m.token(quiet, dir, "gatehouse-broker"); got != "h.p.bc-11" {
		t.Fatalf("first: %q", got)
	}
	<-s.asked
	clock.Add(int64(4*time.Minute + time.Second))
	refreshed := make(chan string, 1)
	go func() { refreshed <- m.token(quiet, dir, "gatehouse-broker") }()
	<-s.asked
	if got := m.token(quiet, dir, "gatehouse-broker"); got != "h.p.bc-11" || s.mints.Load() != 2 {
		t.Fatalf("during the refresh: %q after %d mints", got, s.mints.Load())
	}
	s.gate <- struct{}{}
	if got := <-refreshed; got != "h.p.bc-12" {
		t.Fatalf("refreshed: %q", got)
	}
	if got := m.token(quiet, dir, "gatehouse-broker"); got != "h.p.bc-12" || s.mints.Load() != 2 {
		t.Fatalf("after: %q after %d mints", got, s.mints.Load())
	}
}

// No claim socket, or several, is logged once each time the directory turns
// to it, not once per connection.
func TestCursorClaimChangesAreLoggedOnce(t *testing.T) {
	sink := captureLog(t)
	log := newRelayLog()
	dir := socketDir(t)
	later := func() int64 { return time.Now().Add(5 * time.Minute).Unix() }
	m := &cursorMinter{now: time.Now}
	for range 3 {
		m.token(log, dir, "gatehouse-broker")
	}
	fakeIdentitySocket(t, dir, "bc-1", http.StatusOK, later)
	if got := m.token(log, dir, "gatehouse-broker"); got != "h.p.bc-11" {
		t.Fatalf("one claim: %q", got)
	}
	fakeIdentitySocket(t, dir, "bc-2", http.StatusOK, later)
	for range 3 {
		m.token(log, dir, "gatehouse-broker")
	}
	lines := sink.lines(t, "cursor_claim_unavailable")
	if len(lines) != 2 || lines[0]["sockets"] != float64(0) || lines[0]["level"] != "INFO" ||
		lines[1]["sockets"] != float64(2) || lines[1]["level"] != "WARN" {
		t.Fatalf("claim lines %v", lines)
	}
}

func TestCursorTokenNeedsExactlyOneClaim(t *testing.T) {
	dir := socketDir(t)
	m := &cursorMinter{now: time.Now}
	later := func() int64 { return time.Now().Add(5 * time.Minute).Unix() }
	if got := m.token(quiet, dir, "gatehouse-broker"); got != "" {
		t.Fatalf("no claim: %q", got)
	}
	if got := m.token(quiet, filepath.Join(dir, "missing"), "gatehouse-broker"); got != "" {
		t.Fatalf("no directory: %q", got)
	}
	// A regular file named like a socket is not a claim.
	if err := os.WriteFile(filepath.Join(dir, "bc-0.sock"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	fakeIdentitySocket(t, dir, "bc-1", http.StatusOK, later)
	if got := m.token(quiet, dir, "gatehouse-broker"); got != "h.p.bc-11" {
		t.Fatalf("one claim: %q", got)
	}
	fakeIdentitySocket(t, dir, "bc-2", http.StatusOK, later)
	if got := (&cursorMinter{now: time.Now}).token(quiet, dir, "gatehouse-broker"); got != "" {
		t.Fatalf("two claims: %q", got)
	}
}

func TestCursorMintFailuresSendNothing(t *testing.T) {
	for name, c := range map[string]struct {
		status  int
		expires func() int64
	}{
		"refused":         {http.StatusForbidden, func() int64 { return time.Now().Add(time.Minute).Unix() }},
		"already expired": {http.StatusOK, func() int64 { return time.Now().Add(-time.Second).Unix() }},
	} {
		t.Run(name, func(t *testing.T) {
			dir := socketDir(t)
			fakeIdentitySocket(t, dir, "bc-1", c.status, c.expires)
			if got := (&cursorMinter{now: time.Now}).token(quiet, dir, "gatehouse-broker"); got != "" {
				t.Fatalf("%q", got)
			}
		})
	}
}

func TestSelfModeCursorSessionSource(t *testing.T) {
	valid := func(c *FixedConfig) {
		c.PostgresBindings[0].Upstream.SessionSocketDir = "/var/run/cursor-identity"
		c.PostgresBindings[0].Upstream.SessionAudience = "gatehouse-broker"
	}
	c := selfConfig()
	c.PostgresBindings = append([]PostgresConfig(nil), c.PostgresBindings...)
	valid(&c)
	if err := c.Validate(time.Now()); err != nil {
		t.Fatalf("valid Cursor source refused: %v", err)
	}
	for name, mutate := range map[string]func(*FixedConfig){
		"relative directory":   func(c *FixedConfig) { c.PostgresBindings[0].Upstream.SessionSocketDir = "identity" },
		"no audience":          func(c *FixedConfig) { c.PostgresBindings[0].Upstream.SessionAudience = "" },
		"audience with spaces": func(c *FixedConfig) { c.PostgresBindings[0].Upstream.SessionAudience = "a b" },
		"also a session file":  func(c *FixedConfig) { c.PostgresBindings[0].Upstream.SessionFile = "/run/token" },
		"audience alone": func(c *FixedConfig) {
			c.PostgresBindings[0].Upstream.SessionSocketDir = ""
		},
	} {
		c := selfConfig()
		c.PostgresBindings = append([]PostgresConfig(nil), c.PostgresBindings...)
		valid(&c)
		mutate(&c)
		if c.Validate(time.Now()) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Only a sidecar in the run's own Pod may mint for it.
	paired := selfConfig()
	paired.Self = false
	paired.PostgresBindings = append([]PostgresConfig(nil), paired.PostgresBindings...)
	valid(&paired)
	if paired.Validate(time.Now()) == nil {
		t.Error("paired relay with a Cursor source accepted")
	}
}

// Each connection's session comes from the claim socket when one is configured.
func TestReadSessionMintsFromTheCursorSocket(t *testing.T) {
	dir := socketDir(t)
	fakeIdentitySocket(t, dir, "bc-9", http.StatusOK, func() int64 { return time.Now().Add(5 * time.Minute).Unix() })
	if got := readSession(quiet, UpstreamConfig{SessionSocketDir: dir, SessionAudience: "gatehouse-broker"}); got != "h.p.bc-91" {
		t.Fatalf("%q", got)
	}
}

// A connection that finds no claim yet waits for it instead of going out
// without a session.
func TestAwaitSessionWaitsForTheClaim(t *testing.T) {
	dir := socketDir(t)
	late := &identitySocket{}
	late.status.Store(http.StatusOK)
	go func() {
		time.Sleep(700 * time.Millisecond)
		serveIdentitySocket(t, dir, "bc-7", late, func() int64 { return time.Now().Add(5 * time.Minute).Unix() })
	}()
	got := awaitSession(context.Background(), quiet, UpstreamConfig{SessionSocketDir: dir, SessionAudience: "gatehouse-broker"}, 3*time.Second)
	if !strings.HasPrefix(got, "h.p.bc-7") {
		t.Fatalf("%q", got)
	}
}

func TestAwaitSessionGivesUpAfterTheWait(t *testing.T) {
	dir := socketDir(t)
	start := time.Now()
	if got := awaitSession(context.Background(), quiet, UpstreamConfig{SessionSocketDir: dir, SessionAudience: "gatehouse-broker"}, time.Second); got != "" {
		t.Fatalf("%q", got)
	}
	if d := time.Since(start); d < time.Second || d > 2*time.Second {
		t.Fatalf("waited %v", d)
	}
}

// Without a Cursor socket the session is read once, as before.
func TestAwaitSessionReadsOnceWithoutASocketSource(t *testing.T) {
	start := time.Now()
	if got := awaitSession(context.Background(), quiet, UpstreamConfig{}, 5*time.Second); got != "" || time.Since(start) > time.Second {
		t.Fatalf("%q after %v", got, time.Since(start))
	}
}

// With no token in hand, a failed mint is not retried until the backoff ends,
// so waiting connections do not hammer the mint API.
func TestCursorFailedMintWithNoTokenBacksOff(t *testing.T) {
	dir := socketDir(t)
	mints := fakeIdentitySocket(t, dir, "bc-2", http.StatusForbidden, func() int64 { return time.Now().Add(time.Minute).Unix() })
	m := &cursorMinter{now: time.Now}
	for range 5 {
		if got := m.token(quiet, dir, "gatehouse-broker"); got != "" {
			t.Fatalf("%q", got)
		}
	}
	if n := mints.Load(); n != 1 {
		t.Fatalf("%d mints inside the backoff", n)
	}
}

// A first mint that fails and a retry after the backoff that succeeds both
// land inside the wait.
func TestAwaitSessionSurvivesAFailedFirstMint(t *testing.T) {
	dir := socketDir(t)
	sock := &identitySocket{}
	sock.status.Store(http.StatusForbidden)
	serveIdentitySocket(t, dir, "bc-5", sock, func() int64 { return time.Now().Add(5 * time.Minute).Unix() })
	go func() {
		time.Sleep(500 * time.Millisecond)
		sock.status.Store(http.StatusOK)
	}()
	got := awaitSession(context.Background(), quiet, UpstreamConfig{SessionSocketDir: dir, SessionAudience: "gatehouse-broker"}, sessionWait)
	if !strings.HasPrefix(got, "h.p.bc-5") || sock.mints.Load() != 2 {
		t.Fatalf("%q after %d mints", got, sock.mints.Load())
	}
}
