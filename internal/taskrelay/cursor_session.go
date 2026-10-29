package taskrelay

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// A Cursor worker started with --identity-socket serves one socket per claimed
// run, at <data dir>/identity/<run>.sock, owned by the worker's user with mode
// 0600 (Cursor, "OIDC tokens", Self-hosted workers; the path is the worker
// CLI's). The relay mints the run's token itself, at the moment it connects,
// so the agent never chooses which token is sent: with no claim there is no
// socket and no session, and a pool worker holds one claim at a time.
const (
	cursorMintTimeout = 3 * time.Second
	// Refresh this long before expiry; Cursor tokens live five minutes and
	// each run may mint 30 a minute.
	cursorRefreshBefore = time.Minute
	// After a failed refresh the token in hand is sent and the next mint
	// waits this long, inside the minting budget.
	cursorRetryAfter = 2 * time.Second
	cursorMaxToken   = 8 << 10
)

type cursorToken struct {
	value   string
	expires time.Time
}

// cursorMint is one mint in flight; the connections that need it wait on done
// and send value, "" when it failed and no token in hand is still valid.
type cursorMint struct {
	done  chan struct{}
	value string
}

// cursorMinter caches each socket's current token until shortly before it
// expires, so one run mints a few times an hour however busy it is.
// Connections that open together share one mint, and a refresh that fails
// leaves the token in hand to be sent until it expires.
type cursorMinter struct {
	mu      sync.Mutex
	tokens  map[string]cursorToken // by socket path and audience
	minting map[string]*cursorMint // by the same key
	retry   map[string]time.Time   // no refresh for that key before this
	claims  map[string]int         // claim sockets last seen, by directory
	now     func() time.Time
}

var cursorTokens = &cursorMinter{now: time.Now}

// token returns the claimed run's token for audience, or "" when there is no
// single claim socket or no valid token could be had: the broker then sees no
// session.
func (m *cursorMinter) token(log *slog.Logger, dir, audience string) string {
	socket, sockets := claimSocket(dir)
	m.sawClaims(log, dir, sockets)
	if socket == "" {
		return ""
	}
	key := socket + "\x00" + audience
	m.mu.Lock()
	if m.tokens == nil {
		m.tokens, m.minting, m.retry = map[string]cursorToken{}, map[string]*cursorMint{}, map[string]time.Time{}
	}
	now := m.now()
	for k, t := range m.tokens {
		if !now.Before(t.expires) {
			delete(m.tokens, k)
		}
	}
	for k, t := range m.retry {
		if !now.Before(t) {
			delete(m.retry, k)
		}
	}
	held, ok := m.tokens[key]
	if ok && now.Before(held.expires.Add(-cursorRefreshBefore)) {
		m.mu.Unlock()
		return held.value
	}
	if call := m.minting[key]; call != nil {
		m.mu.Unlock()
		if ok {
			return held.value // still valid while the refresh under way finishes
		}
		<-call.done
		return call.value
	}
	if now.Before(m.retry[key]) {
		m.mu.Unlock()
		return held.value // "" with no token in hand: no new mint inside the backoff
	}
	call := &cursorMint{done: make(chan struct{})}
	m.minting[key] = call
	m.mu.Unlock()

	minted, status, err := mintCursorToken(socket, audience)
	m.mu.Lock()
	delete(m.minting, key)
	now = m.now()
	if err == nil && !now.Before(minted.expires) {
		err = errMintExpired
	}
	if err == nil {
		m.tokens[key] = minted
		delete(m.retry, key)
		call.value = minted.value
	} else {
		m.retry[key] = now.Add(cursorRetryAfter)
		if held, ok := m.tokens[key]; ok && now.Before(held.expires) {
			call.value = held.value
		}
	}
	m.mu.Unlock()
	close(call.done)
	if err != nil {
		// The status and the cause only: never a token or the answer's body.
		log.Warn("cursor_mint_failed", "audience", audience, "status", status, "error", err.Error(), "kept", call.value != "")
	}
	return call.value
}

// sawClaims logs the claim directory holding no socket or several, once each
// time it changes to that: a connection then carries no session.
func (m *cursorMinter) sawClaims(log *slog.Logger, dir string, sockets int) {
	m.mu.Lock()
	if m.claims == nil {
		m.claims = map[string]int{}
	}
	last, seen := m.claims[dir]
	m.claims[dir] = sockets
	m.mu.Unlock()
	switch {
	case seen && last == sockets:
	case sockets == 0:
		log.Info("cursor_claim_unavailable", "dir", dir, "sockets", 0)
	case sockets > 1:
		log.Warn("cursor_claim_unavailable", "dir", dir, "sockets", sockets)
	}
}

// claimSocket is the one socket in dir, or "", and how many there are (two
// standing for two or more).
func claimSocket(dir string) (string, int) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", 0
	}
	found := ""
	for _, e := range entries {
		if e.Type()&os.ModeSocket == 0 || !strings.HasSuffix(e.Name(), ".sock") {
			continue
		}
		if found != "" {
			return "", 2 // two claims: no way to tell whose request this is
		}
		found = filepath.Join(dir, e.Name())
	}
	if found == "" {
		return "", 0
	}
	return found, 1
}

var (
	errMintAnswer  = errors.New("the answer is not a token")
	errMintExpired = errors.New("the token is already expired")
)

// mintCursorToken asks the claim socket for a token. On failure it returns the
// socket's HTTP status (0 when there was none) and why.
func mintCursorToken(socket, audience string) (cursorToken, int, error) {
	client := &http.Client{Timeout: cursorMintTimeout, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		},
		DisableKeepAlives: true, Proxy: nil}}
	body, _ := json.Marshal(map[string]string{"aud": audience})
	resp, err := client.Post("http://cursor-agent/v1/tokens/oidc", "application/json", bytes.NewReader(body))
	if err != nil {
		return cursorToken{}, 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return cursorToken{}, resp.StatusCode, errors.New("refused")
	}
	var out struct {
		Token     string `json:"token"`
		ExpiresAt int64  `json:"expires_at"`
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, cursorMaxToken+1024))
	if err != nil || json.Unmarshal(raw, &out) != nil || len(out.Token) > cursorMaxToken ||
		strings.Count(out.Token, ".") != 2 || strings.ContainsAny(out.Token, " \t\r\n") {
		return cursorToken{}, resp.StatusCode, errMintAnswer
	}
	return cursorToken{value: out.Token, expires: time.Unix(out.ExpiresAt, 0)}, resp.StatusCode, nil
}
