// Package githubapp mints short-lived GitHub App installation tokens scoped to one repository; the App key is held by a signer, never a worker.
package githubapp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// App identifies an installation of a GitHub App on one account.
type App struct {
	AppID          int64
	InstallationID int64
}

// JWTSigner returns an RS256 signature over input with the App's private key.
type JWTSigner interface {
	SignRS256(ctx context.Context, input []byte) ([]byte, error)
}

// Permissions is the scope a token is minted with beyond metadata read; only these can be requested.
type Permissions struct {
	Contents     string // "", "read" or "write"
	PullRequests string // "" or "write"
	Actions      string // "", "read" or "write"
	Deployments  string // "" or "read"
	Checks       string // "" or "read"
	Statuses     string // "" or "read"
}

// PullRequestsWrite carries contents read because GitHub checks the head and base refs with it.
var (
	ContentsRead      = Permissions{Contents: "read"}
	ContentsWrite     = Permissions{Contents: "write"}
	PullRequestsWrite = Permissions{Contents: "read", PullRequests: "write"}
	ActionsRead       = Permissions{Actions: "read"}
	DeploymentsRead   = Permissions{Deployments: "read"}
	ChecksRead        = Permissions{Checks: "read"}
	StatusesRead      = Permissions{Statuses: "read"}
	// UpdateBranch and marking a draft ready need contents write besides pull requests write.
	ActionsWrite = Permissions{Actions: "write"}
	UpdateBranch = Permissions{Contents: "write", PullRequests: "write"}
)

func (p Permissions) valid() bool {
	return (p.Contents == "" || p.Contents == "read" || p.Contents == "write") && (p.PullRequests == "" || p.PullRequests == "write") &&
		(p.Actions == "" || p.Actions == "read" || p.Actions == "write") && (p.Deployments == "" || p.Deployments == "read") &&
		(p.Checks == "" || p.Checks == "read") && (p.Statuses == "" || p.Statuses == "read") && p != Permissions{}
}

func (p Permissions) request() map[string]string {
	out := map[string]string{"metadata": "read"}
	if p.Contents != "" {
		out["contents"] = p.Contents
	}
	if p.PullRequests != "" {
		out["pull_requests"] = p.PullRequests
	}
	if p.Actions != "" {
		out["actions"] = p.Actions
	}
	if p.Deployments != "" {
		out["deployments"] = p.Deployments
	}
	if p.Checks != "" {
		out["checks"] = p.Checks
	}
	if p.Statuses != "" {
		out["statuses"] = p.Statuses
	}
	return out
}

// Token is an installation token. It prints as its scope only.
type Token struct {
	value string
	Repo  string
	// RepoID is GitHub's numeric id of Repo, or 0 when GitHub gave none.
	RepoID      int64
	Permissions Permissions
	Expires     time.Time
}

func (t Token) Value() string { return t.value }
func (t Token) String() string {
	return fmt.Sprintf("github-token(%s contents=%s pull_requests=%s actions=%s deployments=%s checks=%s statuses=%s)", t.Repo,
		t.Permissions.Contents, t.Permissions.PullRequests, t.Permissions.Actions, t.Permissions.Deployments, t.Permissions.Checks, t.Permissions.Statuses)
}
func (t Token) GoString() string           { return t.String() }
func (t Token) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(t.String())) }

var ErrUnavailable = errors.New("github installation token unavailable")

// Minter mints and caches tokens per (installation, repository, access), reusing one until ten minutes before expiry.
// Concurrent requests share a mint, and a failed mint is not retried for five seconds.
type Minter struct {
	Signer JWTSigner
	API    string // default https://api.github.com
	Client *http.Client
	Now    func() time.Time
	// Scope returns what the catalog grants an installation; tokens are refused while GitHub's installation is wider.
	Scope func(installation int64) Scope
	// ScopeMode: empty or ScopeRefuse stops tokens for an over-wide installation, ScopeWarn reports and serves.
	ScopeMode ScopeMode
	// ScopeTimeout bounds one installation check including all pages. Default 5 minutes.
	ScopeTimeout time.Duration
	Log          *slog.Logger

	// scopeMu guards the verdicts only; checks run outside it, one per installation.
	scopeMu       sync.Mutex
	scopes        map[int64]scopeVerdict
	scopeChecking map[int64]chan struct{}
	scopeGen      uint64

	mu          sync.Mutex
	cache       map[tokenKey]Token
	failed      map[tokenKey]time.Time
	flight      map[tokenKey]*sync.Mutex
	invalidated map[tokenKey]time.Time
}

type tokenKey struct {
	installation int64
	repo         string
	permissions  Permissions
}

const (
	refreshBefore      = 10 * time.Minute
	failureBackoff     = 5 * time.Second
	invalidateInterval = 30 * time.Second
)

func (m *Minter) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

// Token returns a token for repo ("owner/name") with exactly permissions plus
// metadata read. Nothing else is ever requested.
func (m *Minter) Token(ctx context.Context, app App, repo string, permissions Permissions) (Token, error) {
	if !permissions.valid() || !m.repoListed(app, repo) || m.checkScope(ctx, app) != nil {
		return Token{}, ErrUnavailable
	}
	key := tokenKey{app.InstallationID, strings.ToLower(repo), permissions}
	m.mu.Lock()
	if m.cache == nil {
		m.cache, m.failed, m.flight, m.invalidated = map[tokenKey]Token{}, map[tokenKey]time.Time{}, map[tokenKey]*sync.Mutex{}, map[tokenKey]time.Time{}
	}
	if t, ok := m.cache[key]; ok && t.Expires.Sub(m.now()) > refreshBefore {
		m.mu.Unlock()
		return t, nil
	}
	lock, ok := m.flight[key]
	if !ok {
		lock = &sync.Mutex{}
		m.flight[key] = lock
	}
	m.mu.Unlock()

	lock.Lock()
	defer lock.Unlock()
	m.mu.Lock()
	cached, have := m.cache[key]
	failedAt, failed := m.failed[key]
	m.mu.Unlock()
	if have && cached.Expires.Sub(m.now()) > refreshBefore {
		return cached, nil
	}
	if failed && m.now().Sub(failedAt) < failureBackoff {
		return Token{}, ErrUnavailable
	}
	t, err := m.mint(ctx, app, key)
	m.mu.Lock()
	defer m.mu.Unlock()
	if err != nil {
		m.failed[key] = m.now()
		return Token{}, ErrUnavailable
	}
	delete(m.failed, key)
	m.cache[key] = t
	return t, nil
}

// Invalidate drops a cached token after GitHub rejects it, at most once per key every 30 seconds.
func (m *Minter) Invalidate(app App, repo string, permissions Permissions) {
	key := tokenKey{app.InstallationID, strings.ToLower(repo), permissions}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.invalidated == nil {
		m.invalidated = map[tokenKey]time.Time{}
	}
	if last, ok := m.invalidated[key]; ok && m.now().Sub(last) < invalidateInterval {
		return
	}
	m.invalidated[key] = m.now()
	if t, ok := m.cache[key]; ok {
		// GitHub rejected it; revoke it anyway so no copy outlives its use.
		go m.revoke(m.api(), m.client(), t.value)
	}
	delete(m.cache, key)
}

// Prune revokes and drops every cached token keep no longer allows.
func (m *Minter) Prune(keep func(installation int64, repo string, p Permissions) bool) {
	m.mu.Lock()
	var gone []string
	for key, t := range m.cache {
		if !keep(key.installation, key.repo, key.permissions) {
			gone = append(gone, t.value)
			delete(m.cache, key)
		}
	}
	m.mu.Unlock()
	for _, value := range gone {
		m.revoke(m.api(), m.client(), value)
	}
}

// RevokeAll revokes every cached token on shutdown, since GitHub honours one for up to an hour.
func (m *Minter) RevokeAll() { m.Prune(func(int64, string, Permissions) bool { return false }) }

func (m *Minter) api() string {
	if api := strings.TrimSuffix(m.API, "/"); api != "" {
		return api
	}
	return "https://api.github.com"
}

func (m *Minter) client() *http.Client {
	if m.Client != nil {
		return m.Client
	}
	return &http.Client{Timeout: 15 * time.Second}
}

func (m *Minter) jwt(ctx context.Context, appID int64) (string, error) {
	now := m.now()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claims, _ := json.Marshal(map[string]int64{"iat": now.Add(-time.Minute).Unix(), "exp": now.Add(9 * time.Minute).Unix(), "iss": appID})
	input := header + "." + base64.RawURLEncoding.EncodeToString(claims)
	signature, err := m.Signer.SignRS256(ctx, []byte(input))
	if err != nil || len(signature) == 0 {
		return "", ErrUnavailable
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func (m *Minter) mint(ctx context.Context, app App, key tokenKey) (Token, error) {
	owner, name, ok := strings.Cut(key.repo, "/")
	if m.Signer == nil || app.AppID <= 0 || app.InstallationID <= 0 || !ok || owner == "" || name == "" {
		return Token{}, ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	jwt, err := m.jwt(ctx, app.AppID)
	if err != nil {
		return Token{}, err
	}
	requested := key.permissions.request()
	body, _ := json.Marshal(map[string]any{"repositories": []string{name}, "permissions": requested})
	api := m.api()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, api+"/app/installations/"+strconv.FormatInt(app.InstallationID, 10)+"/access_tokens", bytes.NewReader(body))
	if err != nil {
		return Token{}, ErrUnavailable
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Content-Type", "application/json")
	client := m.client()
	resp, err := client.Do(req)
	if err != nil {
		return Token{}, ErrUnavailable
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil || resp.StatusCode != http.StatusCreated {
		return Token{}, ErrUnavailable
	}
	var granted struct {
		Token        string            `json:"token"`
		ExpiresAt    time.Time         `json:"expires_at"`
		Permissions  map[string]string `json:"permissions"`
		Repositories []struct {
			ID       int64  `json:"id"`
			FullName string `json:"full_name"`
		} `json:"repositories"`
	}
	if json.Unmarshal(data, &granted) != nil || !tokenShape(granted.Token) || !granted.ExpiresAt.After(m.now().Add(refreshBefore)) {
		return Token{}, ErrUnavailable
	}
	// Refuse and revoke a token broader than requested.
	wide := len(granted.Repositories) != 1 || !strings.EqualFold(granted.Repositories[0].FullName, key.repo)
	for name, level := range granted.Permissions {
		if want, ok := requested[name]; !ok || level != want {
			wide = true
		}
	}
	for name, want := range requested {
		if name != "metadata" && granted.Permissions[name] != want {
			wide = true // a requested permission is missing
		}
	}
	if wide {
		m.revoke(api, client, granted.Token)
		return Token{}, ErrUnavailable
	}
	return Token{value: granted.Token, Repo: key.repo, RepoID: max(granted.Repositories[0].ID, 0), Permissions: key.permissions, Expires: granted.ExpiresAt}, nil
}

func (m *Minter) revoke(api string, client *http.Client, token string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, api+"/installation/token", nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	if resp, err := client.Do(req); err == nil {
		_ = resp.Body.Close()
	}
}

// maxTokenBytes bounds an installation token (about 520 characters today) and fits any request header.
const maxTokenBytes = 4096

// tokenShape checks only that a token is safe in a header: plausible length and URL-safe base64 plus dots. The value is otherwise opaque.
func tokenShape(t string) bool {
	if len(t) < 20 || len(t) > maxTokenBytes {
		return false
	}
	for i := 0; i < len(t); i++ {
		c := t[i]
		if alnum := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'; !alnum && c != '_' && c != '-' && c != '.' {
			return false
		}
	}
	return true
}
