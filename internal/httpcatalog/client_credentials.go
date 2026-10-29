package httpcatalog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ClientCredentialsBinding, header entries only, makes the broker mint the
// entry's key instead of reading it: an OAuth 2.0 access token from the
// client-credentials grant (RFC 6749 section 4.4), for an API that takes only
// short-lived tokens, such as one behind Auth0 machine-to-machine
// applications. The client's ID and secret come from Vault and go only to
// TokenHost. The worker sends the placeholder as its Bearer token and never
// holds the client or the token.
type ClientCredentialsBinding struct {
	// TokenHost is the authorization server's exact DNS name. The broker
	// posts to https://TokenHost/TokenPath on port 443 and nowhere else.
	TokenHost string `json:"tokenHost"`
	// TokenPath defaults to /oauth/token.
	TokenPath string `json:"tokenPath,omitempty"`
	// Audience, when set, is sent as the audience parameter, which Auth0
	// uses to name the API a token is for. Scope, when set, is sent as scope.
	Audience string `json:"audience,omitempty"`
	Scope    string `json:"scope,omitempty"`
	// Client is a KV version 2 secret with fields client_id and client_secret.
	Client KVRef `json:"client"`
}

func (e *Entry) normalizeClientCredentials() error {
	c := e.ClientCredentials
	if e.Header != "Authorization" || !strings.EqualFold(e.Scheme, "Bearer") || e.BasicUser || e.BasicPair || e.PairUserHeader != "" ||
		e.Key != (KeyRef{}) || e.ClientCertificate != nil {
		return errors.New("clientCredentials needs header Authorization and scheme Bearer, and no key, Basic settings or client certificate")
	}
	e.Scheme = "Bearer"
	c.TokenHost = strings.ToLower(c.TokenHost)
	labels := strings.Split(c.TokenHost, ".")
	if !hostPattern.MatchString(c.TokenHost) || len(c.TokenHost) > 253 || strings.Trim(labels[len(labels)-1], "0123456789") == "" {
		return errors.New("clientCredentials.tokenHost must be an exact DNS name; IPs are not allowed")
	}
	if c.TokenPath == "" {
		c.TokenPath = "/oauth/token"
	}
	p := c.TokenPath
	if !strings.HasPrefix(p, "/") || len(p) > 256 || strings.ContainsAny(p, "?#%*{} \\;") || strings.Contains(p, "//") || strings.Contains(p, "/..") ||
		strings.Contains(p, "/./") || !printableASCII(p) {
		return fmt.Errorf("invalid clientCredentials.tokenPath %q", p)
	}
	if len(c.Audience) > 256 || !printableASCII(c.Audience) || strings.Contains(c.Audience, " ") {
		return errors.New("clientCredentials.audience must be printable with no spaces, at most 256 bytes")
	}
	if len(c.Scope) > 256 || !printableASCII(c.Scope) {
		return errors.New("clientCredentials.scope must be printable, at most 256 bytes")
	}
	if prefix, path := keyPath(); !ValidMount(c.Client.Mount) || len(c.Client.Path) > 127 || !path.MatchString(c.Client.Path) {
		return fmt.Errorf("clientCredentials.client needs a KV mount and a path under %s/", prefix)
	}
	return nil
}

// HasTokenHost reports whether host is the token host of a
// clientCredentials entry: where the broker's own token requests may go.
func (c Catalog) HasTokenHost(host string) bool {
	host = strings.ToLower(host)
	for _, e := range c.entries {
		if e.ClientCredentials != nil && e.ClientCredentials.TokenHost == host {
			return true
		}
	}
	return false
}

// ClientTokens mints the access tokens of clientCredentials entries and keeps
// each until a quarter of its life remains. It reads the client from Vault
// through Keys on every call, so a deleted client is refused, and a rotated
// one used, as soon as Keys sees it: a new KV version mints a new token. The
// client is sent only in the token request, which never follows a redirect;
// the token is never logged and the client is never cached here.
type ClientTokens struct {
	Keys interface {
		Get(context.Context, KeyRef) (Secret, error)
	}
	Client *http.Client // must dial only the token hosts in the catalog
	Now    func() time.Time

	mu     sync.Mutex
	states map[string]*clientState
}

// clientState is one entry's token and its minting.
type clientState struct {
	mint    sync.Mutex // one mint at a time
	token   Secret     // the access token; Version is the client's KV version
	life    time.Duration
	expires time.Time
	failed  time.Time // last failed mint
}

var ErrClientToken = errors.New("client-credentials token unavailable")

// remintInterval keeps a token a vendor refused for at least this long: a
// worker can make the API refuse on purpose, and token issuers count and
// limit the tokens each client mints. failedMintInterval is how long a failed
// mint keeps refusing before the next attempt.
const (
	remintInterval     = time.Minute
	failedMintInterval = 10 * time.Second
)

func (t *ClientTokens) now() time.Time {
	if t.Now != nil {
		return t.Now()
	}
	return time.Now()
}

func (t *ClientTokens) fresh(st *clientState, version int) bool {
	left := st.expires.Sub(t.now())
	return st.token.value != "" && st.token.Version == version && left > time.Minute && left > st.life/4
}

func clientCacheKey(e *Entry) string {
	c := e.ClientCredentials
	return strings.Join([]string{e.Name, c.TokenHost, c.TokenPath, c.Audience, c.Scope, c.Client.Mount, c.Client.Path}, "\x00")
}

func (t *ClientTokens) state(e *Entry) *clientState {
	key := clientCacheKey(e)
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.states == nil {
		t.states = map[string]*clientState{}
	}
	st := t.states[key]
	if st == nil {
		st = &clientState{}
		t.states[key] = st
	}
	return st
}

// Token returns the entry's current access token, minting one when there is
// none, it is near its end, or the client has a new KV version. Concurrent
// callers share one mint. A Vault error is returned as Keys gave it, so it is
// refused like a header key's.
func (t *ClientTokens) Token(ctx context.Context, e *Entry) (Secret, error) {
	if e == nil || e.ClientCredentials == nil || t.Keys == nil || t.Client == nil {
		return Secret{}, ErrClientToken
	}
	ref := e.ClientCredentials.Client
	id, err := t.Keys.Get(ctx, ref.Field("client_id"))
	if err != nil {
		return Secret{}, err
	}
	secret, err := t.Keys.Get(ctx, ref.Field("client_secret"))
	if err != nil {
		return Secret{}, err
	}
	st := t.state(e)
	st.mint.Lock()
	defer st.mint.Unlock()
	if t.fresh(st, secret.Version) {
		return st.token, nil
	}
	if !st.failed.IsZero() && t.now().Sub(st.failed) < failedMintInterval {
		return Secret{}, ErrClientToken
	}
	issued := t.now()
	value, life, err := t.mint(ctx, e.ClientCredentials, id.Value(), secret.Value())
	if err != nil {
		st.failed = t.now()
		return Secret{}, ErrClientToken
	}
	st.token, st.life, st.expires, st.failed = Secret{value: value, Version: secret.Version}, life, issued.Add(life), time.Time{}
	return st.token, nil
}

func (t *ClientTokens) mint(ctx context.Context, c *ClientCredentialsBinding, id, secret string) (string, time.Duration, error) {
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {id}, "client_secret": {secret}}
	if c.Audience != "" {
		form.Set("audience", c.Audience)
	}
	if c.Scope != "" {
		form.Set("scope", c.Scope)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+c.TokenHost+c.TokenPath, strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	// A 307 or 308 would re-send the body, the client secret included, to
	// wherever it points.
	client := *t.Client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil || resp.StatusCode != http.StatusOK {
		// The issuer's error text is not passed on.
		return "", 0, ErrClientToken
	}
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
		TokenType   string `json:"token_type"`
	}
	if json.Unmarshal(data, &out) != nil || !headerSafe(out.AccessToken) || out.ExpiresIn < 120 || !strings.EqualFold(out.TokenType, "Bearer") {
		return "", 0, ErrClientToken
	}
	return out.AccessToken, time.Duration(out.ExpiresIn) * time.Second, nil
}

// headerSafe reports whether a minted token may go in a header: printable
// ASCII without spaces, at most maxKeyBytes, as for a stored key.
func headerSafe(v string) bool {
	if v == "" || len(v) > maxKeyBytes {
		return false
	}
	for i := 0; i < len(v); i++ {
		if v[i] < 0x21 || v[i] > 0x7e {
			return false
		}
	}
	return true
}

// Invalidate drops an entry's token after the API refused it, unless the
// token is younger than remintInterval.
func (t *ClientTokens) Invalidate(e *Entry) {
	if e == nil || e.ClientCredentials == nil {
		return
	}
	st := t.state(e)
	st.mint.Lock()
	defer st.mint.Unlock()
	if st.token.value == "" || t.now().Sub(st.expires.Add(-st.life)) < remintInterval {
		return
	}
	st.token = Secret{}
}

// Prune drops the token of every entry the catalog no longer holds, or holds
// with different client-credentials settings, so a removed entry's token
// does not stay in memory until the broker restarts.
func (t *ClientTokens) Prune(c Catalog) {
	keep := map[string]bool{}
	for i := range c.entries {
		if e := &c.entries[i]; e.ClientCredentials != nil {
			keep[clientCacheKey(e)] = true
		}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for key := range t.states {
		if !keep[key] {
			delete(t.states, key)
		}
	}
}
