package runnerid

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	googleTestAudience = "gatehouse-broker"
	googleTestSub      = "104857263948571029384"
)

type googleKeys struct {
	mu   sync.Mutex
	keys map[string]*rsa.PrivateKey
	down bool
}

func (g *googleKeys) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.down {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	i := rsaIssuer{keys: g.keys}
	i.ServeHTTP(w, nil)
}

func (g *googleKeys) set(down bool, add map[string]*rsa.PrivateKey, remove ...string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.down = down
	for kid, k := range add {
		g.keys[kid] = k
	}
	for _, kid := range remove {
		delete(g.keys, kid)
	}
}

func googleClaimsFor(now time.Time) map[string]any {
	return map[string]any{"iss": GoogleIssuer, "aud": googleTestAudience, "azp": googleTestSub, "sub": googleTestSub, "iat": now.Unix(), "exp": now.Unix() + 3600,
		"email": "worker-one@example-project.iam.gserviceaccount.com", "email_verified": true}
}

func newRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func googleSetup(t *testing.T) (*GoogleVerifier, *googleKeys, *rsa.PrivateKey, *time.Time) {
	t.Helper()
	key := newRSAKey(t)
	keys := &googleKeys{keys: map[string]*rsa.PrivateKey{"g1": key}}
	srv := httptest.NewServer(keys)
	t.Cleanup(srv.Close)
	now := time.Now()
	v := &GoogleVerifier{JWKSURL: srv.URL, Issuer: GoogleIssuer, Audience: googleTestAudience, Client: srv.Client(), Now: func() time.Time { return now }}
	return v, keys, key, &now
}

func googleErrOf(_ GoogleIdentity, err error) error { return err }

func TestGoogleAdmitsASignedToken(t *testing.T) {
	v, _, key, now := googleSetup(t)
	id, err := v.Verify(context.Background(), signRS256(t, key, "g1", googleClaimsFor(*now)))
	if err != nil || id.UniqueID != googleTestSub || id.Email != "worker-one@example-project.iam.gserviceaccount.com" || !id.Expires.After(*now) {
		t.Fatalf("%+v %v", id, err)
	}
	c := googleClaimsFor(*now)
	delete(c, "email")
	delete(c, "email_verified")
	if id, err = v.Verify(context.Background(), signRS256(t, key, "g1", c)); err != nil || id.UniqueID != googleTestSub || id.Email != "" {
		t.Fatalf("no email claim: %+v %v", id, err)
	}
}

func TestGoogleRefusals(t *testing.T) {
	v, _, key, now := googleSetup(t)
	other := newRSAKey(t)
	mod := func(f func(map[string]any)) map[string]any {
		c := googleClaimsFor(*now)
		f(c)
		return c
	}
	signed := func(c map[string]any) string { return signRS256(t, key, "g1", c) }
	for name, tc := range map[string]struct{ token, reason string }{
		"wrong issuer":              {signed(mod(func(c map[string]any) { c["iss"] = "https://evil.example" })), "oidc_issuer"},
		"bare issuer":               {signed(mod(func(c map[string]any) { c["iss"] = "accounts.google.com" })), "oidc_issuer"},
		"wrong audience":            {signed(mod(func(c map[string]any) { c["aud"] = "someone-else" })), "oidc_audience"},
		"audience list misses":      {signed(mod(func(c map[string]any) { c["aud"] = []string{"a", "b"} })), "oidc_audience"},
		"audience list adds one":    {signed(mod(func(c map[string]any) { c["aud"] = []string{"other", googleTestAudience} })), "oidc_audience"},
		"no audience":               {signed(mod(func(c map[string]any) { delete(c, "aud") })), "oidc_audience"},
		"expired":                   {signed(mod(func(c map[string]any) { c["exp"] = now.Unix() - 1 })), "oidc_expired"},
		"no expiry":                 {signed(mod(func(c map[string]any) { delete(c, "exp") })), "oidc_expired"},
		"too long lived":            {signed(mod(func(c map[string]any) { c["exp"] = now.Add(48 * time.Hour).Unix() })), "oidc_lifetime"},
		"over an hour and the skew": {signed(mod(func(c map[string]any) { c["exp"] = now.Add(time.Hour + clockSkew + 2*time.Second).Unix() })), "oidc_lifetime"},
		"not yet valid":             {signed(mod(func(c map[string]any) { c["nbf"] = now.Add(time.Hour).Unix() })), "oidc_not_yet_valid"},
		"issued in the future":      {signed(mod(func(c map[string]any) { c["iat"] = now.Add(time.Hour).Unix() })), "oidc_not_yet_valid"},
		"no sub":                    {signed(mod(func(c map[string]any) { delete(c, "sub") })), "oidc_subject_missing"},
		"sub not a unique ID":       {signed(mod(func(c map[string]any) { c["sub"] = "worker-one@example-project.iam.gserviceaccount.com" })), "oidc_subject_missing"},
		"email not verified":        {signed(mod(func(c map[string]any) { c["email_verified"] = false })), "oidc_email_unverified"},
		"email without a verdict":   {signed(mod(func(c map[string]any) { delete(c, "email_verified") })), "oidc_email_unverified"},
		"email_verified a string":   {signed(mod(func(c map[string]any) { c["email_verified"] = "true" })), "oidc_malformed"},
		"email with a space":        {signed(mod(func(c map[string]any) { c["email"] = "a b@example.com" })), "oidc_email_malformed"},
		"email over 254 characters": {signed(mod(func(c map[string]any) { c["email"] = strings.Repeat("a", 255) + "@example.com" })), "oidc_email_malformed"},
		"another key's signature":   {signRS256(t, other, "g1", googleClaimsFor(*now)), "oidc_signature"},
		"unknown kid":               {signRS256(t, key, "nope", googleClaimsFor(*now)), "oidc_key_unknown"},
		"not a token":               {"abc", "oidc_malformed"},
		"two parts":                 {"a.b", "oidc_malformed"},
		"empty":                     {"", "oidc_malformed"},
	} {
		if r := refusalOf(t, googleErrOf(v.Verify(context.Background(), tc.token))); r.Reason != tc.reason {
			t.Errorf("%s: reason %q, want %q", name, r.Reason, tc.reason)
		}
	}
}

func TestGoogleLifetimeAtTheCapWithAClockBehind(t *testing.T) {
	v, _, key, now := googleSetup(t)
	issued := *now
	c := googleClaimsFor(issued)
	token := signRS256(t, key, "g1", c)
	behind := issued.Add(-30 * time.Second)
	v.Now = func() time.Time { return behind }
	if id, err := v.Verify(context.Background(), token); err != nil || id.UniqueID != googleTestSub {
		t.Fatalf("a fresh token with the clock 30s behind: %+v %v", id, err)
	}
	c["exp"] = issued.Add(time.Hour + clockSkew + time.Second).Unix()
	v.Now = func() time.Time { return issued }
	if r := refusalOf(t, googleErrOf(v.Verify(context.Background(), signRS256(t, key, "g1", c)))); r.Reason != "oidc_lifetime" {
		t.Fatalf("past the cap: %q", r.Reason)
	}
}

func TestGoogleAcceptsRS256Only(t *testing.T) {
	v, _, key, now := googleSetup(t)
	parts := splitToken(signRS256(t, key, "g1", googleClaimsFor(*now)))
	for name, alg := range map[string]string{"none": "none", "hs256": "HS256", "es256": "ES256", "ps256": "PS256", "rs384": "RS384"} {
		token := b64([]byte(`{"alg":"`+alg+`","kid":"g1"}`)) + "." + parts[1] + "." + parts[2]
		if r := refusalOf(t, googleErrOf(v.Verify(context.Background(), token))); r.Reason != "oidc_algorithm" {
			t.Errorf("%s: reason %q", name, r.Reason)
		}
	}
	// A properly signed ES256 token from a published EC key is still refused.
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if r := refusalOf(t, googleErrOf(v.Verify(context.Background(), sign(t, ec, "g1", googleClaimsFor(*now))))); r.Reason != "oidc_algorithm" {
		t.Errorf("ES256: reason %q", r.Reason)
	}
}

func TestGoogleNeedsAnAudienceAndIssuer(t *testing.T) {
	v, _, key, now := googleSetup(t)
	token := signRS256(t, key, "g1", googleClaimsFor(*now))
	v.Audience = ""
	if _, err := v.Verify(context.Background(), token); err == nil {
		t.Fatal("a verifier with no audience admitted a token")
	}
	v.Audience, v.Issuer = googleTestAudience, ""
	if _, err := v.Verify(context.Background(), token); err == nil {
		t.Fatal("a verifier with no issuer admitted a token")
	}
}

func TestGoogleKeyRotation(t *testing.T) {
	v, keys, key, now := googleSetup(t)
	if _, err := v.Verify(context.Background(), signRS256(t, key, "g1", googleClaimsFor(*now))); err != nil {
		t.Fatal(err)
	}
	rotated := newRSAKey(t)
	keys.set(false, map[string]*rsa.PrivateKey{"g2": rotated})
	if _, err := v.Verify(context.Background(), signRS256(t, rotated, "g2", googleClaimsFor(*now))); err == nil {
		t.Fatal("rotated key accepted inside the refetch backoff")
	}
	*now = now.Add(31 * time.Second)
	if _, err := v.Verify(context.Background(), signRS256(t, rotated, "g2", googleClaimsFor(*now))); err != nil {
		t.Fatalf("rotated key not picked up on an unknown kid: %v", err)
	}
	keys.set(false, nil, "g1")
	*now = now.Add(2 * time.Hour)
	if r := refusalOf(t, googleErrOf(v.Verify(context.Background(), signRS256(t, key, "g1", googleClaimsFor(*now))))); r.Reason != "oidc_key_unknown" {
		t.Fatalf("retired key: %q", r.Reason)
	}
}

func TestGoogleColdCacheOutageIsRetryable(t *testing.T) {
	v, keys, key, now := googleSetup(t)
	keys.set(true, nil)
	if r := refusalOf(t, googleErrOf(v.Verify(context.Background(), signRS256(t, key, "g1", googleClaimsFor(*now))))); r.Reason != ReasonKeysUnavailable {
		t.Fatalf("cold cache, keys down: %q", r.Reason)
	}
	keys.set(false, nil)
	*now = now.Add(31 * time.Second)
	if _, err := v.Verify(context.Background(), signRS256(t, key, "g1", googleClaimsFor(*now))); err != nil {
		t.Fatalf("after the keys return: %v", err)
	}
}

func TestGoogleOutageKeepsServingCachedKeysForAnHourOnly(t *testing.T) {
	v, keys, key, now := googleSetup(t)
	if _, err := v.Verify(context.Background(), signRS256(t, key, "g1", googleClaimsFor(*now))); err != nil {
		t.Fatal(err)
	}
	keys.set(true, nil)
	*now = now.Add(31 * time.Second)
	other := newRSAKey(t)
	if r := refusalOf(t, googleErrOf(v.Verify(context.Background(), signRS256(t, other, "g2", googleClaimsFor(*now))))); r.Reason != ReasonKeysUnavailable {
		t.Fatalf("unknown kid during an outage: %q", r.Reason)
	}
	if _, err := v.Verify(context.Background(), signRS256(t, key, "g1", googleClaimsFor(*now))); err != nil {
		t.Fatalf("cached key during an outage: %v", err)
	}
	*now = now.Add(2 * time.Hour)
	if r := refusalOf(t, googleErrOf(v.Verify(context.Background(), signRS256(t, key, "g1", googleClaimsFor(*now))))); r.Reason != ReasonKeysUnavailable {
		t.Fatalf("stale cache past an hour: %q", r.Reason)
	}
}
