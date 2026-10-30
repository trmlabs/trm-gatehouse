package runnerid

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/fips140"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func gumloopClaimsFor(now time.Time) map[string]any {
	return map[string]any{"iss": GumloopIssuer, "sub": "agent-1", "aud": "gatehouse-broker", "iat": now.Unix(),
		"exp": now.Unix() + 3600, "gumloop_org_id": "org-1", "gumloop_owner_id": "owner-1", "gumloop_owner_type": "user"}
}

func gumloopSetup(t *testing.T) (*GumloopVerifier, *issuer, *ecdsa.PrivateKey, *time.Time) {
	t.Helper()
	iss, _, key, now := setup(t)
	srv := httptest.NewServer(iss)
	t.Cleanup(srv.Close)
	v := &GumloopVerifier{JWKSURL: srv.URL, Issuer: GumloopIssuer, Audience: "gatehouse-broker", Client: srv.Client(),
		Now: func() time.Time { return *now }}
	return v, iss, key, now
}

func refusalOf(t *testing.T, err error) *Refusal {
	t.Helper()
	var r *Refusal
	if !errors.As(err, &r) {
		t.Fatalf("not a refusal: %v", err)
	}
	return r
}

func TestGumloopAdmitsASignedToken(t *testing.T) {
	v, _, key, now := gumloopSetup(t)
	id, err := v.Verify(context.Background(), sign(t, key, "k1", gumloopClaimsFor(*now)))
	if err != nil || id.OrgID != "org-1" || id.OwnerID != "owner-1" || !id.Expires.After(*now) {
		t.Fatalf("%+v %v", id, err)
	}
	c := gumloopClaimsFor(*now)
	c["aud"] = []string{"other", "gatehouse-broker"}
	delete(c, "gumloop_owner_id")
	if id, err = v.Verify(context.Background(), sign(t, key, "k1", c)); err != nil || id.OwnerID != "" {
		t.Fatalf("list audience, no owner: %+v %v", id, err)
	}
}

func TestGumloopAdmitsRS256(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := httptest.NewServer(&rsaIssuer{keys: map[string]*rsa.PrivateKey{"r1": rsaKey}})
	defer srv.Close()
	now := time.Now()
	v := &GumloopVerifier{JWKSURL: srv.URL, Issuer: GumloopIssuer, Audience: "gatehouse-broker", Client: srv.Client(), Now: func() time.Time { return now }}
	if id, err := v.Verify(context.Background(), signRS256(t, rsaKey, "r1", gumloopClaimsFor(now))); err != nil || id.OrgID != "org-1" {
		t.Fatalf("%+v %v", id, err)
	}
}

func TestGumloopRefusals(t *testing.T) {
	v, _, key, now := gumloopSetup(t)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mod := func(f func(map[string]any)) map[string]any {
		c := gumloopClaimsFor(*now)
		f(c)
		return c
	}
	for name, tc := range map[string]struct {
		token, reason string
	}{
		"wrong issuer":            {sign(t, key, "k1", mod(func(c map[string]any) { c["iss"] = "https://evil.example" })), "oidc_issuer"},
		"wrong audience":          {sign(t, key, "k1", mod(func(c map[string]any) { c["aud"] = "someone-else" })), "oidc_audience"},
		"audience list misses":    {sign(t, key, "k1", mod(func(c map[string]any) { c["aud"] = []string{"a", "b"} })), "oidc_audience"},
		"no audience":             {sign(t, key, "k1", mod(func(c map[string]any) { delete(c, "aud") })), "oidc_audience"},
		"expired":                 {sign(t, key, "k1", mod(func(c map[string]any) { c["exp"] = now.Unix() - 1 })), "oidc_expired"},
		"no expiry":               {sign(t, key, "k1", mod(func(c map[string]any) { delete(c, "exp") })), "oidc_expired"},
		"too long lived":          {sign(t, key, "k1", mod(func(c map[string]any) { c["exp"] = now.Add(48 * time.Hour).Unix() })), "oidc_lifetime"},
		"over an hour":            {sign(t, key, "k1", mod(func(c map[string]any) { c["exp"] = now.Add(time.Hour + time.Minute).Unix() })), "oidc_lifetime"},
		"owner is a workspace":    {sign(t, key, "k1", mod(func(c map[string]any) { c["gumloop_owner_type"] = "workspace" })), "oidc_owner_type"},
		"owner has no type":       {sign(t, key, "k1", mod(func(c map[string]any) { delete(c, "gumloop_owner_type") })), "oidc_owner_type"},
		"not yet valid":           {sign(t, key, "k1", mod(func(c map[string]any) { c["nbf"] = now.Add(time.Hour).Unix() })), "oidc_not_yet_valid"},
		"issued in the future":    {sign(t, key, "k1", mod(func(c map[string]any) { c["iat"] = now.Add(time.Hour).Unix() })), "oidc_not_yet_valid"},
		"no org":                  {sign(t, key, "k1", mod(func(c map[string]any) { delete(c, "gumloop_org_id") })), "oidc_org_missing"},
		"org is not a string":     {sign(t, key, "k1", mod(func(c map[string]any) { c["gumloop_org_id"] = 7 })), "oidc_malformed"},
		"another key's signature": {sign(t, other, "k1", gumloopClaimsFor(*now)), "oidc_signature"},
		"unknown kid":             {sign(t, key, "nope", gumloopClaimsFor(*now)), "oidc_key_unknown"},
		"not a token":             {"abc", "oidc_malformed"},
		"two parts":               {"a.b", "oidc_malformed"},
		"empty":                   {"", "oidc_malformed"},
	} {
		_, err := v.Verify(context.Background(), tc.token)
		if r := refusalOf(t, err); r.Reason != tc.reason {
			t.Errorf("%s: reason %q, want %q", name, r.Reason, tc.reason)
		}
	}
}

func TestGumloopRefusesOtherAlgorithms(t *testing.T) {
	v, _, key, now := gumloopSetup(t)
	good := sign(t, key, "k1", gumloopClaimsFor(*now))
	parts := splitToken(good)
	for name, alg := range map[string]string{"none": "none", "hs256": "HS256", "es384": "ES384", "ps256": "PS256"} {
		header, _ := json.Marshal(map[string]string{"alg": alg, "kid": "k1"})
		token := b64(header) + "." + parts[1] + "." + parts[2]
		if name == "none" {
			token = b64(header) + "." + parts[1] + "."
		}
		if r := refusalOf(t, errOf(v.Verify(context.Background(), token))); r.Reason != "oidc_algorithm" {
			t.Errorf("%s: reason %q", name, r.Reason)
		}
	}
	// An RS256 header over an EC key must not verify.
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "k1"})
	if r := refusalOf(t, errOf(v.Verify(context.Background(), b64(header)+"."+parts[1]+"."+parts[2]))); r.Reason != "oidc_signature" {
		t.Errorf("key type confusion: reason %q", r.Reason)
	}
	// A critical header is refused.
	crit, _ := json.Marshal(map[string]any{"alg": "ES256", "kid": "k1", "crit": []string{"x"}})
	if r := refusalOf(t, errOf(v.Verify(context.Background(), b64(crit)+"."+parts[1]+"."+parts[2]))); r.Reason != "oidc_malformed" {
		t.Errorf("crit: reason %q", r.Reason)
	}
}

func TestGumloopNeedsAnAudienceAndIssuer(t *testing.T) {
	v, _, key, now := gumloopSetup(t)
	token := sign(t, key, "k1", gumloopClaimsFor(*now))
	v.Audience = ""
	if _, err := v.Verify(context.Background(), token); err == nil {
		t.Fatal("a verifier with no audience admitted a token")
	}
	v.Audience, v.Issuer = "gatehouse-broker", ""
	if _, err := v.Verify(context.Background(), token); err == nil {
		t.Fatal("a verifier with no issuer admitted a token")
	}
}

func TestGumloopKeyRotationAndOutage(t *testing.T) {
	v, iss, key, now := gumloopSetup(t)
	if _, err := v.Verify(context.Background(), sign(t, key, "k1", gumloopClaimsFor(*now))); err != nil {
		t.Fatal(err)
	}
	rotated, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	iss.mu.Lock()
	iss.keys["k2"] = rotated
	iss.mu.Unlock()
	// An unknown kid inside the refetch backoff is refused, not fetched for.
	if _, err := v.Verify(context.Background(), sign(t, rotated, "k2", gumloopClaimsFor(*now))); err == nil {
		t.Fatal("rotated key accepted before the refetch backoff")
	}
	*now = now.Add(31 * time.Second)
	if _, err := v.Verify(context.Background(), sign(t, rotated, "k2", gumloopClaimsFor(*now))); err != nil {
		t.Fatalf("rotated key not picked up: %v", err)
	}
	// A removed key stops verifying once the set is refetched.
	iss.mu.Lock()
	delete(iss.keys, "k1")
	iss.mu.Unlock()
	*now = now.Add(2 * time.Hour)
	if r := refusalOf(t, errOf(v.Verify(context.Background(), sign(t, key, "k1", gumloopClaimsFor(*now))))); r.Reason != "oidc_key_unknown" {
		t.Fatalf("retired key: reason %q", r.Reason)
	}
}

func TestGumloopJWKSServerError(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusInternalServerError) }))
	defer srv.Close()
	now := time.Now()
	v := &GumloopVerifier{JWKSURL: srv.URL, Issuer: GumloopIssuer, Audience: "gatehouse-broker", Client: srv.Client(), Now: func() time.Time { return now }}
	if r := refusalOf(t, errOf(v.Verify(context.Background(), sign(t, key, "k1", gumloopClaimsFor(now))))); r.Reason != ReasonKeysUnavailable {
		t.Fatalf("reason %q", r.Reason)
	}
}

func TestGumloopOutageIsNotAnUnknownKey(t *testing.T) {
	v, iss, key, now := gumloopSetup(t)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, err := v.Verify(context.Background(), sign(t, key, "k1", gumloopClaimsFor(*now))); err != nil {
		t.Fatal(err)
	}
	iss.mu.Lock()
	iss.down = true
	iss.mu.Unlock()
	*now = now.Add(31 * time.Second)
	// The fetch fails, so a kid the old set lacks may exist: retryable, and the cached key still serves.
	if r := refusalOf(t, errOf(v.Verify(context.Background(), sign(t, other, "k2", gumloopClaimsFor(*now))))); r.Reason != ReasonKeysUnavailable {
		t.Fatalf("outage: reason %q", r.Reason)
	}
	if _, err := v.Verify(context.Background(), sign(t, key, "k1", gumloopClaimsFor(*now))); err != nil {
		t.Fatalf("cached key during outage: %v", err)
	}
	// Once the set is over an hour old the outage still reads as retryable.
	*now = now.Add(2 * time.Hour)
	if r := refusalOf(t, errOf(v.Verify(context.Background(), sign(t, key, "k1", gumloopClaimsFor(*now))))); r.Reason != ReasonKeysUnavailable {
		t.Fatalf("stale set: reason %q", r.Reason)
	}
	// A fetch that succeeds and lacks the kid is a key that is not published.
	iss.mu.Lock()
	iss.down = false
	iss.mu.Unlock()
	*now = now.Add(31 * time.Second)
	if r := refusalOf(t, errOf(v.Verify(context.Background(), sign(t, other, "k2", gumloopClaimsFor(*now))))); r.Reason != "oidc_key_unknown" {
		t.Fatalf("absent kid: reason %q", r.Reason)
	}
}

func TestGumloopRefusesWeakRSAKeys(t *testing.T) {
	if fips140.Enabled() {
		t.Skip("FIPS mode cannot generate a 1024-bit key")
	}
	small, _ := rsa.GenerateKey(rand.Reader, 1024) // #nosec G403 -- the weak key under test
	srv := httptest.NewServer(&rsaIssuer{keys: map[string]*rsa.PrivateKey{"r1": small}})
	defer srv.Close()
	now := time.Now()
	v := &GumloopVerifier{JWKSURL: srv.URL, Issuer: GumloopIssuer, Audience: "gatehouse-broker", Client: srv.Client(), Now: func() time.Time { return now }}
	if _, err := v.Verify(context.Background(), signRS256(t, small, "r1", gumloopClaimsFor(now))); err == nil {
		t.Fatal("accepted a 1024-bit key")
	}
}

func errOf(_ GumloopIdentity, err error) error { return err }

func splitToken(s string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	return append(parts, s[start:])
}
