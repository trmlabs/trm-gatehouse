package runnerid

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func enc(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// signedRig is a local issuer: a test key set served as a JWKS, and a token maker.
type signedRig struct {
	ec     *ecdsa.PrivateKey
	rsa    *rsa.PrivateKey
	other  *ecdsa.PrivateKey // signs a token the JWKS does not vouch for
	srv    *httptest.Server
	status atomic.Int32 // the JWKS status; 0 is 200
	// rawBody, when set, is served as the JWKS body instead of the key set.
	rawBody atomic.Pointer[string]
	// discoIssuer and discoURI override what the discovery document says; "" is the rig's own URL.
	discoIssuer, discoURI string
	hits                  atomic.Int32
	now                   time.Time
}

const rigIssuer = "https://issuer.example"

func newSignedRig(t *testing.T) *signedRig {
	t.Helper()
	r := &signedRig{now: time.Unix(1_800_000_000, 0)}
	r.ec, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	r.other, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	r.rsa, _ = rsa.GenerateKey(rand.Reader, 2048)
	point, _ := r.ec.PublicKey.Bytes()
	mux := http.NewServeMux()
	jwksBody := func() map[string]any {
		return map[string]any{"keys": []map[string]string{
			{"kty": "EC", "crv": "P-256", "kid": "ec1", "alg": "ES256", "use": "sig", "x": enc(point[1:33]), "y": enc(point[33:65])},
			{"kty": "RSA", "kid": "rsa1", "alg": "RS256", "use": "sig", "n": enc(r.rsa.N.Bytes()), "e": enc([]byte{1, 0, 1})},
		}}
	}
	mux.HandleFunc("/keys", func(w http.ResponseWriter, _ *http.Request) {
		r.hits.Add(1)
		if s := r.status.Load(); s != 0 {
			http.Error(w, "down", int(s))
			return
		}
		if raw := r.rawBody.Load(); raw != nil {
			_, _ = w.Write([]byte(*raw))
			return
		}
		_ = json.NewEncoder(w).Encode(jwksBody())
	})
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		doc := map[string]string{"issuer": r.srv.URL, "jwks_uri": r.srv.URL + "/keys"}
		if r.discoIssuer != "" {
			doc["issuer"] = r.discoIssuer
		}
		if r.discoURI != "" {
			doc["jwks_uri"] = r.discoURI
		}
		_ = json.NewEncoder(w).Encode(doc)
	})
	r.srv = httptest.NewTLSServer(mux)
	t.Cleanup(r.srv.Close)
	return r
}

func (r *signedRig) config() SignedConfig {
	return SignedConfig{Issuer: rigIssuer, JWKSURL: r.srv.URL + "/keys", Audiences: []string{"gatehouse", "gatehouse-staging"}, Algorithms: []string{"ES256", "RS256"},
		MaxLifetime: time.Hour, ClockSkew: time.Minute, SubjectClaim: "sub", GroupsClaim: "groups"}
}

func (r *signedRig) verifier(cfg SignedConfig) *SignedVerifier {
	return NewSignedVerifier(cfg, r.srv.Client(), func() time.Time { return r.now })
}

// claims is a good token's claims; a test overrides or deletes keys.
func (r *signedRig) claims() map[string]any {
	return map[string]any{"iss": rigIssuer, "aud": "gatehouse", "sub": "agent-7", "groups": []string{"team-a", "team-b"},
		"iat": r.now.Unix() - 10, "exp": r.now.Unix() + 600}
}

func (r *signedRig) sign(header map[string]any, claims map[string]any, key any) string {
	h, _ := json.Marshal(header)
	p, _ := json.Marshal(claims)
	input := enc(h) + "." + enc(p)
	digest := sha256.Sum256([]byte(input))
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		rr, ss, _ := ecdsa.Sign(rand.Reader, k, digest[:])
		return input + "." + enc(append(rr.FillBytes(make([]byte, 32)), ss.FillBytes(make([]byte, 32))...))
	case *rsa.PrivateKey:
		sig, _ := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, digest[:])
		return input + "." + enc(sig)
	}
	panic("key type")
}

func (r *signedRig) es(claims map[string]any) string {
	return r.sign(map[string]any{"alg": "ES256", "kid": "ec1"}, claims, r.ec)
}

func reasonOf(err error) string {
	if r, ok := err.(*Refusal); ok {
		return r.Reason
	}
	return "not a refusal: " + err.Error()
}

func TestSignedVerifierAdmitsAGoodToken(t *testing.T) {
	r := newSignedRig(t)
	v := r.verifier(r.config())
	es := r.es(r.claims())
	rs := r.sign(map[string]any{"alg": "RS256", "kid": "rsa1"}, r.claims(), r.rsa)
	for name, token := range map[string]string{"ES256": es, "RS256": rs} {
		id, err := v.Verify(context.Background(), token)
		if err != nil || id.Subject != "agent-7" || len(id.Groups) != 2 || id.Groups[0] != "team-a" || !id.Expires.Equal(time.Unix(r.now.Unix()+600, 0)) {
			t.Errorf("%s: %+v %v", name, id, err)
		}
	}
	// The second configured audience, a list audience, and a single group string read the same way.
	c := r.claims()
	c["aud"], c["groups"] = []string{"other", "gatehouse-staging"}, "solo"
	if id, err := v.Verify(context.Background(), r.es(c)); err != nil || id.Groups[0] != "solo" {
		t.Errorf("list audience and string group: %+v %v", id, err)
	}
	// A subject claim other than sub, and no groups claim configured.
	cfg := r.config()
	cfg.SubjectClaim, cfg.GroupsClaim = "email", ""
	c = r.claims()
	c["email"] = "agent@example.com"
	if id, err := r.verifier(cfg).Verify(context.Background(), r.es(c)); err != nil || id.Subject != "agent@example.com" || len(id.Groups) != 0 {
		t.Errorf("email subject: %+v %v", id, err)
	}
}

func TestSignedVerifierRefusals(t *testing.T) {
	r := newSignedRig(t)
	good := func(mutate func(map[string]any)) string {
		c := r.claims()
		mutate(c)
		return r.es(c)
	}
	cases := map[string]struct {
		token func() string
		want  string
	}{
		"a bad signature": {func() string {
			return r.sign(map[string]any{"alg": "ES256", "kid": "ec1"}, r.claims(), r.other)
		}, "oidc_signature"},
		"an RS256 token signed with the wrong key": {func() string {
			k, _ := rsa.GenerateKey(rand.Reader, 2048)
			return r.sign(map[string]any{"alg": "RS256", "kid": "rsa1"}, r.claims(), k)
		}, "oidc_signature"},
		"an unknown kid": {func() string {
			return r.sign(map[string]any{"alg": "ES256", "kid": "nope"}, r.claims(), r.ec)
		}, "oidc_key_unknown"},
		"no kid": {func() string {
			return r.sign(map[string]any{"alg": "ES256"}, r.claims(), r.ec)
		}, "oidc_malformed"},
		"an algorithm of none": {func() string {
			return r.sign(map[string]any{"alg": "none", "kid": "ec1"}, r.claims(), r.ec)
		}, "oidc_algorithm"},
		"an HMAC algorithm": {func() string {
			return r.sign(map[string]any{"alg": "HS256", "kid": "ec1"}, r.claims(), r.ec)
		}, "oidc_algorithm"},
		"a key of the other kind than the algorithm names": {func() string {
			return r.sign(map[string]any{"alg": "RS256", "kid": "ec1"}, r.claims(), r.rsa)
		}, "oidc_signature"},
		"a critical header": {func() string {
			return r.sign(map[string]any{"alg": "ES256", "kid": "ec1", "crit": []string{"x"}}, r.claims(), r.ec)
		}, "oidc_malformed"},
		"the wrong issuer":   {func() string { return good(func(c map[string]any) { c["iss"] = "https://evil.example" }) }, "oidc_issuer"},
		"no issuer":          {func() string { return good(func(c map[string]any) { delete(c, "iss") }) }, "oidc_issuer"},
		"the wrong audience": {func() string { return good(func(c map[string]any) { c["aud"] = "someone-else" }) }, "oidc_audience"},
		"no audience":        {func() string { return good(func(c map[string]any) { delete(c, "aud") }) }, "oidc_audience"},
		"an expired token":   {func() string { return good(func(c map[string]any) { c["exp"] = r.now.Unix() - 1 }) }, "oidc_expired"},
		"expiring this second": {func() string {
			return good(func(c map[string]any) { c["exp"] = r.now.Unix() })
		}, "oidc_expired"},
		"no exp":       {func() string { return good(func(c map[string]any) { delete(c, "exp") }) }, "oidc_claim_missing"},
		"a string exp": {func() string { return good(func(c map[string]any) { c["exp"] = "soon" }) }, "oidc_claim_missing"},
		"no iat":       {func() string { return good(func(c map[string]any) { delete(c, "iat") }) }, "oidc_claim_missing"},
		"a lifetime past the maximum": {func() string {
			return good(func(c map[string]any) { c["iat"], c["exp"] = r.now.Unix()-4000, r.now.Unix()+600 })
		}, "oidc_lifetime"},
		"an expiry too far ahead": {func() string {
			return good(func(c map[string]any) { c["iat"], c["exp"] = r.now.Unix(), r.now.Unix()+7200 })
		}, "oidc_lifetime"},
		"an iat in the future": {func() string {
			return good(func(c map[string]any) { c["iat"], c["exp"] = r.now.Unix()+3000, r.now.Unix()+3300 })
		}, "oidc_not_yet_valid"},
		"a not-before in the future": {func() string { return good(func(c map[string]any) { c["nbf"] = r.now.Unix() + 3000 }) }, "oidc_not_yet_valid"},
		"no subject":                 {func() string { return good(func(c map[string]any) { delete(c, "sub") }) }, "oidc_claim_missing"},
		"an empty subject":           {func() string { return good(func(c map[string]any) { c["sub"] = "" }) }, "oidc_claim_missing"},
		"a subject that is not a string": {func() string {
			return good(func(c map[string]any) { c["sub"] = 42 })
		}, "oidc_claim_missing"},
		"a subject with a space": {func() string { return good(func(c map[string]any) { c["sub"] = "a b" }) }, "oidc_claim_missing"},
		"a groups claim of the wrong shape": {func() string {
			return good(func(c map[string]any) { c["groups"] = map[string]string{"a": "b"} })
		}, "oidc_claim_missing"},
		"not a token":       {func() string { return "abc" }, "oidc_malformed"},
		"too many segments": {func() string { return "a.b.c.d" }, "oidc_malformed"},
		"a payload that is not JSON": {func() string {
			return enc([]byte(`{"alg":"ES256","kid":"ec1"}`)) + "." + enc([]byte("x")) + "." + enc([]byte("sig"))
		}, "oidc_signature"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := r.verifier(r.config()).Verify(context.Background(), tc.token())
			if err == nil {
				t.Fatal("admitted")
			}
			if got := reasonOf(err); got != tc.want {
				t.Errorf("reason %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSignedVerifierRefusesWhenKeysCannotBeFetched(t *testing.T) {
	r := newSignedRig(t)
	r.status.Store(http.StatusInternalServerError)
	v := r.verifier(r.config())
	if _, err := v.Verify(context.Background(), r.es(r.claims())); reasonOf(err) != ReasonKeysUnavailable {
		t.Errorf("keys down: %v", err)
	}
	// An unreachable issuer, a key set that is not JSON and a redirect are the same refusal, never an open door.
	cfg := r.config()
	cfg.JWKSURL = "https://127.0.0.1:1/keys"
	if _, err := r.verifier(cfg).Verify(context.Background(), r.es(r.claims())); reasonOf(err) != ReasonKeysUnavailable {
		t.Errorf("unreachable: %v", err)
	}
	bad := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("<html>")) }))
	defer bad.Close()
	cfg.JWKSURL = bad.URL
	if _, err := NewSignedVerifier(cfg, bad.Client(), func() time.Time { return r.now }).Verify(context.Background(), r.es(r.claims())); reasonOf(err) != ReasonKeysUnavailable {
		t.Errorf("bad key set: %v", err)
	}
	// Once the issuer recovers the same token is admitted: the refusal was not cached forever.
	r.status.Store(0)
	r.now = r.now.Add(time.Minute)
	if _, err := v.Verify(context.Background(), r.es(r.claims())); err != nil {
		t.Errorf("after recovery: %v", err)
	}
}

func TestSignedVerifierKeepsServingCachedKeysButNeverTrustsAnUnknownOne(t *testing.T) {
	r := newSignedRig(t)
	v := r.verifier(r.config())
	if _, err := v.Verify(context.Background(), r.es(r.claims())); err != nil {
		t.Fatal(err)
	}
	r.status.Store(http.StatusServiceUnavailable)
	r.now = r.now.Add(2 * time.Minute) // past the refresh backoff, inside the key age
	if _, err := v.Verify(context.Background(), r.es(r.claims())); err != nil {
		t.Errorf("cached key within its age, issuer down: %v", err)
	}
	unknown := r.sign(map[string]any{"alg": "ES256", "kid": "rotated"}, r.claims(), r.other)
	if _, err := v.Verify(context.Background(), unknown); reasonOf(err) != ReasonKeysUnavailable {
		t.Errorf("unknown kid while the issuer is down: %v", err)
	}
	// Past the key age with the issuer still down, nothing is served from the old set.
	r.now = r.now.Add(2 * time.Hour)
	if _, err := v.Verify(context.Background(), r.es(r.claims())); reasonOf(err) != ReasonKeysUnavailable {
		t.Errorf("stale keys: %v", err)
	}
}

func TestSignedVerifierFetchesKeysOnceForManyTokens(t *testing.T) {
	r := newSignedRig(t)
	v := r.verifier(r.config())
	for range 200 {
		if _, err := v.Verify(context.Background(), r.es(r.claims())); err != nil {
			t.Fatal(err)
		}
	}
	if n := r.hits.Load(); n != 1 {
		t.Errorf("%d key fetches for 200 verifies", n)
	}
	// A flood of tokens naming unknown keys refetches at most once per backoff, not once per token.
	unknown := r.sign(map[string]any{"alg": "ES256", "kid": "nope"}, r.claims(), r.ec)
	before := r.hits.Load()
	for range 200 {
		_, _ = v.Verify(context.Background(), unknown)
	}
	if n := r.hits.Load() - before; n > 1 {
		t.Errorf("%d key fetches for 200 unknown-kid tokens inside one backoff", n)
	}
}

func TestSignedVerifierCacheSettingsApply(t *testing.T) {
	r := newSignedRig(t)
	cfg := r.config()
	cfg.KeyMaxAge, cfg.RefreshBackoff = 10*time.Minute, 5*time.Second
	v := r.verifier(cfg)
	if _, err := v.Verify(context.Background(), r.es(r.claims())); err != nil {
		t.Fatal(err)
	}
	// Before half the key age no background refresh runs, so the count is exact.
	r.now = r.now.Add(4 * time.Minute)
	if _, err := v.Verify(context.Background(), r.es(r.claims())); err != nil || r.hits.Load() != 1 {
		t.Fatalf("inside the key age: %v, %d fetches", err, r.hits.Load())
	}
	r.now = r.now.Add(7 * time.Minute)
	if _, err := v.Verify(context.Background(), r.es(r.claims())); err != nil || r.hits.Load() != 2 {
		t.Fatalf("past the configured key age: %v, %d fetches", err, r.hits.Load())
	}
}

func TestSignedVerifierDiscovery(t *testing.T) {
	r := newSignedRig(t)
	cfg := r.config()
	cfg.JWKSURL, cfg.Discovery, cfg.Issuer = "", true, r.srv.URL
	claims := func() map[string]any {
		c := r.claims()
		c["iss"] = r.srv.URL
		return c
	}
	if id, err := r.verifier(cfg).Verify(context.Background(), r.es(claims())); err != nil || id.Subject != "agent-7" {
		t.Fatalf("discovered keys: %+v %v", id, err)
	}
	// A discovery document naming another issuer, or a key URL that is not https, is not trusted.
	for name, mutate := range map[string]func(){
		"another issuer":            func() { r.discoIssuer = "https://evil.example" },
		"a plain http key URL":      func() { r.discoURI = "http://keys.example/keys" },
		"a key URL with userinfo":   func() { r.discoURI = "https://user:pass@keys.example/keys" },
		"a key URL with a fragment": func() { r.discoURI = "https://keys.example/keys#x" },
	} {
		r.discoIssuer, r.discoURI = "", ""
		mutate()
		if _, err := r.verifier(cfg).Verify(context.Background(), r.es(claims())); reasonOf(err) != ReasonKeysUnavailable {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestPeekIssuer(t *testing.T) {
	r := newSignedRig(t)
	if iss, ok := PeekIssuer(r.es(r.claims())); !ok || iss != rigIssuer {
		t.Errorf("%q %v", iss, ok)
	}
	for _, bad := range []string{"", "a.b", "a.!.c", "a." + enc([]byte("{}")) + ".c", "a." + enc([]byte("[1]")) + ".c"} {
		if _, ok := PeekIssuer(bad); ok {
			t.Errorf("%q peeked", bad)
		}
	}
}

func TestSignedVerifierDropsMalformedGroupsAndKeepsTheRest(t *testing.T) {
	r := newSignedRig(t)
	v := r.verifier(r.config())
	c := r.claims()
	c["groups"] = []any{"team-a", "Domain Users", "", 42, map[string]string{"a": "b"}, "team-b"}
	id, err := v.Verify(context.Background(), r.es(c))
	if err != nil || len(id.Groups) != 2 || id.Groups[0] != "team-a" || id.Groups[1] != "team-b" {
		t.Fatalf("%+v %v", id, err)
	}
	// A single malformed string leaves no groups, and the token still verifies.
	c["groups"] = "Domain Users"
	if id, err := v.Verify(context.Background(), r.es(c)); err != nil || len(id.Groups) != 0 {
		t.Errorf("%+v %v", id, err)
	}
	// Malformed identity claims still refuse the whole token.
	for name, mutate := range map[string]func(map[string]any){
		"subject with a space": func(c map[string]any) { c["sub"] = "a b" },
		"subject not a string": func(c map[string]any) { c["sub"] = 7 },
		"wrong issuer":         func(c map[string]any) { c["iss"] = "https://evil.example" },
		"wrong audience":       func(c map[string]any) { c["aud"] = "other" },
		"no expiry":            func(c map[string]any) { delete(c, "exp") },
	} {
		c := r.claims()
		mutate(c)
		if _, err := v.Verify(context.Background(), r.es(c)); err == nil {
			t.Errorf("%s: admitted", name)
		}
	}
}

func TestSignedVerifierAllowsSkewOnTheForwardLifetimeBound(t *testing.T) {
	r := newSignedRig(t)
	v := r.verifier(r.config())
	// A one-hour token from an issuer whose clock is 5s ahead: exp is now+3605 against a 1h maximum.
	c := r.claims()
	c["iat"], c["exp"] = r.now.Unix()+5, r.now.Unix()+3605
	if _, err := v.Verify(context.Background(), r.es(c)); err != nil {
		t.Errorf("fresh token, issuer clock ahead by less than the skew: %v", err)
	}
	// The skew does not stretch the token's own lifetime cap.
	c["iat"], c["exp"] = r.now.Unix()+5, r.now.Unix()+3607
	if _, err := v.Verify(context.Background(), r.es(c)); reasonOf(err) != "oidc_lifetime" {
		t.Errorf("lifetime over the maximum: %v", err)
	}
}

func TestSignedVerifierRefusesRedirectedKeysEvenFromAFollowingClient(t *testing.T) {
	r := newSignedRig(t)
	redirect := func(to string) *httptest.Server {
		return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { http.Redirect(w, req, to, http.StatusFound) }))
	}
	jwks := redirect(r.srv.URL + "/keys")
	defer jwks.Close()
	cfg := r.config()
	cfg.JWKSURL = jwks.URL
	// jwks.Client() follows redirects by default; the verifier must not.
	if _, err := NewSignedVerifier(cfg, jwks.Client(), func() time.Time { return r.now }).Verify(context.Background(), r.es(r.claims())); reasonOf(err) != ReasonKeysUnavailable {
		t.Errorf("redirected key set: %v", err)
	}
	disco := redirect(r.srv.URL + "/.well-known/openid-configuration")
	defer disco.Close()
	r.discoIssuer = disco.URL
	cfg = r.config()
	cfg.JWKSURL, cfg.Discovery, cfg.Issuer = "", true, disco.URL
	c := r.claims()
	c["iss"] = disco.URL
	if _, err := NewSignedVerifier(cfg, disco.Client(), func() time.Time { return r.now }).Verify(context.Background(), r.es(c)); reasonOf(err) != ReasonKeysUnavailable {
		t.Errorf("redirected discovery document: %v", err)
	}
	// A redirect to the discovered key URL is refused the same way.
	r.discoIssuer, r.discoURI = "", jwks.URL
	cfg.Issuer = r.srv.URL
	c["iss"] = r.srv.URL
	cfg.Discovery = true
	if _, err := NewSignedVerifier(cfg, r.srv.Client(), func() time.Time { return r.now }).Verify(context.Background(), r.es(c)); reasonOf(err) != ReasonKeysUnavailable {
		t.Errorf("redirected discovered key URL: %v", err)
	}
}

func TestSignedVerifierRequiredClaims(t *testing.T) {
	r := newSignedRig(t)
	cfg := r.config()
	cfg.RequiredClaims = map[string]string{"tenant": "acme", "env": "prod"}
	v := r.verifier(cfg)
	good := func(mutate func(map[string]any)) string {
		c := r.claims()
		c["tenant"], c["env"] = "acme", "prod"
		mutate(c)
		return r.es(c)
	}
	if _, err := v.Verify(context.Background(), good(func(map[string]any) {})); err != nil {
		t.Fatalf("matching claims: %v", err)
	}
	for name, mutate := range map[string]func(map[string]any){
		"another tenant":       func(c map[string]any) { c["tenant"] = "other" },
		"a missing claim":      func(c map[string]any) { delete(c, "env") },
		"a claim not a string": func(c map[string]any) { c["tenant"] = 7 },
		"a list for a string":  func(c map[string]any) { c["tenant"] = []string{"acme"} },
		"a prefix match":       func(c map[string]any) { c["tenant"] = "acme2" },
	} {
		if _, err := v.Verify(context.Background(), good(mutate)); reasonOf(err) != "oidc_claim_missing" {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestSignedVerifierRefusesAKeySetWithNoUsableKey(t *testing.T) {
	small, _ := rsa.GenerateKey(rand.Reader, 1024) // #nosec G403 -- the weak key under test
	if small == nil {
		t.Skip("FIPS 140-only mode cannot generate a 1024-bit RSA key")
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{"kty": "RSA", "kid": "weak", "alg": "RS256", "use": "sig", "n": enc(small.N.Bytes()), "e": enc([]byte{1, 0, 1})}}})
	}))
	defer srv.Close()
	r := newSignedRig(t)
	cfg := r.config()
	cfg.JWKSURL = srv.URL
	v := NewSignedVerifier(cfg, srv.Client(), func() time.Time { return r.now })
	if _, err := v.Verify(context.Background(), r.es(r.claims())); reasonOf(err) != ReasonKeysUnavailable {
		t.Errorf("a set whose only key is too small: %v", err)
	}
}

func TestSignedVerifierRefusesAnAlgorithmTheHarnessDoesNotList(t *testing.T) {
	r := newSignedRig(t)
	cfg := r.config()
	cfg.Algorithms = []string{"ES256"}
	v := r.verifier(cfg)
	rs := r.sign(map[string]any{"alg": "RS256", "kid": "rsa1"}, r.claims(), r.rsa)
	if _, err := v.Verify(context.Background(), rs); reasonOf(err) != "oidc_algorithm" {
		t.Errorf("RS256 token against an ES256-only config: %v", err)
	}
	if _, err := v.Verify(context.Background(), r.es(r.claims())); err != nil {
		t.Errorf("ES256 token on the same config: %v", err)
	}
}

func TestSignedVerifierClockSkewEdges(t *testing.T) {
	r := newSignedRig(t)
	skew := r.config().ClockSkew.Seconds()
	cases := map[string]struct {
		claim  string
		offset int64
		want   string
	}{
		"iat just inside the skew":  {"iat", int64(skew), ""},
		"iat just outside the skew": {"iat", int64(skew) + 1, "oidc_not_yet_valid"},
		"nbf just inside the skew":  {"nbf", int64(skew), ""},
		"nbf just outside the skew": {"nbf", int64(skew) + 1, "oidc_not_yet_valid"},
		"nbf in the past":           {"nbf", -300, ""},
		"iat well in the past":      {"iat", -300, ""},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			c := r.claims()
			c[tc.claim] = r.now.Unix() + tc.offset
			_, err := r.verifier(r.config()).Verify(context.Background(), r.es(c))
			if tc.want == "" {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			if got := reasonOf(err); got != tc.want {
				t.Errorf("reason %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSignedVerifierKeepsPreviousKeysWhenAFetchReturnsNoKeys(t *testing.T) {
	for name, body := range map[string]string{"empty object": `{}`, "empty key list": `{"keys":[]}`, "proxy error body": `{"error":"upstream unavailable"}`} {
		t.Run(name, func(t *testing.T) {
			r := newSignedRig(t)
			v := r.verifier(r.config())
			if _, err := v.Verify(context.Background(), r.es(r.claims())); err != nil {
				t.Fatal(err)
			}
			r.rawBody.Store(&body)
			r.now = r.now.Add(2 * time.Minute) // past the refetch backoff, inside half the key age
			// An unknown kid forces a fetch, which must count as failed.
			unknown := r.sign(map[string]any{"alg": "ES256", "kid": "rotated"}, r.claims(), r.other)
			if _, err := v.Verify(context.Background(), unknown); reasonOf(err) != ReasonKeysUnavailable {
				t.Errorf("unknown kid after a keyless fetch: %v", err)
			}
			if _, err := v.Verify(context.Background(), r.es(r.claims())); err != nil {
				t.Errorf("good token after a keyless fetch: %v", err)
			}
		})
	}
}

func TestSignedVerifierFetchErrorsNameTheIssuer(t *testing.T) {
	r := newSignedRig(t)
	r.status.Store(http.StatusInternalServerError)
	v := r.verifier(r.config())
	if _, err := v.cache.fetch(context.Background()); err == nil || !strings.Contains(err.Error(), rigIssuer) {
		t.Errorf("JWKS fetch error: %v", err)
	}
	cfg := r.config()
	cfg.Discovery, cfg.Issuer = true, r.srv.URL
	cfg.JWKSURL = ""
	if _, err := r.verifier(cfg).cache.fetch(context.Background()); err == nil || !strings.Contains(err.Error(), r.srv.URL) {
		t.Errorf("discovery fetch error: %v", err)
	}
}
