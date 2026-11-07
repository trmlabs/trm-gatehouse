package agenttoken

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/authorize"
	"github.com/Infisical/agent-vault/internal/httpcatalog"
)

const signedIssuer = "https://issuer.example"

type liveCatalog struct{ c httpcatalog.Catalog }

func (l *liveCatalog) Current() httpcatalog.Catalog { return l.c }

type signedFixture struct {
	key *ecdsa.PrivateKey
	srv *httptest.Server
	now time.Time
	// skew is the clockSkewSeconds member (with its trailing comma) the harness carries; empty leaves it unset.
	skew string
}

func newSignedFixture(t *testing.T) *signedFixture {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	point, _ := key.PublicKey.Bytes()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{"kty": "EC", "crv": "P-256", "kid": "k1", "alg": "ES256",
			"use": "sig", "x": b64(point[1:33]), "y": b64(point[33:65])}}})
	}))
	t.Cleanup(srv.Close)
	return &signedFixture{key: key, srv: srv, now: time.Now()}
}

func (f *signedFixture) token(t *testing.T, mutate func(map[string]any)) string {
	t.Helper()
	claims := map[string]any{"iss": signedIssuer, "aud": "gatehouse", "sub": "sa-1@example", "groups": []string{"team-a"},
		"iat": f.now.Unix(), "exp": f.now.Unix() + 600}
	if mutate != nil {
		mutate(claims)
	}
	header, _ := json.Marshal(map[string]string{"alg": "ES256", "kid": "k1"})
	payload, _ := json.Marshal(claims)
	input := b64(header) + "." + b64(payload)
	digest := sha256.Sum256([]byte(input))
	r, s, _ := ecdsa.Sign(rand.Reader, f.key, digest[:])
	return input + "." + b64(append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...))
}

// catalog serves one automations pool; audiences and the agent groups are the parts a test varies.
func (f *signedFixture) catalog(t *testing.T, audiences string, groups string, extraBlocks string) httpcatalog.Catalog {
	t.Helper()
	c, err := httpcatalog.Parse([]byte(fmt.Sprintf(`{
	 "harnesses":[
	  {"name":"token-agents","identity":{"kind":"static-token"},"path":{"kind":"direct"},"authorization":{"mode":"automation","poolName":"automations"},
	   "client":{"proxyEnv":"EXAMPLE_PROXY","caFileEnv":"EXAMPLE_CA_FILE"}},
	  {"name":"platform-a","identity":{"kind":"signed-token","token":{"issuer":%q,"jwksURL":%q,"audiences":[%s],"algorithms":["ES256"],
	   "maxLifetimeSeconds":3600,%s"subjectClaim":"sub","groupsClaim":"groups"}},
	   "path":{"kind":"direct"},"authorization":{"mode":"automation","poolName":"automations"},"client":{"proxyEnv":"EXAMPLE_PROXY","caFileEnv":"EXAMPLE_CA_FILE"}}],
	 "pools":[{"name":"automations","namespace":"n","serviceAccount":"worker","identity":"cursor-automation"}],
	 "entries":[{"name":"open","host":"api.vendor.example","pathPrefixes":["/open/"],"methods":["GET"],"header":"Authorization","placeholder":"__vault_KEY__","key":{"mount":"gatehouse","path":"vendors/p","field":"f"},"pools":["automations"]}],
	 "automations":[{"id":"agent-a","name":"agent-a","owner":"platform-team","entries":["open"],"signedToken":{"harness":"platform-a","subject":"sa-1@example"%s}}%s]}`,
		signedIssuer, f.srv.URL, audiences, f.skew, groups, extraBlocks)))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (f *signedFixture) verifier(cat *liveCatalog) *Signed {
	return &Signed{Catalog: cat, Client: f.srv.Client(), Now: func() time.Time { return f.now }}
}

func TestSignedAdmitsAnAutomationByItsConfiguredClaims(t *testing.T) {
	f := newSignedFixture(t)
	cat := &liveCatalog{f.catalog(t, `"gatehouse"`, "", "")}
	s, err := f.verifier(cat).Verify(context.Background(), f.token(t, nil))
	if err != nil || s.Automation != "agent-a" || s.Pool != "automations" || s.Source != authorize.SourceSignedToken || !s.Expires.Equal(time.Unix(f.now.Unix()+600, 0)) {
		t.Fatalf("%+v %v", s, err)
	}
}

func TestSignedRefusals(t *testing.T) {
	f := newSignedFixture(t)
	cat := &liveCatalog{f.catalog(t, `"gatehouse"`, `,"groups":["team-x","team-a"]`, "")}
	v := f.verifier(cat)
	for name, tc := range map[string]struct {
		mutate func(map[string]any)
		want   string
	}{
		"a subject no block names":           {func(c map[string]any) { c["sub"] = "sa-9@example" }, ReasonSubjectUnlisted},
		"none of the groups the block needs": {func(c map[string]any) { c["groups"] = []string{"team-q"} }, ReasonGroupMissing},
		"no groups at all":                   {func(c map[string]any) { delete(c, "groups") }, ReasonGroupMissing},
		"the wrong audience":                 {func(c map[string]any) { c["aud"] = "other" }, "oidc_audience"},
		"an expired token":                   {func(c map[string]any) { c["exp"] = f.now.Unix() - 5 }, "oidc_expired"},
		"a lifetime past the harness maximum": {func(c map[string]any) {
			c["iat"], c["exp"] = f.now.Unix()-7200, f.now.Unix()+60
		}, "oidc_lifetime"},
	} {
		if _, err := v.Verify(context.Background(), f.token(t, tc.mutate)); reason(err) != tc.want {
			t.Errorf("%s: %q, want %q", name, reason(err), tc.want)
		}
	}
	// Any one of the listed groups is enough.
	if _, err := v.Verify(context.Background(), f.token(t, func(c map[string]any) { c["groups"] = []string{"other", "team-x"} })); err != nil {
		t.Errorf("one listed group: %v", err)
	}
}

func TestSignedFollowsTheLiveCatalog(t *testing.T) {
	f := newSignedFixture(t)
	cat := &liveCatalog{f.catalog(t, `"gatehouse"`, "", "")}
	v := f.verifier(cat)
	ctx := context.Background()
	if _, err := v.Verify(ctx, f.token(t, nil)); err != nil {
		t.Fatal(err)
	}
	// A changed audience applies at the next call, with no restart.
	cat.c = f.catalog(t, `"gatehouse-v2"`, "", "")
	if _, err := v.Verify(ctx, f.token(t, nil)); reason(err) != "oidc_audience" {
		t.Errorf("after the audience changed: %v", reason(err))
	}
	if _, err := v.Verify(ctx, f.token(t, func(c map[string]any) { c["aud"] = "gatehouse-v2" })); err != nil {
		t.Errorf("new audience: %v", err)
	}
	// A removed harness is no longer handled, and its verifier is forgotten once another is built.
	plain, err := httpcatalog.Parse([]byte(`{"pools":[{"name":"automations","namespace":"n","serviceAccount":"worker","identity":"cursor-automation"}],
	 "entries":[{"name":"open","host":"api.vendor.example","pathPrefixes":["/open/"],"methods":["GET"],"header":"Authorization","placeholder":"__vault_KEY__","key":{"mount":"gatehouse","path":"vendors/p","field":"f"},"pools":["automations"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	cat.c = plain
	if v.Handles(f.token(t, nil)) {
		t.Error("a removed harness still handles its issuer")
	}
	if _, err := v.Verify(ctx, f.token(t, nil)); reason(err) != "oidc_issuer" {
		t.Errorf("after the harness was removed: %v", reason(err))
	}
}

func TestSignedForgetsVerifiersOfRemovedHarnesses(t *testing.T) {
	f := newSignedFixture(t)
	cat := &liveCatalog{f.catalog(t, `"gatehouse"`, "", "")}
	v := f.verifier(cat)
	if _, err := v.Verify(context.Background(), f.token(t, nil)); err != nil {
		t.Fatal(err)
	}
	if len(v.verifiers) != 1 {
		t.Fatalf("%d verifiers", len(v.verifiers))
	}
	v.verifiers["gone"] = cachedVerifier{}
	cat.c = f.catalog(t, `"gatehouse-v2"`, "", "")
	_, _ = v.Verify(context.Background(), f.token(t, nil))
	if _, kept := v.verifiers["gone"]; kept || len(v.verifiers) != 1 {
		t.Errorf("verifiers %d, gone kept %v", len(v.verifiers), kept)
	}
}

func TestByIssuerRoutesWithoutChangingTheOtherVerifiers(t *testing.T) {
	f := newSignedFixture(t)
	gl := newGumloopFixture(t)
	static, hash, _ := Mint("agent-1")
	extra := fmt.Sprintf(`,{"id":"agent-1","name":"agent-1","owner":"platform-team","entries":["open"],"tokenSHA256":["%s"],"expires":%q}`, hash, soon().Format(time.RFC3339)) +
		`,{"id":"gl","name":"gl","owner":"platform-team","entries":["open"],"gumloop":{"orgID":"org-1"}}`
	cat := &liveCatalog{f.catalog(t, `"gatehouse"`, "", extra)}
	either := Either{Static: Static{Catalog: cat}, OIDC: SignedByIssuer{
		Signed: f.verifier(cat), Fallback: GumloopOIDC{Catalog: cat, Verifier: gl.v}}}
	ctx := context.Background()
	if s, err := either.Verify(ctx, static); err != nil || s.Automation != "agent-1" || s.Source != "" {
		t.Errorf("static: %+v %v", s, err)
	}
	if s, err := either.Verify(ctx, gl.token(t, "org-1", "")); err != nil || s.Automation != "gl" || s.Source != authorize.SourceGumloopOIDC {
		t.Errorf("gumloop: %+v %v", s, err)
	}
	if s, err := either.Verify(ctx, f.token(t, nil)); err != nil || s.Automation != "agent-a" || s.Source != authorize.SourceSignedToken {
		t.Errorf("signed: %+v %v", s, err)
	}
	// A signed token for an issuer no harness names is never read as a Gumloop or a signed one.
	if _, err := either.Verify(ctx, f.token(t, func(c map[string]any) { c["iss"] = "https://unknown.example" })); err == nil {
		t.Error("a token from an unlisted issuer was admitted")
	}
	// With no Gumloop verifier, a token no harness claims is refused as malformed, as before.
	only := Either{Static: Static{Catalog: cat}, OIDC: SignedByIssuer{Signed: f.verifier(cat)}}
	if _, err := only.Verify(ctx, gl.token(t, "org-1", "")); reason(err) != ReasonMalformed {
		t.Errorf("no fallback: %v", reason(err))
	}
	if _, err := only.Verify(ctx, strings.Repeat("x", 20)); reason(err) != ReasonMalformed {
		t.Errorf("garbage: %v", reason(err))
	}
}

func TestByIssuerDefersReservedIssuersToTheFallback(t *testing.T) {
	f := newSignedFixture(t)
	cat := &liveCatalog{f.catalog(t, `"gatehouse"`, "", "")}
	reserved := Either{Static: Static{Catalog: cat}, OIDC: SignedByIssuer{Signed: f.verifier(cat), Reserved: []string{signedIssuer}}}
	// The harness names this issuer, but another verifier owns it, so the signed path never admits the token.
	if _, err := reserved.Verify(context.Background(), f.token(t, nil)); err == nil {
		t.Error("a token for a reserved issuer was admitted by a signed-token harness")
	}
}

func TestSignedClockSkewZeroUnsetAndPositive(t *testing.T) {
	// A token issued 30s ahead of the broker's clock.
	ahead := func(c map[string]any) { c["iat"] = c["iat"].(int64) + 30 }
	for name, tc := range map[string]struct {
		skew string
		want string
	}{
		"unset keeps the 60s default": {"", ""},
		"zero means no skew":          {`"clockSkewSeconds":0,`, "oidc_not_yet_valid"},
		"a positive value applies":    {`"clockSkewSeconds":10,`, "oidc_not_yet_valid"},
		"a larger positive value":     {`"clockSkewSeconds":45,`, ""},
	} {
		t.Run(name, func(t *testing.T) {
			f := newSignedFixture(t)
			f.skew = tc.skew
			v := f.verifier(&liveCatalog{f.catalog(t, `"gatehouse"`, "", "")})
			_, err := v.Verify(context.Background(), f.token(t, ahead))
			if tc.want == "" && err != nil || tc.want != "" && reason(err) != tc.want {
				t.Errorf("got %v, want %q", err, tc.want)
			}
		})
	}
}
