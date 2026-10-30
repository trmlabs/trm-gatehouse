package agenttoken

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/authorize"
	"github.com/Infisical/agent-vault/internal/runnerid"
)

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

type gumloopFixture struct {
	key *ecdsa.PrivateKey
	v   *runnerid.GumloopVerifier
	now time.Time
}

func newGumloopFixture(t *testing.T) *gumloopFixture {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	point, _ := key.PublicKey.Bytes()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{"kty": "EC", "crv": "P-256", "kid": "k1", "alg": "ES256",
			"use": "sig", "x": b64(point[1:33]), "y": b64(point[33:65])}}})
	}))
	t.Cleanup(srv.Close)
	f := &gumloopFixture{key: key, now: time.Now()}
	f.v = &runnerid.GumloopVerifier{JWKSURL: srv.URL, Issuer: runnerid.GumloopIssuer, Audience: "gatehouse-broker", Client: srv.Client(),
		Now: func() time.Time { return f.now }}
	return f
}

func (f *gumloopFixture) token(t *testing.T, org, owner string) string {
	t.Helper()
	claims := map[string]any{"iss": runnerid.GumloopIssuer, "aud": "gatehouse-broker", "iat": f.now.Unix(), "exp": f.now.Unix() + 3600, "gumloop_org_id": org}
	if owner != "" {
		claims["gumloop_owner_id"], claims["gumloop_owner_type"] = owner, "user"
	}
	header, _ := json.Marshal(map[string]string{"alg": "ES256", "kid": "k1"})
	payload, _ := json.Marshal(claims)
	input := b64(header) + "." + b64(payload)
	digest := sha256.Sum256([]byte(input))
	r, s, _ := ecdsa.Sign(rand.Reader, f.key, digest[:])
	return input + "." + b64(append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...))
}

func gumloopBlock(id, org, owner string) string {
	own := ""
	if owner != "" {
		own = fmt.Sprintf(`,"ownerID":%q`, owner)
	}
	return fmt.Sprintf(`{"id":%q,"name":%q,"owner":"platform-team","entries":["open"],"gumloop":{"orgID":%q%s}}`, id, id, org, own)
}

func TestGumloopOIDCNamesTheAutomationByOrgAndOwner(t *testing.T) {
	f := newGumloopFixture(t)
	cat := catalogWith(t, gumloopBlock("org-wide", "org-1", "")+","+gumloopBlock("one-owner", "org-1", "owner-7")+","+gumloopBlock("other-org", "org-2", ""))
	v := GumloopOIDC{Catalog: cat, Verifier: f.v}
	for name, tc := range map[string]struct{ org, owner, want string }{
		"the org's block":                  {"org-1", "", "org-wide"},
		"an owner the org's block covers":  {"org-1", "owner-9", "org-wide"},
		"an owner with a block of its own": {"org-1", "owner-7", "one-owner"},
		"another org's block":              {"org-2", "owner-7", "other-org"},
	} {
		s, err := v.Verify(context.Background(), f.token(t, tc.org, tc.owner))
		if err != nil || s.Automation != tc.want || s.Pool != "automations" || s.Source != authorize.SourceGumloopOIDC || s.Owner != tc.owner || !s.Expires.After(f.now) {
			t.Errorf("%s: %+v %v", name, s, err)
		}
	}
}

func TestGumloopOIDCRefusals(t *testing.T) {
	f := newGumloopFixture(t)
	v := GumloopOIDC{Catalog: catalogWith(t, gumloopBlock("only-owner", "org-1", "owner-7")), Verifier: f.v}
	if _, err := v.Verify(context.Background(), f.token(t, "org-9", "owner-7")); reason(err) != ReasonOrgUnlisted {
		t.Errorf("an unlisted org: %v", reason(err))
	}
	// A listed org with an owner the block does not name, or none.
	for _, owner := range []string{"owner-8", ""} {
		if _, err := v.Verify(context.Background(), f.token(t, "org-1", owner)); reason(err) != ReasonOrgUnlisted {
			t.Errorf("owner %q: %v", owner, reason(err))
		}
	}
	f.now = f.now.Add(2 * time.Hour)
	if _, err := v.Verify(context.Background(), f.token(t, "org-1", "owner-7")); err != nil {
		t.Fatal(err)
	}
	expired := f.token(t, "org-1", "owner-7")
	f.now = f.now.Add(2 * time.Hour)
	if _, err := v.Verify(context.Background(), expired); reason(err) != "oidc_expired" {
		t.Errorf("an expired token: %v", reason(err))
	}
	if _, err := v.Verify(context.Background(), "not.a.token"); reason(err) == "" {
		t.Error("a refusal with no reason code has no audit row")
	}
}

func TestEitherRoutesByShape(t *testing.T) {
	f := newGumloopFixture(t)
	static, hash, _ := Mint("agent-1")
	cat := catalogWith(t, block("agent-1", hash)+","+gumloopBlock("gl", "org-1", ""))
	e := Either{Static: Static{Catalog: cat}, OIDC: GumloopOIDC{Catalog: cat, Verifier: f.v}}
	if s, err := e.Verify(context.Background(), static); err != nil || s.Automation != "agent-1" || s.Source != "" {
		t.Fatalf("static: %+v %v", s, err)
	}
	if s, err := e.Verify(context.Background(), f.token(t, "org-1", "")); err != nil || s.Automation != "gl" {
		t.Fatalf("oidc: %+v %v", s, err)
	}
	// A static token under an id with dots stays static.
	dotted, dottedHash, _ := Mint("team.agent-1")
	cat = catalogWith(t, block("team.agent-1", dottedHash))
	e = Either{Static: Static{Catalog: cat}, OIDC: GumloopOIDC{Catalog: cat, Verifier: f.v}}
	if s, err := e.Verify(context.Background(), dotted); err != nil || s.Automation != "team.agent-1" {
		t.Fatalf("dotted static: %+v %v", s, err)
	}
	// Without an OIDC verifier a signed token is a malformed static one.
	if _, err := (Either{Static: Static{Catalog: cat}}).Verify(context.Background(), f.token(t, "org-1", "")); reason(err) != ReasonMalformed {
		t.Errorf("oidc off: %v", reason(err))
	}
	// A static token is not accepted as the other kind's identity: a Gumloop block has no token.
	if _, err := e.Verify(context.Background(), strings.Replace(static, "agent-1", "gl", 1)); reason(err) == "" {
		t.Error("a forged static token for a Gumloop block was admitted")
	}
}
