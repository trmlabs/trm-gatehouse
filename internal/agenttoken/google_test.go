package agenttoken

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"crypto"

	"github.com/Infisical/agent-vault/internal/authorize"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/httpcatalog"
	"github.com/Infisical/agent-vault/internal/runnerid"
)

type googleFixture struct {
	key *rsa.PrivateKey
	v   *runnerid.GoogleVerifier
	now time.Time
}

func newGoogleFixture(t *testing.T) *googleFixture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{"kty": "RSA", "kid": "g1", "alg": "RS256", "use": "sig",
			"n": b64(key.N.Bytes()), "e": b64(big.NewInt(int64(key.E)).Bytes())}}})
	}))
	t.Cleanup(srv.Close)
	f := &googleFixture{key: key, now: time.Now()}
	f.v = &runnerid.GoogleVerifier{JWKSURL: srv.URL, Issuer: runnerid.GoogleIssuer, Audience: "gatehouse-broker", Client: srv.Client(),
		Now: func() time.Time { return f.now }}
	return f
}

func (f *googleFixture) token(t *testing.T, sub, email string) string {
	t.Helper()
	claims := map[string]any{"iss": runnerid.GoogleIssuer, "aud": "gatehouse-broker", "iat": f.now.Unix(), "exp": f.now.Unix() + 3600, "sub": sub}
	if email != "" {
		claims["email"], claims["email_verified"] = email, true
	}
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "g1"})
	payload, _ := json.Marshal(claims)
	input := b64(header) + "." + b64(payload)
	digest := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + b64(sig)
}

func googleBlock(id, email, uniqueID string) string {
	return fmt.Sprintf(`{"id":%q,"name":%q,"owner":"platform-team","entries":["open"],"googleServiceAccount":{"email":%q,"uniqueID":%q}}`, id, id, email, uniqueID)
}

const (
	googleAccount = "worker-one@example-project.iam.gserviceaccount.com"
	googleID      = "104857263948571029384"
	googleOther   = "worker-two@example-project.iam.gserviceaccount.com"
	googleOtherID = "204857263948571029384"
)

func TestGoogleOIDCNamesTheAutomationByUniqueID(t *testing.T) {
	f := newGoogleFixture(t)
	cat := catalogWith(t, googleBlock("one", googleAccount, googleID)+","+googleBlock("two", googleOther, googleOtherID))
	v := GoogleOIDC{Catalog: cat, Verifier: f.v}
	for _, tc := range []struct{ sub, email, want string }{
		{googleID, googleAccount, "one"}, {googleOtherID, googleOther, "two"}, {googleID, "", "one"},
	} {
		s, err := v.Verify(context.Background(), f.token(t, tc.sub, tc.email))
		if err != nil || s.Automation != tc.want || s.Pool != "automations" || s.Source != authorize.SourceGoogleOIDC || s.Owner != "" || !s.Expires.After(f.now) {
			t.Errorf("%s %q: %+v %v", tc.sub, tc.email, s, err)
		}
	}
}

func TestGoogleOIDCRefusals(t *testing.T) {
	f := newGoogleFixture(t)
	v := GoogleOIDC{Catalog: catalogWith(t, googleBlock("one", googleAccount, googleID)), Verifier: f.v}
	for name, tc := range map[string]struct{ sub, email, reason string }{
		"an unlisted unique ID":             {googleOtherID, googleOther, ReasonServiceAccountUnlisted},
		"a wrong sub with the email listed": {googleOtherID, googleAccount, ReasonServiceAccountUnlisted},
		"the right sub with another email":  {googleID, googleOther, ReasonEmailMismatch},
		"no sub":                            {"", googleAccount, "oidc_subject_missing"},
	} {
		if _, err := v.Verify(context.Background(), f.token(t, tc.sub, tc.email)); reason(err) != tc.reason {
			t.Errorf("%s: %q", name, reason(err))
		}
	}
	expired := f.token(t, googleID, googleAccount)
	f.now = f.now.Add(2 * time.Hour)
	if _, err := v.Verify(context.Background(), expired); reason(err) != "oidc_expired" {
		t.Errorf("an expired token: %q", reason(err))
	}
	if _, err := v.Verify(context.Background(), "not.a.token"); reason(err) == "" {
		t.Error("a refusal with no reason code has no audit row")
	}
}

func TestGoogleOIDCRefusesTheNextRequestOnceTheBlockIsRemoved(t *testing.T) {
	f := newGoogleFixture(t)
	live := &swapCatalog{cat: catalogWith(t, googleBlock("one", googleAccount, googleID))}
	v := GoogleOIDC{Catalog: live, Verifier: f.v}
	token := f.token(t, googleID, googleAccount)
	if _, err := v.Verify(context.Background(), token); err != nil {
		t.Fatal(err)
	}
	live.cat = catalogWith(t, googleBlock("two", googleOther, googleOtherID))
	if _, err := v.Verify(context.Background(), token); reason(err) != ReasonServiceAccountUnlisted {
		t.Fatalf("after the block was removed: %q", reason(err))
	}
}

type swapCatalog struct{ cat httpcatalog.Catalog }

func (s *swapCatalog) Current() httpcatalog.Catalog { return s.cat }

func TestGoogleOIDCIsNotAGumloopBlock(t *testing.T) {
	f := newGoogleFixture(t)
	cat := catalogWith(t, gumloopBlock("gl", "org-1", ""))
	if _, err := (GoogleOIDC{Catalog: cat, Verifier: f.v}).Verify(context.Background(), f.token(t, googleID, googleAccount)); reason(err) != ReasonServiceAccountUnlisted {
		t.Errorf("a catalog with no Google block: %q", reason(err))
	}
}

func TestByIssuerRoutesByTheTokensIssuer(t *testing.T) {
	g, gl := newGoogleFixture(t), newGumloopFixture(t)
	cat := catalogWith(t, googleBlock("goog", googleAccount, googleID)+","+gumloopBlock("gl", "org-1", ""))
	both := ByIssuer{Google: GoogleOIDC{Catalog: cat, Verifier: g.v}, Gumloop: GumloopOIDC{Catalog: cat, Verifier: gl.v}}
	if s, err := both.Verify(context.Background(), g.token(t, googleID, googleAccount)); err != nil || s.Automation != "goog" || s.Source != authorize.SourceGoogleOIDC {
		t.Fatalf("google: %+v %v", s, err)
	}
	if s, err := both.Verify(context.Background(), gl.token(t, "org-1", "")); err != nil || s.Automation != "gl" || s.Source != authorize.SourceGumloopOIDC {
		t.Fatalf("gumloop: %+v %v", s, err)
	}
	if _, err := both.Verify(context.Background(), "a.b.c"); reason(err) == "" {
		t.Error("an unroutable token was refused without a code")
	}
}

func TestEitherSendsGoogleTokensToOIDC(t *testing.T) {
	f := newGoogleFixture(t)
	static, hash, _ := Mint("agent-1")
	cat := catalogWith(t, block("agent-1", hash)+","+googleBlock("goog", googleAccount, googleID))
	e := Either{Static: Static{Catalog: cat}, OIDC: GoogleOIDC{Catalog: cat, Verifier: f.v}}
	if s, err := e.Verify(context.Background(), f.token(t, googleID, googleAccount)); err != nil || s.Automation != "goog" {
		t.Fatalf("oidc: %+v %v", s, err)
	}
	if s, err := e.Verify(context.Background(), static); err != nil || s.Automation != "agent-1" || s.Source != "" {
		t.Fatalf("static: %+v %v", s, err)
	}
}

type countingVerifier struct{ calls int }

func (c *countingVerifier) Verify(context.Context, string) (Session, error) {
	c.calls++
	return Session{}, brokercore.Denied("stub")
}

func TestByIssuerDoesNotDecodeAnOversizedToken(t *testing.T) {
	google, gumloop := &countingVerifier{}, &countingVerifier{}
	b := ByIssuer{Google: google, Gumloop: gumloop}
	payload, _ := json.Marshal(map[string]string{"iss": runnerid.GoogleIssuer, "pad": strings.Repeat("a", runnerid.MaxTokenBytes)})
	big := "e30." + b64(payload) + ".c2ln"
	_, _ = b.Verify(context.Background(), big)
	if google.calls != 0 || gumloop.calls != 1 {
		t.Fatalf("oversized: google %d, gumloop %d", google.calls, gumloop.calls)
	}
	small, _ := json.Marshal(map[string]string{"iss": runnerid.GoogleIssuer})
	_, _ = b.Verify(context.Background(), "e30."+b64(small)+".c2ln")
	if google.calls != 1 {
		t.Fatalf("a Google-issued token did not reach Google: %d", google.calls)
	}
}
