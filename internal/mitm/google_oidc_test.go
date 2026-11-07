package mitm

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/agenttoken"
	"github.com/Infisical/agent-vault/internal/authorize"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/runnerid"
)

func TestResolveAgentTokenGoogleOIDC(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n, e := base64.RawURLEncoding.EncodeToString(key.N.Bytes()), base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())
		_, _ = fmt.Fprintf(w, `{"keys":[{"kty":"RSA","kid":"g1","alg":"RS256","use":"sig","n":%q,"e":%q}]}`, n, e)
	}))
	defer jwks.Close()
	const account, uniqueID = "worker-one@example-project.iam.gserviceaccount.com", "104857263948571029384"
	sign := func(sub, email string, verified bool, exp time.Time) string {
		header, payload := `{"alg":"RS256","kid":"g1"}`, fmt.Sprintf(`{"iss":%q,"aud":"gatehouse-broker","exp":%d,"sub":%q,"email":%q,"email_verified":%t}`, runnerid.GoogleIssuer, exp.Unix(), sub, email, verified)
		input := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload))
		digest := sha256.Sum256([]byte(input))
		sig, _ := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
		return input + "." + base64.RawURLEncoding.EncodeToString(sig)
	}
	catalog := staticCatalog(t, 443, `{"id":"gg-1","name":"google-one","owner":"platform-team","entries":["llm"],"googleServiceAccount":{"email":"`+account+`","uniqueID":"`+uniqueID+`"}}`)
	verifier := &runnerid.GoogleVerifier{JWKSURL: jwks.URL, Issuer: runnerid.GoogleIssuer, Audience: "gatehouse-broker", Client: jwks.Client()}
	p := &Proxy{agentTokens: agenttoken.Either{Static: agenttoken.Static{Catalog: catalog}, OIDC: agenttoken.GoogleOIDC{Catalog: catalog, Verifier: verifier}}}
	peer := netip.MustParseAddr("192.0.2.7")
	ctx := withKinds(context.Background(), []string{brokercore.KindStaticToken})
	exp := time.Now().Add(time.Hour)
	scope, err := p.resolveScope(ctx, sign(uniqueID, account, true, exp), "", peer, nil, false)
	if err != nil || scope.AgentID != "gg-1" || scope.Automation != "gg-1" || scope.Pool != "automations" || scope.IdentityKind != brokercore.KindStaticToken ||
		scope.TokenSource != authorize.SourceGoogleOIDC || scope.TokenOwner != "" || scope.NotAfter.IsZero() || scope.NotAfter.After(exp.Add(time.Second)) {
		t.Fatalf("%+v %v", scope, err)
	}
	good := sign(uniqueID, account, true, exp)
	for name, tc := range map[string]struct{ token, reason string }{
		"a wrong sub with the email listed": {sign("204857263948571029384", account, true, exp), agenttoken.ReasonServiceAccountUnlisted},
		"an unverified email":               {sign(uniqueID, account, false, exp), "oidc_email_unverified"},
		"an expired token":                  {sign(uniqueID, account, true, time.Now().Add(-time.Minute)), "oidc_expired"},
		"a bad signature":                   {good[:len(good)-4] + "AAAA", "oidc_signature"},
		"a token of no shape":               {"a.b.c", "oidc_malformed"},
	} {
		_, err := p.resolveScope(ctx, tc.token, "", peer, nil, false)
		if brokercore.DenialReason(err) != tc.reason {
			t.Errorf("%s: %q", name, brokercore.DenialReason(err))
		}
	}
	if _, err := p.resolveScope(ctx, good, "vault", peer, nil, false); brokercore.DenialReason(err) != agenttoken.ReasonMalformed {
		t.Errorf("hint: %v", err)
	}
}
