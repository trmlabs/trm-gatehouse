package runnerid

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"strings"
	"time"
)

// GumloopIssuer is the issuer of Gumloop's ID tokens.
const GumloopIssuer = "https://api.gumloop.com"

// gumloopMaxLifetime caps how far ahead a Gumloop token may expire; Gumloop issues 5-minute tokens and there is no jti, so lifetime is the replay window.
const gumloopMaxLifetime = time.Hour

// ReasonKeysUnavailable is a refusal made because Gumloop's signing keys could not be fetched, so the token's key may exist; the same token can succeed later.
const ReasonKeysUnavailable = "oidc_keys_unavailable"

// Refusal is a GumloopVerifier refusal: a fixed reason code, and the token's kid once it has been read.
type Refusal struct{ Reason, Kid string }

func (r *Refusal) Error() string { return "gumloop ID token refused: " + r.Reason }

// GumloopIdentity is a verified Gumloop ID token. OwnerID is "" when the token has none, and is always a user when set.
type GumloopIdentity struct {
	OrgID, OwnerID string
	Expires        time.Time
}

// GumloopVerifier checks Gumloop ID tokens against the issuer's JWKS, cached with rotation.
type GumloopVerifier struct {
	JWKSURL  string
	Issuer   string
	Audience string
	Client   *http.Client
	Now      func() time.Time

	cache jwks
}

type gumloopClaims struct {
	Issuer   string          `json:"iss"`
	Audience json.RawMessage `json:"aud"`
	Expires  int64           `json:"exp"`
	Issued   int64           `json:"iat"`
	NotBefor int64           `json:"nbf"`
	OrgID    string          `json:"gumloop_org_id"`
	OwnerID  string          `json:"gumloop_owner_id"`
	OwnerTyp string          `json:"gumloop_owner_type"`
}

func (v *GumloopVerifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

func refuse(reason, kid string) error { return &Refusal{Reason: reason, Kid: kid} }

// Verify checks signature, issuer, audience and lifetime, and returns the org and owner the token names; an owner that is not a user (a workspace, or no type) is refused. Which org may act as which Automation is the caller's decision.
func (v *GumloopVerifier) Verify(ctx context.Context, token string) (GumloopIdentity, error) {
	if len(token) == 0 || len(token) > 16384 || strings.ContainsAny(token, " \t\r\n") || v.Audience == "" || v.Issuer == "" {
		return GumloopIdentity{}, refuse("oidc_malformed", "")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return GumloopIdentity{}, refuse("oidc_malformed", "")
	}
	headerBytes, e1 := base64.RawURLEncoding.DecodeString(parts[0])
	payload, e2 := base64.RawURLEncoding.DecodeString(parts[1])
	signature, e3 := base64.RawURLEncoding.DecodeString(parts[2])
	if e1 != nil || e2 != nil || e3 != nil {
		return GumloopIdentity{}, refuse("oidc_malformed", "")
	}
	var header struct {
		Alg, Kid string
		Crit     []string
	}
	if json.Unmarshal(headerBytes, &header) != nil || header.Kid == "" || len(header.Crit) != 0 {
		return GumloopIdentity{}, refuse("oidc_malformed", "")
	}
	if header.Alg != "RS256" && header.Alg != "ES256" {
		return GumloopIdentity{}, refuse("oidc_algorithm", header.Kid)
	}
	key, settled := v.cache.lookup(ctx, header.Kid, v.JWKSURL, v.Client, v.now)
	switch {
	case key == nil && !settled:
		return GumloopIdentity{}, refuse(ReasonKeysUnavailable, header.Kid)
	case key == nil:
		return GumloopIdentity{}, refuse("oidc_key_unknown", header.Kid)
	}
	if !verifySignature(header.Alg, key, []byte(parts[0]+"."+parts[1]), signature) {
		return GumloopIdentity{}, refuse("oidc_signature", header.Kid)
	}
	var c gumloopClaims
	if json.Unmarshal(payload, &c) != nil {
		return GumloopIdentity{}, refuse("oidc_malformed", header.Kid)
	}
	now := v.now()
	expires := time.Unix(c.Expires, 0)
	switch {
	case c.Issuer != v.Issuer:
		return GumloopIdentity{}, refuse("oidc_issuer", header.Kid)
	case !audienceHas(c.Audience, v.Audience):
		return GumloopIdentity{}, refuse("oidc_audience", header.Kid)
	case c.Expires <= 0 || !now.Before(expires):
		return GumloopIdentity{}, refuse("oidc_expired", header.Kid)
	case expires.Sub(now) > gumloopMaxLifetime:
		return GumloopIdentity{}, refuse("oidc_lifetime", header.Kid)
	case c.Issued > 0 && time.Unix(c.Issued, 0).After(now.Add(clockSkew)),
		c.NotBefor > 0 && time.Unix(c.NotBefor, 0).After(now.Add(clockSkew)):
		return GumloopIdentity{}, refuse("oidc_not_yet_valid", header.Kid)
	case !plainSubject(c.OrgID) || c.OrgID == "" || !plainSubject(c.OwnerID):
		return GumloopIdentity{}, refuse("oidc_org_missing", header.Kid)
	case c.OwnerID != "" && c.OwnerTyp != "user":
		return GumloopIdentity{}, refuse("oidc_owner_type", header.Kid)
	}
	return GumloopIdentity{OrgID: c.OrgID, OwnerID: c.OwnerID, Expires: expires}, nil
}

// verifySignature accepts only the key type its algorithm names.
func verifySignature(alg string, key crypto.PublicKey, signed, signature []byte) bool {
	digest := sha256.Sum256(signed)
	switch k := key.(type) {
	case *rsa.PublicKey:
		return alg == "RS256" && rsa.VerifyPKCS1v15(k, crypto.SHA256, digest[:], signature) == nil
	case *ecdsa.PublicKey:
		if alg != "ES256" || len(signature) != 64 {
			return false
		}
		return ecdsa.Verify(k, digest[:], new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:]))
	}
	return false
}

// audienceHas reports whether a string or list audience includes want.
func audienceHas(raw json.RawMessage, want string) bool {
	var one string
	var many []string
	if json.Unmarshal(raw, &one) == nil {
		return one == want
	}
	return json.Unmarshal(raw, &many) == nil && contains(many, want)
}
