package runnerid

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"math/big"
	"net/http"
	"time"
)

// GumloopIssuer is the issuer of Gumloop's ID tokens.
const GumloopIssuer = "https://api.gumloop.com"

// gumloopMaxLifetime caps how far ahead a Gumloop token may expire; Gumloop issues 5-minute tokens and there is no jti, so lifetime is the replay window.
const gumloopMaxLifetime = time.Hour

// ReasonKeysUnavailable is a refusal made because the issuer's signing keys could not be fetched, so the token's key may exist; the same token can succeed later.
const ReasonKeysUnavailable = "oidc_keys_unavailable"

// Refusal is an ID token refusal (Gumloop or Google): a fixed reason code, and the token's kid once it has been read.
type Refusal struct{ Reason, Kid string }

func (r *Refusal) Error() string { return "ID token refused: " + r.Reason }

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
	if v.Audience == "" || v.Issuer == "" {
		return GumloopIdentity{}, refuse("oidc_malformed", "")
	}
	payload, kid, err := openToken(ctx, token, nil, &v.cache, v.JWKSURL, v.Client, v.now)
	if err != nil {
		return GumloopIdentity{}, err
	}
	var c gumloopClaims
	if json.Unmarshal(payload, &c) != nil {
		return GumloopIdentity{}, refuse("oidc_malformed", kid)
	}
	now := v.now()
	expires := time.Unix(c.Expires, 0)
	switch {
	case c.Issuer != v.Issuer:
		return GumloopIdentity{}, refuse("oidc_issuer", kid)
	case !audienceHas(c.Audience, v.Audience):
		return GumloopIdentity{}, refuse("oidc_audience", kid)
	case c.Expires <= 0 || !now.Before(expires):
		return GumloopIdentity{}, refuse("oidc_expired", kid)
	case expires.Sub(now) > gumloopMaxLifetime:
		return GumloopIdentity{}, refuse("oidc_lifetime", kid)
	case c.Issued > 0 && time.Unix(c.Issued, 0).After(now.Add(clockSkew)),
		c.NotBefor > 0 && time.Unix(c.NotBefor, 0).After(now.Add(clockSkew)):
		return GumloopIdentity{}, refuse("oidc_not_yet_valid", kid)
	case !plainSubject(c.OrgID) || c.OrgID == "" || !plainSubject(c.OwnerID):
		return GumloopIdentity{}, refuse("oidc_org_missing", kid)
	case c.OwnerID != "" && c.OwnerTyp != "user":
		return GumloopIdentity{}, refuse("oidc_owner_type", kid)
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
