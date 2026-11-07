package runnerid

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"time"
)

// GoogleIssuer is the issuer of Google ID tokens.
const GoogleIssuer = "https://accounts.google.com"

// googleMaxLifetime is the furthest ahead a Google token may expire.
const googleMaxLifetime = time.Hour

// GoogleIdentity is a verified Google ID token: the service account's unique ID (the token's sub), its email when the token has one, and the expiry.
type GoogleIdentity struct {
	UniqueID, Email string
	Expires         time.Time
}

// GoogleVerifier checks Google ID tokens against the issuer's JWKS, cached with rotation.
type GoogleVerifier struct {
	JWKSURL  string
	Issuer   string
	Audience string
	Client   *http.Client
	Now      func() time.Time

	cache jwks
}

type googleClaims struct {
	Issuer        string          `json:"iss"`
	Audience      json.RawMessage `json:"aud"`
	Expires       int64           `json:"exp"`
	Issued        int64           `json:"iat"`
	NotBefor      int64           `json:"nbf"`
	Subject       string          `json:"sub"`
	Email         string          `json:"email"`
	EmailVerified bool            `json:"email_verified"`
}

func (v *GoogleVerifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

// Verify returns the service account unique ID (sub) of a valid token, and its email when the token has one.
func (v *GoogleVerifier) Verify(ctx context.Context, token string) (GoogleIdentity, error) {
	if v.Audience == "" || v.Issuer == "" {
		return GoogleIdentity{}, refuse("oidc_malformed", "")
	}
	payload, kid, err := openToken(ctx, token, []string{"RS256"}, &v.cache, v.JWKSURL, v.Client, v.now)
	if err != nil {
		return GoogleIdentity{}, err
	}
	var c googleClaims
	if json.Unmarshal(payload, &c) != nil {
		return GoogleIdentity{}, refuse("oidc_malformed", kid)
	}
	now := v.now()
	expires := time.Unix(c.Expires, 0)
	switch {
	case c.Issuer != v.Issuer:
		return GoogleIdentity{}, refuse("oidc_issuer", kid)
	case !audienceIs(c.Audience, v.Audience):
		return GoogleIdentity{}, refuse("oidc_audience", kid)
	case c.Expires <= 0 || !now.Before(expires):
		return GoogleIdentity{}, refuse("oidc_expired", kid)
	case expires.Sub(now) > googleMaxLifetime+clockSkew:
		return GoogleIdentity{}, refuse("oidc_lifetime", kid)
	case c.Issued > 0 && time.Unix(c.Issued, 0).After(now.Add(clockSkew)),
		c.NotBefor > 0 && time.Unix(c.NotBefor, 0).After(now.Add(clockSkew)):
		return GoogleIdentity{}, refuse("oidc_not_yet_valid", kid)
	case !googleSubject.MatchString(c.Subject):
		return GoogleIdentity{}, refuse("oidc_subject_missing", kid)
	case c.Email != "" && (len(c.Email) > 254 || !plainSubject(c.Email)):
		return GoogleIdentity{}, refuse("oidc_email_malformed", kid)
	case c.Email != "" && !c.EmailVerified:
		return GoogleIdentity{}, refuse("oidc_email_unverified", kid)
	}
	return GoogleIdentity{UniqueID: c.Subject, Email: c.Email, Expires: expires}, nil
}

var googleSubject = regexp.MustCompile(`^[0-9]{10,25}$`)
