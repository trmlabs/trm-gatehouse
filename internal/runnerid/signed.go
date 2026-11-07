package runnerid

import (
	"bytes"
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

// SignedConfig is one platform's signed-token rules, read from its harness profile: nothing here is specific to a vendor.
type SignedConfig struct {
	Issuer string
	// JWKSURL is where the issuer publishes its keys; with Discovery it is "" and the URL comes from the issuer's discovery document.
	JWKSURL   string
	Discovery bool
	// Audiences: a token must name at least one. Algorithms: RS256 and ES256 only.
	Audiences  []string
	Algorithms []string
	// MaxLifetime bounds exp minus iat, and how far ahead of now a token may expire.
	MaxLifetime time.Duration
	// ClockSkew forgives a clock that runs ahead for iat, nbf and the forward lifetime bound, never for expiry itself.
	ClockSkew time.Duration
	// SubjectClaim names the identity; GroupsClaim, when set, the groups.
	SubjectClaim, GroupsClaim string
	// RequiredClaims must each be a string claim equal to the value given, or the token is refused.
	RequiredClaims map[string]string
	// KeyMaxAge and RefreshBackoff tune the key cache; zero keeps an hour and 30 seconds.
	KeyMaxAge, RefreshBackoff time.Duration
}

// SignedIdentity is a verified token's subject and groups, read from the configured claims.
type SignedIdentity struct {
	Subject string
	Groups  []string
	Expires time.Time
}

// SignedVerifier checks the signed tokens of one platform against its issuer's keys, cached with bounded refresh. It holds no per-token state.
type SignedVerifier struct {
	Config SignedConfig
	Client *http.Client
	Now    func() time.Time

	cache jwks
}

// NewSignedVerifier prepares the key cache from the config. A nil client gets a default with no redirects.
func NewSignedVerifier(cfg SignedConfig, client *http.Client, now func() time.Time) *SignedVerifier {
	v := &SignedVerifier{Config: cfg, Client: client, Now: now}
	v.cache.maxAge, v.cache.backoff = cfg.KeyMaxAge, cfg.RefreshBackoff
	if cfg.Discovery {
		v.cache.fetch = func(ctx context.Context) (map[string]crypto.PublicKey, error) {
			keys, err := fetchDiscovered(ctx, cfg.Issuer, client)
			return keys, wrapIssuer(cfg.Issuer, err)
		}
	} else {
		v.cache.fetch = func(ctx context.Context) (map[string]crypto.PublicKey, error) {
			keys, err := fetchKeys(ctx, cfg.JWKSURL, client)
			return keys, wrapIssuer(cfg.Issuer, err)
		}
	}
	return v
}

// wrapIssuer names the issuer in a fetch error so the warning says which one failed.
func wrapIssuer(issuer string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("issuer %s: %w", issuer, err)
}

func (v *SignedVerifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

// MaxTokenBytes bounds a token any verifier will read.
const MaxTokenBytes = 16384

// PeekIssuer reads a token's unverified iss claim, only to choose which platform's rules to check it against; it proves nothing.
func PeekIssuer(token string) (string, bool) {
	// The size check comes before the split so a huge dotted token allocates nothing.
	if len(token) > MaxTokenBytes {
		return "", false
	}
	parts := strings.SplitN(token, ".", 4)
	if len(parts) != 3 {
		return "", false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", false
	}
	var c struct {
		Issuer string `json:"iss"`
	}
	if json.Unmarshal(payload, &c) != nil || c.Issuer == "" {
		return "", false
	}
	return c.Issuer, true
}

// Verify checks signature, algorithm, issuer, audience, expiry, issued-at and lifetime, then reads the configured claims. Anything it cannot prove is a refusal: it never falls back to trusting the token.
func (v *SignedVerifier) Verify(ctx context.Context, token string) (SignedIdentity, error) {
	cfg := v.Config
	if len(token) == 0 || len(token) > MaxTokenBytes || strings.ContainsAny(token, " \t\r\n") || cfg.Issuer == "" || len(cfg.Audiences) == 0 || len(cfg.Algorithms) == 0 ||
		cfg.MaxLifetime <= 0 || cfg.SubjectClaim == "" {
		return SignedIdentity{}, refuse("oidc_malformed", "")
	}
	payload, kid, err := openToken(ctx, token, cfg.Algorithms, &v.cache, cfg.JWKSURL, v.Client, v.now)
	if err != nil {
		return SignedIdentity{}, err
	}
	var claims map[string]json.RawMessage
	if d := json.NewDecoder(bytes.NewReader(payload)); d.Decode(&claims) != nil || claims == nil {
		return SignedIdentity{}, refuse("oidc_malformed", kid)
	}
	var issuer string
	if json.Unmarshal(claims["iss"], &issuer) != nil || issuer != cfg.Issuer {
		return SignedIdentity{}, refuse("oidc_issuer", kid)
	}
	aud := claims["aud"]
	if !slices.ContainsFunc(cfg.Audiences, func(a string) bool { return audienceHas(aud, a) }) {
		return SignedIdentity{}, refuse("oidc_audience", kid)
	}
	// exp and iat are required: a token that does not say when it expires or was issued is not short-lived evidence.
	exp, okExp := numericDate(claims["exp"])
	iat, okIat := numericDate(claims["iat"])
	if !okExp || !okIat {
		return SignedIdentity{}, refuse("oidc_claim_missing", kid)
	}
	now := v.now()
	switch {
	case !now.Before(exp):
		return SignedIdentity{}, refuse("oidc_expired", kid)
	case exp.Sub(iat) > cfg.MaxLifetime || exp.Sub(now) > cfg.MaxLifetime+cfg.ClockSkew || exp.Before(iat):
		return SignedIdentity{}, refuse("oidc_lifetime", kid)
	case iat.After(now.Add(cfg.ClockSkew)):
		return SignedIdentity{}, refuse("oidc_not_yet_valid", kid)
	}
	if raw, present := claims["nbf"]; present {
		nbf, ok := numericDate(raw)
		if !ok || nbf.After(now.Add(cfg.ClockSkew)) {
			return SignedIdentity{}, refuse("oidc_not_yet_valid", kid)
		}
	}
	var subject string
	if json.Unmarshal(claims[cfg.SubjectClaim], &subject) != nil || subject == "" || !plainSubject(subject) {
		return SignedIdentity{}, refuse("oidc_claim_missing", kid)
	}
	for name, want := range cfg.RequiredClaims {
		var got string
		if json.Unmarshal(claims[name], &got) != nil || got != want {
			return SignedIdentity{}, refuse("oidc_claim_missing", kid)
		}
	}
	var groups []string
	if cfg.GroupsClaim != "" {
		if raw, present := claims[cfg.GroupsClaim]; present {
			var items []json.RawMessage
			var one string
			if json.Unmarshal(raw, &items) != nil {
				if json.Unmarshal(raw, &one) != nil {
					return SignedIdentity{}, refuse("oidc_claim_missing", kid)
				}
				items = []json.RawMessage{raw}
			}
			// A group that is not a plain string cannot match a catalog group, so it is dropped and the rest kept.
			dropped := 0
			for _, item := range items {
				var g string
				if json.Unmarshal(item, &g) != nil || g == "" || !plainSubject(g) {
					dropped++
					continue
				}
				groups = append(groups, g)
			}
			if dropped > 0 {
				slog.Warn("signed token: dropped malformed group values", "issuer", cfg.Issuer, "dropped", dropped, "kept", len(groups))
			}
		}
	}
	return SignedIdentity{Subject: subject, Groups: groups, Expires: exp}, nil
}

// numericDate reads a JWT NumericDate: a positive number of seconds, whole or fractional.
func numericDate(raw json.RawMessage) (time.Time, bool) {
	var n float64
	if json.Unmarshal(raw, &n) != nil || n <= 0 || n > 1e11 {
		return time.Time{}, false
	}
	return time.Unix(int64(n), 0), true
}

// fetchDiscovered reads the issuer's discovery document and then the key set it names. The document must name the same issuer and an https key URL.
func fetchDiscovered(ctx context.Context, issuer string, client *http.Client) (map[string]crypto.PublicKey, error) {
	client = noRedirects(client)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(issuer, "/")+"/.well-known/openid-configuration", nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("issuer discovery unavailable")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var doc struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if json.Unmarshal(body, &doc) != nil || doc.Issuer != issuer || !httpsURL(doc.JWKSURI) {
		return nil, errors.New("invalid issuer discovery document")
	}
	return fetchKeys(ctx, doc.JWKSURI, client)
}

// httpsURL accepts an https URL with a host, no userinfo and no fragment, as the catalog requires of a static key URL.
func httpsURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && raw != "" && len(raw) <= 512 && u.Scheme == "https" && u.Host != "" && u.User == nil && u.Fragment == ""
}
