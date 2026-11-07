package runnerid

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"time"
)

// openToken verifies a token's signature and returns its payload and kid; only, when set, lists the algorithms accepted.
func openToken(ctx context.Context, token string, only []string, cache *jwks, url string, client *http.Client, now func() time.Time) ([]byte, string, error) {
	if len(token) == 0 || len(token) > 16384 || strings.ContainsAny(token, " \t\r\n") {
		return nil, "", refuse("oidc_malformed", "")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, "", refuse("oidc_malformed", "")
	}
	headerBytes, e1 := base64.RawURLEncoding.DecodeString(parts[0])
	payload, e2 := base64.RawURLEncoding.DecodeString(parts[1])
	signature, e3 := base64.RawURLEncoding.DecodeString(parts[2])
	if e1 != nil || e2 != nil || e3 != nil {
		return nil, "", refuse("oidc_malformed", "")
	}
	var header struct {
		Alg, Kid string
		Crit     []string
	}
	if json.Unmarshal(headerBytes, &header) != nil || header.Kid == "" || len(header.Crit) != 0 {
		return nil, "", refuse("oidc_malformed", "")
	}
	if (header.Alg != "RS256" && header.Alg != "ES256") || (len(only) > 0 && !slices.Contains(only, header.Alg)) {
		return nil, "", refuse("oidc_algorithm", header.Kid)
	}
	key, settled := cache.lookup(ctx, header.Kid, url, client, now)
	switch {
	case key == nil && !settled:
		return nil, "", refuse(ReasonKeysUnavailable, header.Kid)
	case key == nil:
		return nil, "", refuse("oidc_key_unknown", header.Kid)
	}
	if !verifySignature(header.Alg, key, []byte(parts[0]+"."+parts[1]), signature) {
		return nil, "", refuse("oidc_signature", header.Kid)
	}
	return payload, header.Kid, nil
}
