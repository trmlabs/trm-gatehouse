package brokercore

import (
	"encoding/base64"
	"net/http"
	"strings"
)

// ParseProxyAuth extracts a session token and optional vault hint from a Proxy-Authorization header (Bearer or Basic).
// Vault names cannot contain a colon, so splitting userinfo on the first colon is unambiguous.
func ParseProxyAuth(r *http.Request) (token, vaultHint string, err error) {
	h := r.Header.Get("Proxy-Authorization")
	if h == "" {
		return "", "", ErrInvalidSession
	}

	scheme, rest, ok := strings.Cut(h, " ")
	if !ok || rest == "" {
		return "", "", ErrInvalidSession
	}
	rest = strings.TrimSpace(rest)

	switch strings.ToLower(scheme) {
	case "bearer":
		if rest == "" {
			return "", "", ErrInvalidSession
		}
		return rest, "", nil
	case "basic":
		decoded, derr := base64.StdEncoding.DecodeString(rest)
		if derr != nil {
			return "", "", ErrInvalidSession
		}
		userinfo := string(decoded)
		if userinfo == "" {
			return "", "", ErrInvalidSession
		}
		if idx := strings.Index(userinfo, ":"); idx >= 0 {
			tok := userinfo[:idx]
			hint := userinfo[idx+1:]
			if tok == "" {
				return "", "", ErrInvalidSession
			}
			return tok, hint, nil
		}
		return userinfo, "", nil
	default:
		return "", "", ErrInvalidSession
	}
}
