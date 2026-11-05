package ratelimit

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
)

// Keyer extracts a stable key from a request; returning "" makes the middleware skip the check.
type Keyer func(*http.Request) string

// IPKey wraps a clientIP function into a Keyer; the server package owns the trusted-proxy policy.
func IPKey(clientIP func(*http.Request) string) Keyer {
	return func(r *http.Request) string {
		return "ip:" + clientIP(r)
	}
}

// HashToken returns a base16 SHA-256 prefix of s. Used for token
// keys so raw secrets never sit in the limiter's memory or logs.
func HashToken(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:8])
}

// IPTokenKey combines clientIP with a hashed token from tokenFromRequest; an empty token returns "" so the check is skipped.
func IPTokenKey(clientIP func(*http.Request) string, tokenFromRequest func(*http.Request) string) Keyer {
	return func(r *http.Request) string {
		tok := tokenFromRequest(r)
		if tok == "" {
			return ""
		}
		return "ipt:" + clientIP(r) + ":" + HashToken(tok)
	}
}

// ActorKey keys on a caller-provided actor identifier read from the request context.
func ActorKey(actorFromRequest func(*http.Request) string) Keyer {
	return func(r *http.Request) string {
		id := actorFromRequest(r)
		if id == "" {
			return ""
		}
		return "actor:" + id
	}
}
