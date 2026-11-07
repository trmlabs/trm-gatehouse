// Package agenttoken verifies per-agent bearer tokens ("<agent-id>.<secret>") against SHA-256 hashes in the catalog's Automation blocks.
// The token is worth exactly the entries its one block lists, and the listener is reachable only over a private link.
package agenttoken

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/httpcatalog"
)

// Refusal reason codes reach only the audit row and log, never the caller.
const (
	ReasonMalformed = "token_malformed"
	ReasonUnknown   = "agent_unknown"
	ReasonMismatch  = "token_mismatch"
	ReasonExpired   = "token_expired"
)

const secretBytes = 32

const encodedSecret = 43

var secretPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// Session is a verified agent token: its Automation, the pool its runs land on, and its expiry, never zero.
type Session struct {
	Automation string
	Pool       string
	Expires    time.Time
	// Source is authorize.SourceGumloopOIDC, SourceGoogleOIDC or SourceSignedToken for an ID token, "" for a static token.
	Source string
	// Owner is the verified Gumloop owner id the token names, "" for a static token or a token with none.
	Owner string
}

type Verifier interface {
	Verify(ctx context.Context, token string) (Session, error)
}

// Static verifies tokens against the live catalog, read per call so a removed block is refused on the next request.
type Static struct {
	// Catalog is an httpcatalog.Catalog or a live *httpcatalog.Source.
	Catalog interface{ Current() httpcatalog.Catalog }
	// Now is the clock; nil is time.Now.
	Now func() time.Time
}

var _ Verifier = Static{}

// Split returns the claimed agent id and whether the token has the right shape; the id grants nothing.
func Split(token string) (id string, ok bool) {
	i := strings.LastIndexByte(token, '.')
	if i < 1 || !httpcatalog.ValidID(token[:i]) || !secretPattern.MatchString(token[i+1:]) {
		return "", false
	}
	return token[:i], true
}

// ClaimedAgent returns the claimed agent id, or "" for a token of the wrong shape.
func ClaimedAgent(token string) string {
	id, _ := Split(token)
	return id
}

// Verify admits a token whose block lists its hash and whose expiry has not passed. An unknown id costs the same hash as a wrong secret,
// and expiry is read only after the hash matches.
func (s Static) Verify(_ context.Context, token string) (Session, error) {
	id, ok := Split(token)
	if !ok {
		return Session{}, brokercore.Denied(ReasonMalformed)
	}
	a, pool, found := s.Catalog.Current().StaticAgent(id)
	if !found {
		// The same work as a known id: one hash, two comparisons.
		httpcatalog.Automation{}.MatchToken(token)
		return Session{}, brokercore.DeniedKey(ReasonUnknown, id)
	}
	if !a.MatchToken(token) {
		return Session{}, brokercore.DeniedKey(ReasonMismatch, id)
	}
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	if expired(a.TokenExpires(), now()) {
		return Session{}, brokercore.DeniedKey(ReasonExpired, id)
	}
	return Session{Automation: a.ID, Pool: pool, Expires: a.TokenExpires()}, nil
}

// expired refuses the zero time as well as a token at or past its expiry.
func expired(exp, now time.Time) bool {
	return exp.IsZero() || !now.Before(exp)
}

// Mint returns a new token (shown once, never stored) and its hash for the catalog block.
func Mint(agentID string) (token, hash string, err error) {
	if !httpcatalog.ValidID(agentID) {
		return "", "", errors.New("agent id must be 1 to 128 letters, digits, '.', '_' or '-', starting with a letter or digit")
	}
	b := make([]byte, secretBytes)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	secret := base64.RawURLEncoding.EncodeToString(b)
	if len(secret) != encodedSecret {
		return "", "", errors.New("unexpected secret length")
	}
	token = agentID + "." + secret
	return token, Hash(token), nil
}

// Hash is the catalog's tokenSHA256 value for a token.
func Hash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
