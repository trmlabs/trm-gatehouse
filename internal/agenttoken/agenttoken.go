// Package agenttoken verifies a per-agent bearer token for a client that has
// no Kubernetes identity to prove: an agent running on another platform's
// machines, reaching the broker over a private link. The token is
// "<agent-id>.<secret>", the secret 256 random bits in base64url. The id names
// the agent's Automation block in the catalog; the block holds the SHA-256 of
// the token (one hash, or two while a token rotates) and an optional expiry.
// The broker never stores a token: mint prints it once, and the catalog keeps
// only its hash. Removing the block revokes the token at the next catalog
// reload.
//
// A bearer secret the client holds can be replayed by anything that can read
// it, so the token is worth exactly the entries its one block lists, and the
// listener that admits it is reachable only over a private link. Verification
// sits behind Verifier, the shape runnerid gives a platform's signed run
// token, so a token the platform signs can replace this one without touching
// how the verified agent is authorized.
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

// Refusal reason codes. They reach the broker's own audit row and log, never
// the caller, who is told only that the identity was refused.
const (
	ReasonMalformed = "token_malformed"
	ReasonUnknown   = "agent_unknown"
	ReasonMismatch  = "token_mismatch"
	ReasonExpired   = "token_expired"
)

// secretBytes is the secret's length: 256 bits.
const secretBytes = 32

// encodedSecret is the secret's length in base64url without padding.
const encodedSecret = 43

var secretPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// Session is a verified agent token: the Automation it names, the pool that
// Automation's runs land on, and when the token stops being accepted. Static
// never returns the zero time: it refuses a token whose block has no expiry.
type Session struct {
	Automation string
	Pool       string
	Expires    time.Time
	// Source is authorize.SourceGumloopOIDC for a Gumloop ID token, "" for a static token.
	Source string
	// Owner is the verified Gumloop owner id the token names, "" for a static token or a token with none.
	Owner string
}

// Verifier checks an agent's token.
type Verifier interface {
	Verify(ctx context.Context, token string) (Session, error)
}

// Static verifies tokens against the hashes in the live catalog. The catalog
// is read once per call, so a reloaded catalog applies to the next request:
// a removed block is refused on the next request of a tunnel already open.
type Static struct {
	// Catalog is an httpcatalog.Catalog or a live *httpcatalog.Source.
	Catalog interface{ Current() httpcatalog.Catalog }
	// Now is the clock; nil is time.Now.
	Now func() time.Time
}

var _ Verifier = Static{}

// Split returns the agent id a token claims and whether the token has the
// right shape. It decides nothing about the token: the id is whatever the
// caller wrote, so it keys pre-authentication rate limits and audit rows only
// after this check, and never grants anything.
func Split(token string) (id string, ok bool) {
	i := strings.LastIndexByte(token, '.')
	if i < 1 || !httpcatalog.ValidID(token[:i]) || !secretPattern.MatchString(token[i+1:]) {
		return "", false
	}
	return token[:i], true
}

// ClaimedAgent returns the agent id a token claims, or "" for a token of the
// wrong shape.
func ClaimedAgent(token string) string {
	id, _ := Split(token)
	return id
}

// Verify admits a token whose block lists its hash and whose expiry has not
// passed. The order is fixed so a refusal reveals nothing a caller without
// the secret could use: an unknown id and a wrong secret cost the same hash,
// and the expiry is read only after the hash matches.
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

// expired reports whether a token must be refused for its expiry. The zero
// time is refused, not read as never: the catalog already refuses a token
// block without a real expiry at load, and this keeps the token bounded if a
// block ever reaches the verifier another way.
func expired(exp, now time.Time) bool {
	return exp.IsZero() || !now.Before(exp)
}

// Mint makes a token for an agent id: 256 random bits after the id. It
// returns the token, shown once and never stored, and its hash for the
// catalog block.
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
