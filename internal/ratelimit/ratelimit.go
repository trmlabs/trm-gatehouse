// Package ratelimit is Agent Vault's tiered rate limiter, keyed per tier on the defended principal, with one Registry owning all state.
package ratelimit

import (
	"errors"
	"fmt"
	"time"
)

// Tier identifies a rate-limiting bucket. Each tier carries its own
// Config and covers a distinct attack surface.
type Tier int

const (
	// TierAuth covers unauthenticated endpoints and proxy auth failures; sliding window, the caller picks the keyer (login uses IP and email).
	// On the MITM path only auth failures are recorded; successes skip this tier.
	TierAuth Tier = iota

	// TierProxy is the /proxy and MITM limit keyed on (actor, vault): token bucket plus a per-scope concurrency semaphore.
	TierProxy

	// TierAuthed is the catch-all for authenticated endpoints: token bucket keyed on actor, sized for the heaviest workload.
	TierAuthed

	// TierGlobal is the server-wide backstop: Rate/Burst drive the RPS bucket, Concurrency the in-flight cap.
	TierGlobal

	// TierVerifyFailure counts bad verification and reset codes per email, not a rate limit; the cap invalidates the code.
	TierVerifyFailure

	tierCount
)

// tierNames maps each stable wire name (also the env-var suffix) to its Tier; String and TierByName use it.
var tierNames = [tierCount]string{
	TierAuth:          "AUTH",
	TierProxy:         "PROXY",
	TierAuthed:        "AUTHED",
	TierGlobal:        "GLOBAL",
	TierVerifyFailure: "VERIFY_FAIL",
}

// String returns the stable env-suffix form of a Tier, used for
// AGENT_VAULT_RATELIMIT_<TIER>_<KNOB> variable names.
func (t Tier) String() string {
	if t < 0 || int(t) >= len(tierNames) {
		return fmt.Sprintf("TIER_%d", int(t))
	}
	return tierNames[t]
}

// TierByName returns the Tier for name, or (0, false); case-sensitive, so upper-case user input first.
func TierByName(name string) (Tier, bool) {
	for i, n := range tierNames {
		if n == name {
			return Tier(i), true
		}
	}
	return 0, false
}

// AllTiers returns valid Tier values in declaration order; do not assume slice index equals Tier value.
func AllTiers() []Tier {
	out := make([]Tier, 0, tierCount)
	for i := 0; i < int(tierCount); i++ {
		out = append(out, Tier(i))
	}
	return out
}

// Algorithm selects the backing implementation for a tier.
type Algorithm int

const (
	// AlgSliding is the sliding-window limiter: at most N events within
	// a rolling Window. Best for strict attempt caps (login floods).
	AlgSliding Algorithm = iota

	// AlgTokenBucket is the smooth token-bucket: Rate refill per second
	// with Burst as bucket depth. Best for sustained traffic (proxy).
	AlgTokenBucket

	// AlgSemaphore is a counting semaphore: at most Concurrency
	// in-flight acquirers. Used alongside another algorithm.
	AlgSemaphore

	// AlgFailureCounter counts failures (not rate): increments on
	// recordFailure, resets on reset. Used for verify-code invalidation.
	AlgFailureCounter
)

// Decision is the outcome of Allow/Acquire; a denial carries RetryAfter and Reason for the 429.
type Decision struct {
	Allow      bool
	RetryAfter time.Duration
	Remaining  int
	Limit      int
	Reason     string // "rate", "concurrency", "global", or ""
}

// Deny builds a refusal decision.
func Deny(reason string, retryAfter time.Duration, limit int) Decision {
	return Decision{Allow: false, RetryAfter: retryAfter, Limit: limit, Reason: reason}
}

// Allow builds an allowance decision.
func AllowOK(remaining, limit int) Decision {
	return Decision{Allow: true, Remaining: remaining, Limit: limit}
}

// ErrLocked is returned by setting mutation when
// AGENT_VAULT_RATELIMIT_LOCK pins the config.
var ErrLocked = errors.New("rate-limit config is pinned by operator env var")
