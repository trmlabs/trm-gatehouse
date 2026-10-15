// Package entitlement decides whether an agent's request may use a catalog
// entry: the lesser of the pool's tier ceiling and, for human sessions, the
// verified person's live group membership. Every lookup error refuses.
package entitlement

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// maxTrackedPeople bounds the answer cache and lookup budgets, which start
// over when exceeded. It is sized for every person in a large organization
// times a few group sets; an entry is a few hundred bytes. A budget is a
// person's, or an Automation's for the checks on its owner's account.
const maxTrackedPeople = 200000

// MaxCacheTTL bounds how long a person's groups are trusted. Offboarding takes
// effect within it, because the runner's session tokens cannot be revoked.
const MaxCacheTTL = 5 * time.Minute

// Person is one directory user and the subset of asked groups it belongs to.
type Person struct {
	ObjectID   string
	Enabled    bool
	MemberOf   []string // only groups that were asked about
	Department string   // the directory's department, for the audit trail only; never decides
}

// Source looks a person up by SSO subject and checks membership of groups.
type Source interface {
	Lookup(ctx context.Context, subject string, groups []string) (Person, error)
}

type cached struct {
	person  Person
	fetched time.Time
}

// ErrLookupLimited refuses a directory lookup over the per-person budget.
var ErrLookupLimited = errors.New("entitlement lookups over budget")

const (
	// DefaultLookupsPerMinute is each person's directory budget. A worker
	// looping on a T2 entry asks once per request; past the budget it is
	// refused before the directory is asked, so it cannot get the tenant
	// throttled and fail every decision in the fleet.
	DefaultLookupsPerMinute = 60
	// DefaultRecentAnswer is how old an answer a fresh lookup over budget
	// still accepts instead of refusing.
	DefaultRecentAnswer = 5 * time.Second
	lookupTimeout       = 10 * time.Second
)

// flight is one directory lookup that concurrent askers share.
type flight struct {
	done   chan struct{}
	person Person
	err    error
}

// Cache wraps a Source with a short per-person, per-group-set cache. Lookups
// of one person and group set in flight together share one directory call,
// and each person has a directory budget.
type Cache struct {
	Source           Source
	TTL              time.Duration
	Now              func() time.Time
	LookupsPerMinute int           // per budget (a person, or an Automation); default DefaultLookupsPerMinute
	RecentAnswer     time.Duration // default DefaultRecentAnswer

	mu      sync.Mutex
	entries map[string]cached
	flights map[string]*flight
	spent   map[string][]time.Time // per person: directory calls in the last minute
	purges  uint64                 // bumped by every Purge, so an older lookup cannot refill the cache
}

func (c *Cache) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// Lookup returns the person and how old the answer is. Errors are never cached.
func (c *Cache) Lookup(ctx context.Context, subject string, groups []string) (Person, time.Duration, error) {
	return c.lookup(ctx, subject, subject, groups, false)
}

// Fresh asks the source now, ignoring any cached answer, and caches the result.
// It joins a lookup of the same question already in flight, and over the
// person's budget it accepts an answer at most RecentAnswer old or refuses.
func (c *Cache) Fresh(ctx context.Context, subject string, groups []string) (Person, time.Duration, error) {
	return c.lookup(ctx, subject, subject, groups, true)
}

// Purge forgets every cached answer about subject, so its next lookup of any
// group set asks the source. A lookup already in flight neither refills the
// cache nor serves anyone who asks after the purge.
func (c *Cache) Purge(subject string) {
	if c == nil {
		return
	}
	prefix := subject + "\x00"
	c.mu.Lock()
	defer c.mu.Unlock()
	c.purges++
	for key := range c.entries {
		if strings.HasPrefix(key, prefix) {
			delete(c.entries, key)
		}
	}
	for key := range c.flights {
		if strings.HasPrefix(key, prefix) {
			delete(c.flights, key)
		}
	}
}

// spend records one directory call against budget if it allows. The caller
// holds c.mu.
func (c *Cache) spend(budget string, now time.Time) bool {
	limit := c.LookupsPerMinute
	if limit <= 0 {
		limit = DefaultLookupsPerMinute
	}
	if c.spent == nil || len(c.spent) > maxTrackedPeople {
		c.spent = map[string][]time.Time{}
	}
	recent := c.spent[budget][:0]
	for _, t := range c.spent[budget] {
		if now.Sub(t) < time.Minute {
			recent = append(recent, t)
		}
	}
	if len(recent) >= limit {
		c.spent[budget] = recent
		return false
	}
	c.spent[budget] = append(recent, now)
	return true
}

// lookup asks about subject, charging any directory call to budget: the
// subject's own, or an Automation's for its owner's checks.
func (c *Cache) lookup(ctx context.Context, subject, budget string, groups []string, fresh bool) (Person, time.Duration, error) {
	if c == nil || c.Source == nil {
		return Person{}, 0, errors.New("no entitlement source configured")
	}
	ttl := c.TTL
	if ttl <= 0 || ttl > MaxCacheTTL {
		ttl = MaxCacheTTL
	}
	sorted := append([]string(nil), groups...)
	sort.Strings(sorted)
	key := subject + "\x00" + strings.Join(sorted, ",")
	now := c.now()
	c.mu.Lock()
	e, ok := c.entries[key]
	if ok && !fresh && now.Sub(e.fetched) < ttl {
		c.mu.Unlock()
		return e.person, now.Sub(e.fetched), nil
	}
	if f := c.flights[key]; f != nil {
		c.mu.Unlock()
		select {
		case <-f.done:
			return f.person, 0, f.err
		case <-ctx.Done():
			return Person{}, 0, ctx.Err()
		}
	}
	if !c.spend(budget, now) {
		recent := c.RecentAnswer
		if recent <= 0 {
			recent = DefaultRecentAnswer
		}
		c.mu.Unlock()
		if ok && now.Sub(e.fetched) < min(recent, ttl) {
			return e.person, now.Sub(e.fetched), nil
		}
		return Person{}, 0, ErrLookupLimited
	}
	f := &flight{done: make(chan struct{})}
	if c.flights == nil {
		c.flights = map[string]*flight{}
	}
	c.flights[key] = f
	generation := c.purges
	c.mu.Unlock()
	// The answer serves every asker, so one asker giving up does not end it.
	callCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), lookupTimeout)
	f.person, f.err = c.Source.Lookup(callCtx, subject, sorted)
	cancel()
	c.mu.Lock()
	if c.flights[key] == f {
		delete(c.flights, key)
	}
	if f.err == nil && c.purges == generation {
		if c.entries == nil || len(c.entries) > maxTrackedPeople {
			c.entries = map[string]cached{}
		}
		c.entries[key] = cached{person: f.person, fetched: now}
	}
	c.mu.Unlock()
	close(f.done)
	if f.err != nil {
		return Person{}, 0, f.err
	}
	return f.person, 0, nil
}

// Tier ranks catalog tiers. T0 is readable by everyone allowed on the pool.
func Tier(t string) (int, error) {
	switch t {
	case "", "T0":
		return 0, nil
	case "T1":
		return 1, nil
	case "T2":
		return 2, nil
	}
	return 0, fmt.Errorf("unknown tier %q", t)
}

// Pool is what the decision needs from a catalog pool.
type Pool struct {
	Identity     string // "none" (default), "claude-session", "cursor-session", "attested-person" or "workload"
	Ceiling      string // highest tier the pool may reach
	Entitlements []string
}

// Entry is what the decision needs from a catalog entry.
type Entry struct {
	Tier     string
	Requires []string
}

// Requester is the verified identity behind the request.
type Requester struct {
	Kind    string // "person", "agent", "workload", "automation" or "none"
	Subject string // the person's email; for an automation, its owner's
	// Budget is the lookup budget a directory call is charged to, when it
	// is not Subject's own: an Automation's, so its runs neither use up nor
	// share its owner's budget.
	Budget string
}

// Decision records why a request was allowed or refused, for the audit row.
type Decision struct {
	Allowed    bool
	Outcome    string // fixed code
	Tier       string
	Groups     []string // groups checked
	ObjectID   string
	Department string // the person's directory department when one was looked up
	CacheAge   time.Duration
}

type recheckKey struct{}

// WithRecheck marks a decision as the periodic recheck of an open session.
func WithRecheck(ctx context.Context) context.Context {
	return context.WithValue(ctx, recheckKey{}, true)
}

func isRecheck(ctx context.Context) bool { v, _ := ctx.Value(recheckKey{}).(bool); return v }

// LookupFor answers a membership question with the freshness Decide uses for
// an entry at tier: a T2 admission asks the directory now, within the
// person's budget; T1, T0 and rechecks may use the cache. A refusing answer
// that was fresh, or on a recheck, should be followed by Forget.
func LookupFor(ctx context.Context, cache *Cache, subject string, groups []string, tier string) (Person, error) {
	want, err := Tier(tier)
	if err != nil {
		return Person{}, err
	}
	lookup := cache.Lookup
	if want >= 2 && !isRecheck(ctx) {
		lookup = cache.Fresh
	}
	p, _, err := lookup(ctx, subject, groups)
	return p, err
}

// Forget purges subject after a refusing answer that was fresh (tier T2) or
// on a recheck, as Decide does, so no other session rides an older answer.
func Forget(ctx context.Context, cache *Cache, subject, tier string) {
	if want, err := Tier(tier); err == nil && (want >= 2 || isRecheck(ctx)) {
		cache.Purge(subject)
	}
}

// Decide applies the lesser of the pool ceiling and the requester's entitlements.
// A T2 admission always asks the directory now, within the requester's lookup
// budget (Budget, or the person's own); T1 admissions and rechecks may use the
// cache. A refusal on a recheck
// or a fresh answer forgets everything cached about the person, so none of
// their other sessions or entries rides a stale answer.
func Decide(ctx context.Context, cache *Cache, pool Pool, entry Entry, who Requester) Decision {
	tier := entry.Tier
	if tier == "" {
		tier = "T0"
	}
	d := Decision{Tier: tier, Groups: append([]string(nil), entry.Requires...)}
	// A pool below T0 reaches nothing; the catalog grants it no entry either.
	if pool.Ceiling == "external" {
		d.Outcome = "pool_external"
		return d
	}
	want, err1 := Tier(entry.Tier)
	ceiling, err2 := Tier(pool.Ceiling)
	if err1 != nil || err2 != nil {
		d.Outcome = "entitlement_config"
		return d
	}
	if want > ceiling {
		d.Outcome = "pool_ceiling"
		return d
	}
	// An Automation is checked on its owner's account at every tier, so an
	// offboarded owner's Automation stops entirely.
	if want == 0 && pool.Identity != "cursor-automation" {
		d.Allowed, d.Outcome = true, "t0"
		return d
	}
	switch pool.Identity {
	case "workload":
		if want >= 2 || !subset(entry.Requires, pool.Entitlements) {
			d.Outcome = "workload_not_entitled"
			return d
		}
		d.Allowed, d.Outcome = true, "workload_entitled"
		return d
	case "claude-session", "cursor-session", "attested-person":
		if who.Kind != "person" || who.Subject == "" {
			d.Outcome = "no_person"
			return d
		}
	case "cursor-automation":
		// An Automation is decided on its owner's account, so it never
		// reaches what its owner could not, and stops when that account
		// does. Which entries it may use, and who may run it, are the
		// caller's checks.
		if who.Kind != "automation" || who.Subject == "" {
			d.Outcome = "no_automation"
			return d
		}
	default:
		d.Outcome = "no_identity"
		return d
	}
	if want > 0 && len(entry.Requires) == 0 {
		d.Outcome = "entitlement_config"
		return d
	}
	fresh := want >= 2 && !isRecheck(ctx)
	budget := who.Budget
	if budget == "" {
		budget = who.Subject
	}
	person, age, err := cache.lookup(ctx, who.Subject, budget, entry.Requires, fresh)
	d.CacheAge = age
	switch {
	case errors.Is(err, ErrLookupLimited):
		d.Outcome = "entitlement_rate_limited"
		return d
	case err != nil:
		d.Outcome = "entitlement_unavailable"
	case !person.Enabled:
		d.ObjectID, d.Department, d.Outcome = person.ObjectID, person.Department, "account_disabled"
	case !subset(entry.Requires, person.MemberOf):
		d.ObjectID, d.Department, d.Outcome = person.ObjectID, person.Department, "not_entitled"
	case want == 0:
		d.ObjectID, d.Department, d.Allowed, d.Outcome = person.ObjectID, person.Department, true, "t0"
		return d
	default:
		d.ObjectID, d.Department, d.Allowed, d.Outcome = person.ObjectID, person.Department, true, "entitled"
		return d
	}
	// A recheck that refuses, or a fresh answer that refuses, forgets the
	// person: none of their other sessions or entries rides an older answer.
	if isRecheck(ctx) || (fresh && err == nil) {
		cache.Purge(who.Subject)
	}
	return d
}

func subset(want, have []string) bool {
	set := map[string]bool{}
	for _, h := range have {
		set[h] = true
	}
	for _, w := range want {
		if !set[w] {
			return false
		}
	}
	return true
}
