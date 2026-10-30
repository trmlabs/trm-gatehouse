package authorize

import (
	"context"
	"encoding/json"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/httpcatalog"
	"github.com/Infisical/agent-vault/internal/runnerid"
)

// A subagent run is served as its parent's Automation only while the parent's live Pod, owner, team, pool and registration still match.

// SubagentStore keeps registrations shared across broker replicas; an empty parent in RegisterSubagent's answer means parent is at its limit.
type SubagentStore interface {
	RegisterSubagent(ctx context.Context, run, parent, record string, expires time.Time, limit int) (string, string, error)
	Subagent(ctx context.Context, run string) (string, string, error)
}

// Subagents is the Binder that adds the registry and live Pod check to the session pins.
type Subagents struct {
	Binder
	Registry SubagentStore
	Pods     brokercore.LivePods
	// Wait is how long a Pod waits for its run to be registered; zero is DefaultSubagentWait.
	Wait time.Duration
	// LiveTTL is how long a Pod read as running is trusted; zero is DefaultLiveTTL.
	LiveTTL time.Duration

	mu   sync.Mutex
	live map[liveKey]time.Time
}

type liveKey struct {
	pod brokercore.PodRef
	run string
}

// DefaultLiveTTL keeps a gone parent's subagents served for only seconds.
const DefaultLiveTTL = 5 * time.Second

// podRunning caches only a running answer; an error or a gone Pod is read again on the next request.
func (s *Subagents) podRunning(ctx context.Context, pod brokercore.PodRef, run string) (bool, error) {
	k, now := liveKey{pod, run}, time.Now()
	s.mu.Lock()
	until, hit := s.live[k]
	s.mu.Unlock()
	if hit && now.Before(until) {
		return true, nil
	}
	live, err := s.Pods.PodRunning(ctx, pod, run)
	if err != nil || !live {
		return live, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.live == nil || len(s.live) >= 4096 {
		s.live = map[liveKey]time.Time{}
	}
	ttl := s.LiveTTL
	if ttl <= 0 {
		ttl = DefaultLiveTTL
	}
	s.live[k] = now.Add(ttl)
	return true, nil
}

// DefaultSubagentWait covers the race where a subagent's clone arrives before its parent has registered it.
const DefaultSubagentWait = 2 * time.Minute

const subagentPoll = time.Second

// subagentRun is a Cursor run id (a bc- id) as a registration names it.
var subagentRun = regexp.MustCompile(`^bc-[A-Za-z0-9-]{1,128}$`)

// registration binds a subagent to the owner, team and Automation it must match.
type registration struct {
	Automation string            `json:"automation"`
	Owner      string            `json:"owner"`
	Team       string            `json:"team"`
	Pool       string            `json:"pool"`
	Pod        brokercore.PodRef `json:"pod"`
	Expires    time.Time         `json:"expires"`
}

// RegisterSubagent refuses with a Resolve-style code unless who is a listed Automation's own verified run, and returns the parent Pod's deadline.
func RegisterSubagent(ctx context.Context, pool httpcatalog.Pool, who Requester, claims Claims, run string, b Binder) (time.Time, string) {
	sub, ok := b.(*Subagents)
	switch {
	case !ok || sub.Registry == nil || sub.Pods == nil:
		return time.Time{}, "broker_misconfigured"
	case who.ParentRun != "":
		return time.Time{}, "subagent_nested"
	case who.Kind != "automation" || who.grant == nil || who.Source != runnerid.SourceAutomations || who.Run == "" || who.owner == "" || who.team == "":
		return time.Time{}, "not_automation"
	case who.grant.Subagents == 0:
		return time.Time{}, "subagents_not_granted"
	case !subagentRun.MatchString(run) || run == who.Run:
		return time.Time{}, "request_shape"
	case claims.PodRef.IsZero() || claims.PodRef.UID != claims.Pod || claims.NotAfter.IsZero():
		return time.Time{}, "session_unbindable"
	}
	record, err := json.Marshal(registration{Automation: who.grant.ID, Owner: who.owner, Team: who.team, Pool: pool.Name,
		Pod: claims.PodRef, Expires: claims.NotAfter})
	if err != nil {
		return time.Time{}, "subagent_unavailable"
	}
	parent, held, err := sub.Registry.RegisterSubagent(ctx, run, who.Run, string(record), claims.NotAfter, who.grant.Subagents)
	switch {
	case err != nil:
		return time.Time{}, "subagent_unavailable"
	case parent == "":
		return time.Time{}, "subagent_limit"
	case parent != who.Run:
		return time.Time{}, "subagent_taken"
	}
	var r registration
	if json.Unmarshal([]byte(held), &r) != nil {
		return time.Time{}, "subagent_unavailable"
	}
	return r.Expires, ""
}

// resolve returns the Automation whose run registered this run, or a refusal; who already carries the token's claims for the audit row.
func (s *Subagents) resolve(ctx context.Context, pool httpcatalog.Pool, run runnerid.Session, pod string, who Requester) (Requester, string) {
	if s.Registry == nil || s.Pods == nil {
		return who, "not_automation"
	}
	parent, record, err := s.lookup(ctx, run.Run, pod, pool.GrantsSubagents())
	if err != nil {
		return who, "subagent_unavailable"
	}
	if parent == "" {
		return who, "not_automation"
	}
	who.ParentRun = parent
	var r registration
	if json.Unmarshal([]byte(record), &r) != nil {
		return who, "subagent_unavailable"
	}
	if r.Owner == "" || r.Owner != run.Owner || r.Team == "" || r.Team != run.Team || r.Pool != pool.Name ||
		(run.Automation != "" && run.Automation != r.Automation) {
		return who, "subagent_mismatch"
	}
	a, ok := pool.Automation(r.Automation)
	if !ok || a.HasOwnIdentity() {
		return who, "automation_unlisted"
	}
	if a.Subagents == 0 {
		return who, "subagents_not_granted"
	}
	live, err := s.podRunning(ctx, r.Pod, parent)
	if err != nil {
		return who, "subagent_unavailable"
	}
	if !live || !time.Now().Before(r.Expires) {
		return who, "subagent_parent_gone"
	}
	// The Automation's grant, exactly: Decide and MayWrite read the block.
	who.Kind, who.Subject, who.Automation, who.AutomationName, who.AutomationOwner = "automation", a.ID, a.ID, a.Name, a.Owner
	who.grant = &a
	if run.Kind == runnerid.KindPerson {
		who.RunPerson = run.Subject
	}
	return who, ""
}

// lookup waits for a registration only while the Pod is within its first-request wait, since a clone can precede its parent's registration.
func (s *Subagents) lookup(ctx context.Context, run, pod string, wait bool) (string, string, error) {
	parent, record, err := s.Registry.Subagent(ctx, run)
	if err != nil || parent != "" || pod == "" || !wait {
		return parent, record, err
	}
	now := time.Now()
	// The first-request time is pinned like the run owner so every replica agrees on when the wait ends.
	first, err := s.BindRunnerSession(ctx, "cursor-first-request:"+pod, strconv.FormatInt(now.UnixMilli(), 10), now.Add(podOwnerPin))
	if err != nil {
		return "", "", err
	}
	ms, err := strconv.ParseInt(first, 10, 64)
	if err != nil {
		return "", "", err
	}
	limit := s.Wait
	if limit <= 0 {
		limit = DefaultSubagentWait
	}
	deadline := time.UnixMilli(ms).Add(limit)
	for delay := 100 * time.Millisecond; time.Now().Before(deadline); delay = min(2*delay, subagentPoll) {
		timer := time.NewTimer(min(delay, time.Until(deadline)))
		select {
		case <-ctx.Done():
			timer.Stop()
			return "", "", nil
		case <-timer.C:
		}
		if parent, record, err = s.Registry.Subagent(ctx, run); err != nil || parent != "" {
			return parent, record, err
		}
	}
	return "", "", nil
}
