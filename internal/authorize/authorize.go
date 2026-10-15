// Package authorize is the one place both protocol adapters decide who stands
// behind a request and whether that requester may use a catalog entry: the
// lesser of the pool's tier ceiling and the verified person's entitlements.
package authorize

import (
	"context"
	"errors"
	"time"

	"github.com/Infisical/agent-vault/internal/entitlement"
	"github.com/Infisical/agent-vault/internal/httpcatalog"
	"github.com/Infisical/agent-vault/internal/runnerid"
)

// Verifier checks a Claude runner session token.
type Verifier interface {
	Verify(context.Context, string) (runnerid.Session, error)
}

// CursorVerifier checks a Cursor run's identity token. A Verifier that also
// implements it (runnerid.Verifiers) serves cursor-session pools.
type CursorVerifier interface {
	VerifyCursor(context.Context, string) (runnerid.Session, error)
}

// AttestedPersons names the person behind a login a shared proxy attested:
// the Entra user principal name, or "" for no person. runnerid.ErrUnverifiable
// means no domain is configured.
type AttestedPersons interface {
	AttestedPerson(login string) (string, error)
}

// Claims is what the broker learned about the agent's Pod at admission.
type Claims struct {
	Pod        string // the verified Pod UID
	ClaimedRun string // the Cursor run the spawn hook recorded on the Pod
	// AttestedRequester is the login a shared proxy attested from the Pod's
	// requester annotation.
	AttestedRequester string
}

// podOwnerPin is how long a Pod stays pinned to the first Cursor run owner it
// presents. Pod UIDs never repeat, so the pin only has to outlive the Pod;
// a day is far past any worker's lifetime and costs one row.
const podOwnerPin = 24 * time.Hour

// Binder pins a runner session to the first Pod that presents it, across
// every broker replica, and returns the Pod it is pinned to. The pin lasts
// until the token expires.
type Binder interface {
	BindRunnerSession(ctx context.Context, tokenSHA256, pod string, expires time.Time) (string, error)
}

// Requester is who stands behind a request. TokenSHA256 identifies the runner
// session token without keeping it.
type Requester struct {
	Kind        string // person, agent, workload, automation or none
	Subject     string // the person's email, the agent, or the Automation's id
	TokenSHA256 string
	// Source and Automation are what a verified Cursor run token says about
	// how the run started, on any pool, for the audit row.
	Source     string
	Automation string
	// AutomationName and AutomationOwner are the catalog's, for a listed
	// Automation on a cursor-automation pool, and RunPerson is the verified
	// person whose run it is.
	AutomationName  string
	AutomationOwner string
	RunPerson       string
}

// Audited is the verified identity an audit row names as the requester: the
// person, the agent, or the person whose run started an Automation's request.
func (r Requester) Audited() string {
	switch r.Kind {
	case "person", "agent":
		return r.Subject
	case "automation":
		return r.RunPerson
	}
	return ""
}

// Resolve derives the requester for a pool from the session token the sidecar
// relayed (empty when none), as the pool's harness profile says. It returns a
// refusal code when a presented token is invalid, was issued for another
// runner pool, or arrives on a profile whose requester is not a session: a
// bad token is refused even for T0, never silently ignored. A session-jwt
// profile with no session has no person: T0 only.
//
// A session token is a bearer credential, so it is pinned to the first Pod
// that presents it: the same token from another Pod is refused
// (session_pod_mismatch), and without a binder or a Pod the session is
// refused (session_unbindable).
//
// A Cursor token is a bearer credential any process on a worker can mint for
// that worker's run, so it counts only on the Pod the spawn hook created for
// that run: its run must equal claimedRun, the run the controller recorded on
// the live Pod (session_run). And since runs on one Pod share its workspace, a
// cursor-session Pod is also pinned to the first run owner it presents: a run
// by anyone else on that Pod is refused (session_pod_owner).
//
// A cursor-oidc profile decides for the person behind each run, so every
// request on it must name one, T0 included: a request with no token
// (session_missing) or whose run names no person, such as a Cursor service
// account's or an owner outside the configured domains (no_person), is
// refused, never served as the pool. The refusal is that one request's: other
// Pods, and other requests on the same Pod, are decided on their own token.
//
// A cursor-automation pool decides for the Automation that started each run,
// so every request on it must come from one the catalog lists, T0 included: a
// run any other way, such as a person's from the web or Slack
// (not_automation), by an Automation the catalog does not list
// (automation_unlisted), or whose run names no person (automation_no_person),
// is refused. Whether that person may run it is Decide's check. On every
// Cursor pool the run's source and Automation are kept for the audit row,
// refused or not.
func Resolve(ctx context.Context, pool httpcatalog.Pool, session string, claims Claims, v Verifier, b Binder) (Requester, string) {
	pod, claimedRun := claims.Pod, claims.ClaimedRun
	who := Requester{Kind: "none"}
	requester := pool.Profile().RequesterKind()
	// An attested requester counts only on a profile that takes its person
	// from one; on any other, a proxy fault must not lend a person to a pool,
	// so it is refused rather than ignored.
	if claims.AttestedRequester != "" && requester != httpcatalog.RequesterPodAnnotation {
		return who, "requester_unexpected"
	}
	// Only a session sidecar relays a session. One arriving on any other
	// profile is a misconfigured or forged channel, never ignored.
	if session != "" && requester != httpcatalog.RequesterSessionJWT && requester != httpcatalog.RequesterCursorOIDC {
		return who, "session_unexpected"
	}
	switch requester {
	case "":
		// Pool authorization: a workload pool's fixed entitlements, or none.
		if pool.Identity == "workload" {
			who.Kind = "workload"
		}
	case httpcatalog.RequesterSessionJWT, httpcatalog.RequesterCursorOIDC:
		cursor := requester == httpcatalog.RequesterCursorOIDC
		if session == "" && cursor {
			return who, "session_missing"
		}
		if session == "" {
			return who, ""
		}
		var s runnerid.Session
		var err error
		if cv, ok := v.(CursorVerifier); cursor && ok {
			s, err = cv.VerifyCursor(ctx, session)
		} else if v != nil && !cursor {
			s, err = v.Verify(ctx, session)
		} else {
			return who, "session_unverifiable"
		}
		if errors.Is(err, runnerid.ErrUnverifiable) {
			return who, "session_unverifiable"
		}
		if err != nil {
			return who, "session_token"
		}
		who.TokenSHA256, who.Source, who.Automation = s.TokenSHA256, s.Source, s.Automation
		// A Cursor token is bound to the broker's teams and audience instead,
		// and to the run the controller started this Pod for.
		if !cursor && !s.InPool(pool.CCPoolID) {
			return who, "session_pool"
		}
		if cursor && (claimedRun == "" || s.Run != claimedRun) {
			return who, "session_run"
		}
		if b == nil || pod == "" {
			return who, "session_unbindable"
		}
		bound, err := b.BindRunnerSession(ctx, s.TokenSHA256, pod, s.Expires)
		if err != nil {
			return who, "session_unbindable"
		}
		if bound != pod {
			return who, "session_pod_mismatch"
		}
		if cursor {
			if s.Owner == "" {
				return who, "session_token"
			}
			owner, err := b.BindRunnerSession(ctx, "cursor-pod:"+pod, s.Owner, time.Now().Add(podOwnerPin))
			if err != nil {
				return who, "session_unbindable"
			}
			if owner != s.Owner {
				return who, "session_pod_owner"
			}
			if pool.Profile().Authorization.Mode == httpcatalog.AuthorizeAutomation {
				if s.Source != runnerid.SourceAutomations || s.Automation == "" {
					return who, "not_automation"
				}
				a, ok := pool.Automation(s.Automation)
				if !ok {
					return who, "automation_unlisted"
				}
				// TODO(probe): this assumes an Automation's run token names
				// the person who started it (sub user:, owner_email). If the
				// claims probe shows a service account instead, decide who is
				// accountable for such a run before serving it; until then it
				// is refused.
				if s.Kind != runnerid.KindPerson || s.Subject == "" {
					return who, "automation_no_person"
				}
				who.Kind, who.Subject, who.AutomationName, who.AutomationOwner, who.RunPerson = "automation", a.ID, a.Name, a.Owner, s.Subject
				return who, ""
			}
			if s.Kind != runnerid.KindPerson || s.Subject == "" {
				return who, "no_person"
			}
		}
		who.Kind, who.Subject = string(s.Kind), s.Subject
	case httpcatalog.RequesterPodAnnotation:
		// The proxy admits no Pod in such a namespace without a requester,
		// so a missing one is a fault, never a pool-level session.
		if claims.AttestedRequester == "" {
			return who, "requester_missing"
		}
		persons, ok := v.(AttestedPersons)
		if !ok {
			return who, "requester_unverifiable"
		}
		person, err := persons.AttestedPerson(claims.AttestedRequester)
		if err != nil {
			return who, "requester_unverifiable"
		}
		if person != "" {
			who.Kind, who.Subject = "person", person
		}
	default:
		// A requester kind this broker cannot verify. The catalog refuses
		// such a profile at load; this keeps the decision closed regardless.
		return who, "requester_unverifiable"
	}
	return who, ""
}

// Decide applies the entitlement decision for one entry. On a
// cursor-automation pool, at every tier, T0 included: the entry must be one
// the catalog lists for the run's Automation (automation_not_granted); the
// run's person must be the owner or in the Automation's runner group
// (automation_runner); and the entry is then decided on the owner's account,
// which must be enabled.
func Decide(ctx context.Context, cache *entitlement.Cache, pool httpcatalog.Pool, entry httpcatalog.Entry, who Requester) entitlement.Decision {
	requester := entitlement.Requester{Kind: who.Kind, Subject: who.Subject}
	if pool.Identity == httpcatalog.IdentityCursorAutomation {
		tier := entry.Tier
		if tier == "" {
			tier = "T0"
		}
		refused := entitlement.Decision{Tier: tier, Groups: append([]string(nil), entry.Requires...)}
		a, ok := pool.Automation(who.Subject)
		if who.Kind != "automation" || !ok || !a.Uses(entry.Name) {
			refused.Outcome = "automation_not_granted"
			return refused
		}
		if outcome := runnerAllowed(ctx, cache, a, who.RunPerson); outcome != "" {
			refused.Outcome = outcome
			return refused
		}
		requester.Subject = a.Owner
	}
	return entitlement.Decide(ctx, cache, entitlement.Pool{Identity: pool.Identity, Ceiling: pool.Ceiling, Entitlements: pool.Entitlements},
		entitlement.Entry{Tier: entry.Tier, Requires: entry.Requires}, requester)
}

// runnerAllowed checks that the person whose run it is may run the
// Automation: its owner, or an enabled member of its runner group. It returns
// a refusal code, or "".
func runnerAllowed(ctx context.Context, cache *entitlement.Cache, a httpcatalog.Automation, person string) string {
	switch {
	case person == "":
		return "automation_runner"
	case person == a.Owner:
		return ""
	case a.RunnerGroup == "":
		return "automation_runner"
	}
	p, _, err := cache.Lookup(ctx, person, []string{a.RunnerGroup})
	switch {
	case errors.Is(err, entitlement.ErrLookupLimited):
		return "entitlement_rate_limited"
	case err != nil:
		return "entitlement_unavailable"
	case !p.Enabled || len(p.MemberOf) != 1 || p.MemberOf[0] != a.RunnerGroup:
		return "automation_runner"
	}
	return ""
}
