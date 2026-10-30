// Package authorize is the one place both protocol adapters decide who stands
// behind a request and whether that requester may use a catalog entry: the
// lesser of the pool's tier ceiling and the verified person's entitlements.
package authorize

import (
	"context"
	"errors"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
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
	// TokenAgent is the Automation a verified static agent token names, the
	// one identity here that no Pod stands behind; empty for every other.
	TokenAgent string
	// PodRef and NotAfter locate the Pod and its deadline for a parent registering a subagent; zero for a non-pool-Pod identity.
	PodRef   brokercore.PodRef
	NotAfter time.Time
	// TokenSource is how that identity was proven, for the audit row; empty is a static token.
	TokenSource string
	// TokenOwner is the verified Gumloop owner id, recorded as the run's person since no Pod or run token names one.
	TokenOwner string
}

// SourceStaticToken is the audit row's Source for an Automation admitted by
// its static token, where a Cursor run's would be AUTOMATIONS.
const SourceStaticToken = "STATIC_TOKEN"

// SourceGumloopOIDC is the audit row's Source for an Automation admitted by a Gumloop ID token.
const SourceGumloopOIDC = "GUMLOOP_OIDC"

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
	// AutomationName and AutomationOwner (the owning team) are the
	// catalog's, for a listed Automation on a cursor-automation pool, and
	// RunPerson is the person the verified run token names, or "" when it
	// names none. Only the audit row reads them.
	AutomationName  string
	AutomationOwner string
	RunPerson       string
	// Run and ParentRun are read only by the audit row; ParentRun is the Automation run that registered a subagent.
	Run       string
	ParentRun string
	// grant is the catalog's block for a listed Automation, which decides
	// MayWrite. A pointer, so a Requester stays comparable.
	grant *httpcatalog.Automation
	// owner and team are the run token's sub and team_id, which registered subagents must share.
	owner, team string
}

// MayWrite reports whether the requester gets the pool's write grant on a git
// or github-api entry: a push, or a GitHub operation that writes. Anyone but
// an Automation does, since the pool's own prefixes and operations are what
// limit a person or a workload. So does an Automation whose block has no write
// key. One whose block has it does only on the entries it names, so an empty
// list fetches and reads only.
func (r Requester) MayWrite(entry string) bool {
	if r.Kind != "automation" {
		return true
	}
	return r.grant != nil && r.grant.Writes(entry)
}

// Settings are the plain settings the catalog lists for the requester's
// Automation, nil for anyone else: a person, a workload, or a run on a pool
// that does not decide per Automation. The map is the catalog's; it is never
// changed.
func (r Requester) Settings() map[string]string {
	if r.Kind != "automation" || r.grant == nil {
		return nil
	}
	return r.grant.Settings
}

// Audited is the verified identity an audit row names as the requester: the
// person, the agent, or the person an Automation's run token names, if any.
func (r Requester) Audited() string {
	switch r.Kind {
	case "person", "agent":
		return r.Subject
	case "automation":
		return r.RunPerson
	}
	return ""
}

// BranchSegment is the branch segment a {requester} push prefix names for
// this requester (httpcatalog.RequesterSegment): a person's email, or an
// Automation's id; "" for anyone else, who then gets no branch there.
func (r Requester) BranchSegment() string { return httpcatalog.RequesterSegment(r.Kind, r.Subject) }

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
// A run an Automation started is refused there too (automation_on_person_pool)
// unless the pool sets AutomationRunsAsPerson: served as its person, it would
// get every entry the pool grants instead of the Automation's own list.
//
// A cursor-automation pool decides for the Automation that started each run,
// so every request on it must come from one the catalog lists, T0 included: a
// run any other way, such as a person's from the web or Slack
// (not_automation), or by an Automation the catalog does not list
// (automation_unlisted), is refused unless a listed Automation's run registered it as a subagent.
func Resolve(ctx context.Context, pool httpcatalog.Pool, session string, claims Claims, v Verifier, b Binder) (Requester, string) {
	pod, claimedRun := claims.Pod, claims.ClaimedRun
	who := Requester{Kind: "none"}
	if claims.TokenAgent != "" {
		return resolveTokenAgent(pool, session, claims)
	}
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
		who.TokenSHA256, who.Source, who.Automation, who.Run = s.TokenSHA256, s.Source, s.Automation, s.Run
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
					if sub, ok := b.(*Subagents); ok {
						return sub.resolve(ctx, pool, s, pod, who)
					}
					return who, "not_automation"
				}
				a, ok := pool.Automation(s.Automation)
				// A block with a token hash is an agent that proves itself
				// by that token alone; a run token naming its id is refused,
				// so a vendor's ids and the catalog's agent ids never alias.
				if !ok || a.HasOwnIdentity() {
					return who, "automation_unlisted"
				}
				who.Kind, who.Subject, who.AutomationName, who.AutomationOwner = "automation", a.ID, a.Name, a.Owner
				who.grant, who.owner, who.team = &a, s.Owner, s.Team
				if s.Kind == runnerid.KindPerson {
					who.RunPerson = s.Subject
				}
				return who, ""
			}
			// Either sign of an Automation counts, so a token carrying only
			// one of them is not served as a person by default. A new
			// automated source that sets neither would still be served as
			// its person.
			if (s.Source == runnerid.SourceAutomations || s.Automation != "") && !pool.AutomationRunsAsPerson {
				return who, "automation_on_person_pool"
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

// resolveTokenAgent decides for an Automation admitted by its static token. It
// is the Automation the catalog lists, with the block's own entries, and no
// person: nothing a client sends can add one. The pool must have a
// static-token harness and the block a token hash; either missing refuses
// (automation_unlisted), as does a run session on the same connection
// (session_unexpected), since a token agent has no runner session.
func resolveTokenAgent(pool httpcatalog.Pool, session string, claims Claims) (Requester, string) {
	who := Requester{Kind: "none"}
	if claims.AttestedRequester != "" {
		return who, "requester_unexpected"
	}
	if session != "" {
		return who, "session_unexpected"
	}
	if _, ok := pool.StaticToken(); !ok {
		return who, "automation_unlisted"
	}
	a, ok := pool.Automation(claims.TokenAgent)
	if !ok || !a.HasOwnIdentity() {
		return who, "automation_unlisted"
	}
	who.Kind, who.Subject, who.AutomationName, who.AutomationOwner = "automation", a.ID, a.Name, a.Owner
	who.Source, who.Automation = SourceStaticToken, a.ID
	if claims.TokenSource == SourceGumloopOIDC {
		who.Source, who.RunPerson = SourceGumloopOIDC, claims.TokenOwner
	}
	who.grant = &a
	return who, ""
}

// Attribute names the run behind a request for a refusal that comes before any
// entry is authorized (an unlisted host, path or method), so its audit row
// carries the same Source, Automation, AutomationName and AutomationOwner an
// authorized row would: the run token's own source and Automation id whenever
// a Cursor run's token verifies, listed or not, and the catalog's name and
// owner when the pool lists that Automation. Nothing else is decided here, and
// a token that does not verify, or no token, names nothing.
func Attribute(ctx context.Context, pool httpcatalog.Pool, session string, claims Claims, v Verifier) Requester {
	if claims.TokenAgent != "" {
		who, _ := resolveTokenAgent(pool, "", Claims{TokenAgent: claims.TokenAgent, TokenSource: claims.TokenSource})
		return Requester{Source: who.Source, Automation: who.Automation, AutomationName: who.AutomationName, AutomationOwner: who.AutomationOwner}
	}
	cv, ok := v.(CursorVerifier)
	if !ok || session == "" || pool.Profile().RequesterKind() != httpcatalog.RequesterCursorOIDC {
		return Requester{}
	}
	s, err := cv.VerifyCursor(ctx, session)
	if err != nil {
		return Requester{}
	}
	who := Requester{Source: s.Source, Automation: s.Automation}
	if a, ok := pool.Automation(s.Automation); ok && !a.HasOwnIdentity() && s.Source == runnerid.SourceAutomations {
		who.AutomationName, who.AutomationOwner = a.Name, a.Owner
	}
	return who
}

// Decide applies the entitlement decision for one entry. On a
// cursor-automation pool the requester is granted the entry only when the
// catalog lists it for the run's Automation; entitlement.Decide refuses
// anything else there (automation_not_granted), at every tier.
func Decide(ctx context.Context, cache *entitlement.Cache, pool httpcatalog.Pool, entry httpcatalog.Entry, who Requester) entitlement.Decision {
	requester := entitlement.Requester{Kind: who.Kind, Subject: who.Subject}
	if a, ok := pool.Automation(who.Subject); ok && who.Kind == "automation" {
		requester.Granted = a.Uses(entry.Name)
	}
	return entitlement.Decide(ctx, cache, entitlement.Pool{Identity: pool.Identity, Ceiling: pool.Ceiling, Entitlements: pool.Entitlements},
		entitlement.Entry{Tier: entry.Tier, Requires: entry.Requires}, requester)
}
