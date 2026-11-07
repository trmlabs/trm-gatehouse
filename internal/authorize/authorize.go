// Package authorize decides who stands behind a request and whether it may use a catalog entry: the lesser of the pool's tier ceiling and the person's entitlements.
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

// CursorVerifier checks a Cursor run's identity token.
type CursorVerifier interface {
	VerifyCursor(context.Context, string) (runnerid.Session, error)
}

// AttestedPersons returns the Entra UPN behind an attested login, or "" for no person; runnerid.ErrUnverifiable means no domain is configured.
type AttestedPersons interface {
	AttestedPerson(login string) (string, error)
}

// Claims is what the broker learned about the agent's Pod at admission.
type Claims struct {
	Pod        string // the verified Pod UID
	ClaimedRun string // the Cursor run the spawn hook recorded on the Pod
	// AttestedRequester is the login a shared proxy attested from the Pod's requester annotation.
	AttestedRequester string
	// TokenAgent is the Automation a verified static token names; no Pod stands behind it.
	TokenAgent string
	// PodRef and NotAfter locate the Pod and its deadline for a parent registering a subagent; zero for a non-pool-Pod identity.
	PodRef   brokercore.PodRef
	NotAfter time.Time
	// TokenSource is how that identity was proven, for the audit row; empty is a static token.
	TokenSource string
	// TokenOwner is the verified Gumloop owner id, recorded as the run's person since no Pod or run token names one.
	TokenOwner string
}

// SourceStaticToken is the audit Source for an Automation admitted by its static token.
const SourceStaticToken = "STATIC_TOKEN"

// SourceGumloopOIDC is the audit row's Source for an Automation admitted by a Gumloop ID token.
const SourceGumloopOIDC = "GUMLOOP_OIDC"

// SourceSignedToken is the audit row's Source for an Automation admitted by a signed-token harness's ID token.
const SourceSignedToken = "SIGNED_TOKEN"

// SourceGoogleOIDC is the audit row's Source for an Automation admitted by a Google ID token.
const SourceGoogleOIDC = "GOOGLE_OIDC"

// podOwnerPin is how long a Pod stays pinned to the first Cursor run owner it presents.
// Pod UIDs never repeat, so a day is far past any worker's lifetime.
const podOwnerPin = 24 * time.Hour

// Binder pins a runner session to the first Pod that presents it, across replicas, until the token expires.
type Binder interface {
	BindRunnerSession(ctx context.Context, tokenSHA256, pod string, expires time.Time) (string, error)
}

// PodSessions is the optional read a Binder offers: whether a Pod holds a live pin from a verified run token.
type PodSessions interface {
	PodHasSession(ctx context.Context, pod string) (bool, error)
}

// Decisions an audit row carries for a session_missing refusal, so the Pod's first connection racing its session is apart from a session that went missing mid-run.
const (
	// SessionStartup is no live run token on record for the Pod, usually its first connection racing its session; an expired pin reads the same.
	SessionStartup = "session_startup"
	SessionMidRun  = "session_mid_run"
)

// sessionGapTimeout bounds the lookup that labels a session_missing refusal.
const sessionGapTimeout = 250 * time.Millisecond

// sessionGap names a session_missing refusal for the audit row; empty when the Binder cannot tell.
func sessionGap(ctx context.Context, b Binder, pod string) string {
	ps, ok := b.(PodSessions)
	if !ok || pod == "" {
		return ""
	}
	// The value is diagnostic only: a slow store leaves it empty rather than hold the refusal, and a client hang-up does not cancel it.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), sessionGapTimeout)
	defer cancel()
	seen, err := ps.PodHasSession(ctx, pod)
	switch {
	case err != nil:
		return ""
	case seen:
		return SessionMidRun
	}
	return SessionStartup
}

// Requester is who stands behind a request.
type Requester struct {
	Kind string // person, agent, workload, automation or none
	// SessionGap is set with a session_missing refusal: SessionStartup or SessionMidRun, empty when unknown.
	SessionGap  string
	Subject     string // the person's email, the agent, or the Automation's id
	TokenSHA256 string
	// Source and Automation come from the verified Cursor run token, for the audit row.
	Source     string
	Automation string
	// AutomationName, AutomationOwner and RunPerson (the person the run token names) are read only by the audit row.
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

// MayWrite reports whether the requester gets the pool's write grant on a git or github-api entry.
// Anyone but an Automation does; an Automation does only on the entries its write key names, and an empty list means read only.
func (r Requester) MayWrite(entry string) bool {
	if r.Kind != "automation" {
		return true
	}
	return r.grant != nil && r.grant.Writes(entry)
}

// Settings are the plain settings the catalog lists for the requester's Automation, nil for anyone else.
func (r Requester) Settings() map[string]string {
	if r.Kind != "automation" || r.grant == nil {
		return nil
	}
	return r.grant.Settings
}

// Audited is the verified identity an audit row names as the requester.
func (r Requester) Audited() string {
	switch r.Kind {
	case "person", "agent":
		return r.Subject
	case "automation":
		return r.RunPerson
	}
	return ""
}

// BranchSegment is the {requester} push-prefix segment: a person's email or an Automation's id, else "".
func (r Requester) BranchSegment() string { return httpcatalog.RequesterSegment(r.Kind, r.Subject) }

// Resolve derives the requester for a pool from the relayed session token, returning a refusal code on failure.
// Session and Cursor tokens are bearers, pinned to the first Pod (and for Cursor, run and owner) that presents them.
func Resolve(ctx context.Context, pool httpcatalog.Pool, session string, claims Claims, v Verifier, b Binder) (Requester, string) {
	pod, claimedRun := claims.Pod, claims.ClaimedRun
	who := Requester{Kind: "none"}
	if claims.TokenAgent != "" {
		return resolveTokenAgent(pool, session, claims)
	}
	requester := pool.Profile().RequesterKind()
	// A proxy fault must not lend a person to a pool whose profile does not take one.
	if claims.AttestedRequester != "" && requester != httpcatalog.RequesterPodAnnotation {
		return who, "requester_unexpected"
	}
	// A session on any other profile is a misconfigured or forged channel.
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
			who.SessionGap = sessionGap(ctx, b, pod)
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
				// A block with a token hash is an agent that proves itself by that token alone;
				// a run token naming its id is refused, so vendor ids and catalog agent ids never alias.
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
			// Either sign of an Automation counts; a new automated source that sets neither would still be served as a person.
			if (s.Source == runnerid.SourceAutomations || s.Automation != "") && !pool.AutomationRunsAsPerson {
				return who, "automation_on_person_pool"
			}
			if s.Kind != runnerid.KindPerson || s.Subject == "" {
				return who, "no_person"
			}
		}
		who.Kind, who.Subject = string(s.Kind), s.Subject
	case httpcatalog.RequesterPodAnnotation:
		// The proxy admits no such Pod without a requester, so a missing one is a fault.
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
		// The catalog refuses such a profile at load; this keeps the decision closed regardless.
		return who, "requester_unverifiable"
	}
	return who, ""
}

// resolveTokenAgent decides for an Automation admitted by its static token, with no person. The pool needs a
// static-token harness and the block a token hash (else automation_unlisted); a run session is refused (session_unexpected).
func resolveTokenAgent(pool httpcatalog.Pool, session string, claims Claims) (Requester, string) {
	who := Requester{Kind: "none"}
	if claims.AttestedRequester != "" {
		return who, "requester_unexpected"
	}
	if session != "" {
		return who, "session_unexpected"
	}
	a, ok := pool.Automation(claims.TokenAgent)
	if !ok || !a.HasOwnIdentity() || !pool.AdmitsToken(a) {
		return who, "automation_unlisted"
	}
	who.Kind, who.Subject, who.AutomationName, who.AutomationOwner = "automation", a.ID, a.Name, a.Owner
	who.Source, who.Automation = SourceStaticToken, a.ID
	switch claims.TokenSource {
	case SourceGumloopOIDC:
		who.Source, who.RunPerson = SourceGumloopOIDC, claims.TokenOwner
	case SourceSignedToken:
		who.Source = SourceSignedToken
	case SourceGoogleOIDC:
		who.Source = SourceGoogleOIDC
	}
	who.grant = &a
	return who, ""
}

// Attribute names the run behind a refusal made before any entry is authorized, as an authorized row would.
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

// Decide applies the entitlement decision for one entry; on a cursor-automation pool only entries listed for the Automation are granted (automation_not_granted).
func Decide(ctx context.Context, cache *entitlement.Cache, pool httpcatalog.Pool, entry httpcatalog.Entry, who Requester) entitlement.Decision {
	requester := entitlement.Requester{Kind: who.Kind, Subject: who.Subject}
	if a, ok := pool.Automation(who.Subject); ok && who.Kind == "automation" {
		requester.Granted = a.Uses(entry.Name)
	}
	return entitlement.Decide(ctx, cache, entitlement.Pool{Identity: pool.Identity, Ceiling: pool.Ceiling, Entitlements: pool.Entitlements},
		entitlement.Entry{Tier: entry.Tier, Requires: entry.Requires}, requester)
}
