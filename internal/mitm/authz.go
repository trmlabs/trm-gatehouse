package mitm

import (
	"context"
	"strings"

	"github.com/Infisical/agent-vault/internal/auditchain"
	"github.com/Infisical/agent-vault/internal/authorize"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/httpcatalog"
)

// SessionHeader carries the runner's session token from the in-Pod sidecar; a worker cannot set it.
const SessionHeader = "Gatehouse-Session"

type sessionTokenKey struct{}

func withSessionToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, sessionTokenKey{}, token)
}

func sessionToken(ctx context.Context) string {
	token, _ := ctx.Value(sessionTokenKey{}).(string)
	return token
}

// authorize applies the authorization model to a matched entry and fills the audit event; it returns the requester and a refusal code, or "".
func (p *Proxy) authorize(ctx context.Context, scope *brokercore.ProxyScope, entry *httpcatalog.Entry, event *auditchain.Event) (authorize.Requester, string) {
	a := p.adapter
	pool, _ := a.Catalog.Current().Pool(scope.Pool) // undefined pools: no identity, ceiling T0
	who, refusal := p.requester(ctx, scope, pool, event)
	if refusal != "" {
		return who, refusal
	}
	d := authorize.Decide(ctx, a.Entitlements, pool, *entry, who)
	event.Tier, event.Decision, event.RequesterOID = d.Tier, d.Outcome, d.ObjectID
	event.RequesterDepartment = auditchain.DepartmentField(d.Department)
	event.Groups = strings.Join(d.Groups, ",")
	event.CacheAgeSec = int64(d.CacheAge.Seconds())
	if !d.Allowed {
		return who, d.Outcome
	}
	return who, ""
}

// requester resolves who stands behind a request and fills the audit event with the run token's claims and the admitted requester.
func (p *Proxy) requester(ctx context.Context, scope *brokercore.ProxyScope, pool httpcatalog.Pool, event *auditchain.Event) (authorize.Requester, string) {
	a := p.adapter
	var verifier authorize.Verifier
	if a.Runner != nil {
		verifier = a.Runner
	}
	who, refusal := authorize.Resolve(ctx, pool, sessionToken(ctx), claimsOf(scope), verifier, a.Sessions)
	event.TokenSHA256, event.RequesterKind = who.TokenSHA256, who.Kind
	event.Source, event.Automation, event.AutomationName, event.AutomationOwner = who.Source, who.Automation, who.AutomationName, who.AutomationOwner
	event.Run, event.ParentRun = who.Run, who.ParentRun
	switch refusal {
	case "":
		event.Requester = who.Audited()
	case "session_missing":
		event.Decision = who.SessionGap
	}
	return who, refusal
}

// claimsOf maps what the broker learned about the workload at admission into authorize.Claims.
func claimsOf(scope *brokercore.ProxyScope) authorize.Claims {
	return authorize.Claims{Pod: scope.WorkloadID, ClaimedRun: scope.ClaimedRun, AttestedRequester: scope.AttestedRequester, TokenAgent: tokenAgent(scope),
		TokenSource: scope.TokenSource, TokenOwner: scope.TokenOwner, PodRef: scope.Pod, NotAfter: scope.NotAfter}
}

// attribute names the run behind a refusal that comes before any entry is authorized, from its verified run token.
// The token is the session the CONNECT carried (ctx); an event that already names a run is left alone.
func (p *Proxy) attribute(ctx context.Context, scope *brokercore.ProxyScope, event *auditchain.Event) {
	a := p.adapter
	if scope == nil || event.Source != "" || event.Automation != "" || a == nil || a.Catalog == nil {
		return
	}
	pool, _ := a.Catalog.Current().Pool(scope.Pool)
	var verifier authorize.Verifier
	if a.Runner != nil {
		verifier = a.Runner
	}
	who := authorize.Attribute(ctx, pool, sessionToken(ctx), authorize.Claims{TokenAgent: tokenAgent(scope), TokenSource: scope.TokenSource}, verifier)
	event.Source, event.Automation, event.AutomationName, event.AutomationOwner = who.Source, who.Automation, who.AutomationName, who.AutomationOwner
}

// withWriteGrant returns err, or ErrAutomationReadOnly when the request needs a write grant the requester lacks.
func withWriteGrant(who authorize.Requester, g httpcatalog.GitRequest, err error) error {
	if err != nil {
		return err
	}
	for _, entry := range g.WriteEntries() {
		if !who.MayWrite(entry) {
			return httpcatalog.ErrAutomationReadOnly
		}
	}
	return nil
}

// tokenAgent is the Automation named by a scope's static agent token, or "".
func tokenAgent(scope *brokercore.ProxyScope) string {
	if scope.IdentityKind != brokercore.KindStaticToken {
		return ""
	}
	return scope.Automation
}
