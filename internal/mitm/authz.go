package mitm

import (
	"context"
	"strings"

	"github.com/Infisical/agent-vault/internal/auditchain"
	"github.com/Infisical/agent-vault/internal/authorize"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/httpcatalog"
)

// SessionHeader carries the Claude runner's session token from the in-Pod
// sidecar on the CONNECT request. The sidecar sets it; a worker cannot, since
// the sidecar forwards only a fixed set of CONNECT headers.
const SessionHeader = "Gatehouse-Session"

type sessionTokenKey struct{}

func withSessionToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, sessionTokenKey{}, token)
}

func sessionToken(ctx context.Context) string {
	token, _ := ctx.Value(sessionTokenKey{}).(string)
	return token
}

// authorize applies the authorization model to one matched catalog entry and
// fills the audit event. It returns who stands behind the request, whose
// branch segment narrows a git or github-api request's push prefixes
// (httpcatalog.GitRequest.ForRequester), and a refusal code, or "".
func (p *Proxy) authorize(ctx context.Context, scope *brokercore.ProxyScope, entry *httpcatalog.Entry, event *auditchain.Event) (authorize.Requester, string) {
	a := p.adapter
	pool, _ := a.Catalog.Current().Pool(scope.Pool) // undefined pools: no identity, ceiling T0
	var verifier authorize.Verifier
	if a.Runner != nil {
		verifier = a.Runner
	}
	who, refusal := authorize.Resolve(ctx, pool, sessionToken(ctx), authorize.Claims{Pod: scope.WorkloadID, ClaimedRun: scope.ClaimedRun, AttestedRequester: scope.AttestedRequester, TokenAgent: tokenAgent(scope)}, verifier, a.Sessions)
	event.TokenSHA256, event.RequesterKind = who.TokenSHA256, who.Kind
	event.Source, event.Automation, event.AutomationName, event.AutomationOwner = who.Source, who.Automation, who.AutomationName, who.AutomationOwner
	if refusal != "" {
		return who, refusal
	}
	event.Requester = who.Audited()
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

// attribute names the run behind a refusal that comes before any entry is
// authorized, from its verified run token (authorize.Attribute), unless the
// event already names one. The token is the session the CONNECT carried (ctx).
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
	who := authorize.Attribute(ctx, pool, sessionToken(ctx), authorize.Claims{TokenAgent: tokenAgent(scope)}, verifier)
	event.Source, event.Automation, event.AutomationName, event.AutomationOwner = who.Source, who.Automation, who.AutomationName, who.AutomationOwner
}

// withWriteGrant is the match error to forward with a matched git or github-api
// request: err when the match failed, and otherwise ErrAutomationReadOnly when
// the request needs the write grant of an entry (GitRequest.WriteEntries) that
// the requester does not hold (Requester.MayWrite), which only an Automation
// can lack. It runs after the entry's authorization, which names who the
// requester is, and before any token is minted or GitHub asked.
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

// tokenAgent is the Automation a scope's static agent token names, or "".
// Only a scope that came by that token carries one.
func tokenAgent(scope *brokercore.ProxyScope) string {
	if scope.IdentityKind != brokercore.KindStaticToken {
		return ""
	}
	return scope.Automation
}
