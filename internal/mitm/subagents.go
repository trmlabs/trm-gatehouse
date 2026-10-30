package mitm

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/Infisical/agent-vault/internal/auditchain"
	"github.com/Infisical/agent-vault/internal/authorize"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/httpcatalog"
)

// SubagentHost is the broker-local registration route; .invalid never resolves, so no real destination can share the name.
const SubagentHost = "subagents.gatehouse.invalid"

const subagentPath = "/v1/subagents/"

// subagentRoute is true only for the subagent host on port 443 of a pool that decides per Automation.
func subagentRoute(catalog httpcatalog.Catalog, host string, port int, pool string) bool {
	if !strings.EqualFold(host, SubagentHost) || port != 443 {
		return false
	}
	p, ok := catalog.Pool(pool)
	return ok && p.Identity == httpcatalog.IdentityCursorAutomation
}

// subagentRegistered is the route's answer: the run, its parent run, the Automation and when the registration ends.
type subagentRegistered struct {
	Run        string `json:"run"`
	ParentRun  string `json:"parentRun"`
	Automation string `json:"automation"`
	Expires    string `json:"expires"`
}

// registerSubagent resolves the caller like a catalog entry and requires a listed Automation's own run; audit rows name the registering run.
func (p *Proxy) registerSubagent(w http.ResponseWriter, r *http.Request, target string, scope *brokercore.ProxyScope, event auditchain.Event, catalog httpcatalog.Catalog) {
	a := p.adapter
	event.Binding, event.Operation = "subagents", "subagent.register"
	deny := func(status int, outcome string) { p.adapterDeny(w, event, target, status, outcome) }
	if r.Method != http.MethodPost {
		deny(http.StatusMethodNotAllowed, "method")
		return
	}
	run, ok := strings.CutPrefix(r.URL.Path, subagentPath)
	if !ok || r.URL.IsAbs() || !authorityMatches(r, target) || r.URL.User != nil || r.URL.RawQuery != "" || r.URL.ForceQuery ||
		r.URL.Fragment != "" || r.URL.RawPath != "" || r.ContentLength != 0 || len(r.TransferEncoding) != 0 || len(r.Trailer) != 0 ||
		r.Header.Get("Upgrade") != "" || r.Header.Get("Content-Encoding") != "" {
		deny(http.StatusBadRequest, "request_shape")
		return
	}
	pool, _ := catalog.Pool(scope.Pool)
	who, refusal := p.requester(r.Context(), scope, pool, &event)
	if refusal != "" {
		deny(http.StatusForbidden, refusal)
		return
	}
	enf := p.rateLimit.EnforceProxy(r.Context(), proxyLimitActor(scope), event.Binding)
	if !enf.Allowed {
		p.adapterRateDeny(w, event, target, enf.Decision)
		return
	}
	defer enf.Release()
	admitted := event
	admitted.Event, admitted.Outcome = auditchain.EventHTTPRequest, "admitted"
	if err := a.Audit.Record(admitted); err != nil {
		refuse(w, "audit_unavailable")
		return
	}
	expires, refusal := authorize.RegisterSubagent(r.Context(), pool, who, claimsOf(scope), run, a.Sessions)
	switch refusal {
	case "":
	case "request_shape":
		deny(http.StatusBadRequest, refusal)
		return
	default:
		deny(http.StatusForbidden, refusal)
		return
	}
	done := event
	done.Event, done.Outcome, done.Status = auditchain.EventHTTPResponse, "subagent_registered", http.StatusOK
	_ = a.Audit.Record(done)
	body, err := json.Marshal(subagentRegistered{Run: run, ParentRun: who.Run, Automation: who.Subject, Expires: expires.UTC().Format(time.RFC3339)})
	if err != nil {
		refuse(w, "broker_unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(append(body, '\n'))
}
