package mitm

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/Infisical/agent-vault/internal/auditchain"
	"github.com/Infisical/agent-vault/internal/authorize"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/httpcatalog"
	"github.com/Infisical/agent-vault/internal/ratelimit"
)

// settingsOperation names a settings request in its audit row.
const settingsOperation = "automation.settings"

// isSettingsRequest reports an origin-form request for the settings route,
// which a sidecar sends on the listener it already reaches the broker on.
func (p *Proxy) isSettingsRequest(r *http.Request) bool {
	return p.adapter.valid() && r.URL.Host == "" && r.URL.Path == httpcatalog.SettingsPath
}

// handleSettings serves GET httpcatalog.SettingsPath: the plain settings the
// catalog lists for the Automation behind the calling worker's run, which its
// sidecar writes where the agent's shells read them.
//
// The caller proves its Pod as on a CONNECT (Proxy-Authorization) and relays
// the run's token (Gatehouse-Session), and the requester is resolved exactly
// as for a request through the proxy (authorize.Resolve): the token must be
// for the run the live Pod was started for, pinned to that Pod, and the Pod
// to one run owner. Nothing in the request names an Automation, so a worker
// can read only its own run's. A run whose requester is not an Automation, on
// any pool, gets an empty set.
//
// Every refusal is a bare 403: no body and no reason, which its audit row
// records instead. The sidecar treats any other status as the broker being
// unavailable and asks again.
func (p *Proxy) handleSettings(w http.ResponseWriter, r *http.Request) {
	a := p.adapter
	bare := func(status int) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Length", "0")
		w.WriteHeader(status)
	}
	if r.Method != http.MethodGet || r.RequestURI != httpcatalog.SettingsPath || r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
		bare(http.StatusBadRequest)
		return
	}
	if p.rateLimit != nil && !isLoopbackPeer(r) {
		if d := p.rateLimit.Check(ratelimit.TierAuth, mitmIPKey(r)); !d.Allow {
			w.Header().Set("Retry-After", strconv.Itoa(max(1, int(d.RetryAfter.Seconds()))))
			bare(http.StatusTooManyRequests)
			return
		}
	}
	event := auditchain.Event{Event: auditchain.EventDenied, Method: http.MethodGet, Path: httpcatalog.SettingsPath, Operation: settingsOperation}
	deny := func(decision string) {
		event.Outcome, event.Decision, event.Status = "refused", decision, http.StatusForbidden
		if a.Audit.Record(event) != nil {
			bare(http.StatusServiceUnavailable)
			return
		}
		bare(http.StatusForbidden)
	}
	token, hint, err := brokercore.ParseProxyAuth(r)
	if err != nil {
		p.recordAuthFailure(r)
		deny("")
		return
	}
	peer, peerErr := peerFromContext(r.Context())
	scope, err := p.resolveScope(r.Context(), token, hint, peer, peerErr, false)
	if err != nil {
		p.recordAuthFailure(r)
		if key := brokercore.DenialKey(err); key != nil {
			event.Kid, event.KidSHA256, event.Peer = key.Kid, key.KidSHA256, key.Peer
		}
		decision := ""
		if reason := brokercore.DenialReason(err); reason != "" {
			decision = "identity_" + reason
		}
		deny(decision)
		return
	}
	event.Pool, event.Agent, event.PodUID = scope.Pool, scope.AgentID, scope.WorkloadID
	if a.Audit.Admit() != nil {
		bare(http.StatusServiceUnavailable)
		return
	}
	pool, _ := a.Catalog.Current().Pool(scope.Pool)
	var verifier authorize.Verifier
	if a.Runner != nil {
		verifier = a.Runner
	}
	who, refusal := authorize.Resolve(r.Context(), pool, r.Header.Get(SessionHeader),
		authorize.Claims{Pod: scope.WorkloadID, ClaimedRun: scope.ClaimedRun, AttestedRequester: scope.AttestedRequester}, verifier, a.Sessions)
	event.TokenSHA256, event.RequesterKind = who.TokenSHA256, who.Kind
	event.Source, event.Automation, event.AutomationName, event.AutomationOwner = who.Source, who.Automation, who.AutomationName, who.AutomationOwner
	if refusal != "" {
		deny(refusal)
		return
	}
	settings := who.Settings()
	if settings == nil {
		settings = map[string]string{}
	}
	body, err := json.Marshal(struct {
		Settings map[string]string `json:"settings"`
	}{settings})
	if err != nil {
		bare(http.StatusInternalServerError)
		return
	}
	event.Event, event.Outcome, event.Status = auditchain.EventSettings, "served", http.StatusOK
	event.Requester, event.Settings = who.Audited(), auditchain.SettingsField(httpcatalog.SettingNames(settings))
	if a.Audit.Record(event) != nil {
		bare(http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}
