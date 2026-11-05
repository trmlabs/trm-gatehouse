// Package brokercore is the runtime glue for the MITM proxy ingress: credential and session+vault resolution behind interfaces.
package brokercore

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/Infisical/agent-vault/internal/broker"
)

// DefaultMaxResponseBytes is the default response body cap on the MITM ingress; 0 means unlimited (streamed, no OOM risk).
const DefaultMaxResponseBytes int64 = 0

// ProxyErrorHeader marks broker-layer error responses so SDK clients can tell them from upstream ones.
const ProxyErrorHeader = "X-Agent-Vault-Proxy-Error"

// HopByHopHeaders must not be forwarded by a proxy; includes the non-RFC Proxy-Connection.
var HopByHopHeaders = map[string]bool{
	"Connection":          true,
	"Keep-Alive":          true,
	"Proxy-Authenticate":  true,
	"Proxy-Authorization": true,
	"Proxy-Connection":    true,
	"Te":                  true,
	"Trailer":             true,
	"Transfer-Encoding":   true,
	"Upgrade":             true,
}

// IsHopByHop reports whether the given header name is hop-by-hop.
func IsHopByHop(name string) bool {
	return HopByHopHeaders[http.CanonicalHeaderKey(name)]
}

// IsValidHost reports whether h is a safe hostname for an outbound URL or CONNECT target; h must not include a port.
func IsValidHost(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	for _, c := range h {
		if c == '@' || c == '?' || c == '#' || c == '/' || c == '\\' || c == ' ' || c == '%' || c < 0x20 || c == 0x7f {
			return false
		}
	}
	return !strings.HasPrefix(h, ".") && !strings.HasSuffix(h, ".")
}

// brokerScopedRequestHeaders authenticate the client to Agent Vault itself and must never reach the target.
var brokerScopedRequestHeaders = map[string]bool{
	"X-Vault":             true,
	"Proxy-Authorization": true,
}

// IsBrokerScopedRequestHeader reports whether a header must be stripped before forwarding to the target.
func IsBrokerScopedRequestHeader(name string) bool {
	return brokerScopedRequestHeaders[http.CanonicalHeaderKey(name)]
}

// ApplyInjection writes outbound headers; inject.Headers keys are stripped first so injected values always win.
func ApplyInjection(src, dst http.Header, inject *InjectResult, extraStrip ...string) {
	strip := make(map[string]bool, len(extraStrip)+len(inject.Headers))
	for _, s := range extraStrip {
		strip[http.CanonicalHeaderKey(s)] = true
	}
	for k := range inject.Headers {
		strip[http.CanonicalHeaderKey(k)] = true
	}
	for _, c := range src.Values("Connection") {
		for _, f := range strings.Split(c, ",") {
			if f = strings.TrimSpace(f); f != "" {
				strip[http.CanonicalHeaderKey(f)] = true
			}
		}
	}
	for k, vv := range src {
		ck := http.CanonicalHeaderKey(k)
		if IsHopByHop(ck) || IsBrokerScopedRequestHeader(ck) || strip[ck] {
			continue
		}
		for _, v := range vv {
			dst.Add(ck, v)
		}
	}
	for k, v := range inject.Headers {
		dst.Set(k, v)
	}
}

// helpLinks returns the standard "see available services / usage instructions"
// suffix appended to broker-layer error messages when baseURL is known.
func helpLinks(baseURL string) string {
	return fmt.Sprintf(
		"To see available services, GET %s/discover. For usage instructions including how to create a proposal, GET %s/v1/skills/cli",
		baseURL, baseURL,
	)
}

// ForbiddenHintBody returns the 403 JSON body when the target host matches no broker service; baseURL builds help links.
func ForbiddenHintBody(targetHost, vaultName, baseURL string) map[string]interface{} {
	body := map[string]interface{}{
		"error":   "forbidden",
		"message": fmt.Sprintf("No broker service matching host %q in vault %q", targetHost, vaultName),
		"proposal_hint": map[string]interface{}{
			"host":                 targetHost,
			"endpoint":             "POST /v1/proposals",
			"supported_auth_types": broker.SupportedAuthTypes,
		},
	}
	if baseURL != "" {
		body["help"] = "This request was intercepted by Agent Vault. " + helpLinks(baseURL)
	}
	return body
}

// ShouldStripResponseHeader reports whether an upstream header must not reach the agent (hop-by-hop, Set-Cookie, RefusalHeader).
func ShouldStripResponseHeader(name string) bool {
	return IsHopByHop(name) || strings.EqualFold(name, "Set-Cookie") || strings.EqualFold(name, RefusalHeader)
}

// WriteProxyError writes a JSON {error, message} response with the ProxyErrorHeader set.
func WriteProxyError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set(ProxyErrorHeader, "true")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "message": message})
}

// writeProxyErrorWithHelp is like WriteProxyError but appends an optional
// help field when baseURL is non-empty.
func writeProxyErrorWithHelp(w http.ResponseWriter, status int, code, message, baseURL string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set(ProxyErrorHeader, "true")
	w.WriteHeader(status)
	body := map[string]interface{}{"error": code, "message": message}
	if baseURL != "" {
		body["help"] = helpLinks(baseURL)
	}
	_ = json.NewEncoder(w).Encode(body)
}

// WriteForbiddenHint writes a 403 with the shared proposal_hint body for
// the "host not brokerable" case on the MITM ingress.
func WriteForbiddenHint(w http.ResponseWriter, targetHost, vaultName, baseURL string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set(ProxyErrorHeader, "true")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(ForbiddenHintBody(targetHost, vaultName, baseURL))
}

// WriteInjectError maps a CredentialProvider.Inject error to the standard ingress HTTP response.
func WriteInjectError(w http.ResponseWriter, err error, targetHost, vaultName, baseURL string) {
	switch {
	case errors.Is(err, ErrServiceNotFound):
		WriteForbiddenHint(w, targetHost, vaultName, baseURL)
	case errors.Is(err, ErrServiceDisabled):
		writeProxyErrorWithHelp(w, http.StatusForbidden, "service_disabled",
			fmt.Sprintf("Broker service matching host %q in vault %q is currently disabled", targetHost, vaultName), baseURL)
	case errors.Is(err, ErrOAuthNotConnected):
		writeProxyErrorWithHelp(w, http.StatusBadGateway, "oauth_not_connected",
			"OAuth credential is approved but not yet connected — complete the connection in the Agent Vault dashboard", baseURL)
	case errors.Is(err, ErrOAuthRefreshFailed):
		writeProxyErrorWithHelp(w, http.StatusBadGateway, "oauth_refresh_failed",
			"OAuth token expired and refresh failed — reconnect in the Agent Vault dashboard", baseURL)
	case errors.Is(err, ErrCredentialMissing):
		writeProxyErrorWithHelp(w, http.StatusBadGateway, "credential_not_found",
			"A required credential could not be resolved; check vault configuration", baseURL)
	default:
		WriteProxyError(w, http.StatusInternalServerError, "internal",
			"Failed to resolve broker services")
	}
}
