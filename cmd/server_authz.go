package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Infisical/agent-vault/internal/authorize"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/entitlement"
	"github.com/Infisical/agent-vault/internal/mitm"
	"github.com/Infisical/agent-vault/internal/netguard"
	"github.com/Infisical/agent-vault/internal/runnerid"
)

// authorization is the Claude and Cursor verifiers and the entitlement cache,
// any of which may be nil.
type authorization struct {
	runner       *runnerid.Verifier
	cursor       *runnerid.CursorVerifier
	sandbox      []string // person domains for attested requesters
	entitlements *entitlement.Cache
}

// verifier returns the session verifiers as the interface consumers take, nil
// (not a typed nil) when none is set.
func (a authorization) verifier() authorize.Verifier {
	if a.runner == nil && a.cursor == nil && len(a.sandbox) == 0 {
		return nil
	}
	return runnerid.Verifiers{Claude: a.runner, Cursor: a.cursor, SandboxDomains: a.sandbox}
}

// attachAuthorization wires the authorization model into the HTTP adapter.
func attachAuthorization(adapter *mitm.HeaderAdapter, getenv func(string) string) error {
	a, err := loadAuthorization(getenv)
	if err != nil {
		return err
	}
	if v := a.verifier(); v != nil {
		adapter.Runner = v
	}
	adapter.Entitlements = a.entitlements
	return nil
}

// loadAuthorization reads the authorization model's settings, shared by the
// HTTP adapter and the PostgreSQL broker:
//   - AGENT_VAULT_RUNNER_JWKS_URL (and AGENT_VAULT_RUNNER_ISSUER, default ccr)
//     verify Claude runner session tokens;
//   - AGENT_VAULT_RUNNER_PERSON_DOMAINS lists the email domains (comma
//     separated, lower case) whose user sessions name a person, by act.email as
//     the Entra user principal name. Unset: no session names a person;
//   - AGENT_VAULT_CURSOR_AUDIENCE and AGENT_VAULT_CURSOR_TEAM_IDS (comma
//     separated) verify Cursor run identity tokens minted for that audience in
//     those teams; AGENT_VAULT_CURSOR_PERSON_DOMAINS names persons by
//     owner_email as AGENT_VAULT_RUNNER_PERSON_DOMAINS does for Claude.
//     AGENT_VAULT_CURSOR_JWKS_URL and AGENT_VAULT_CURSOR_ISSUER default to
//     Cursor's published ones; AGENT_VAULT_CURSOR_PEOPLE_FILE, when set,
//     replaces owner_email: a JSON object of Cursor user ID to Entra object ID,
//     the only way a user run names a person, by that object ID;
//   - AGENT_VAULT_GUMLOOP_AUDIENCE must be a broker-only audience: Gumloop sets
//     aud to whatever provider path a credential names, so the audience alone
//     separates a broker token from a GCP federation token. Never use a real
//     workload identity provider path;
//   - AGENT_VAULT_SANDBOX_PERSON_DOMAINS lists the email domains whose logins,
//     attested by a shared proxy from an agent Pod's requester annotation, name
//     a person, as the Entra user principal name. Unset: no attested login
//     names a person, and person-mode agent-sandbox pools are refused;
//   - AGENT_VAULT_ENTITLEMENTS selects the entitlement source: "file:<path>"
//     (fixtures and tests), "graph", or unset. "graph" asks Microsoft Graph,
//     looking the person up by user principal name, with a token from
//     workload identity federation and no secret: AGENT_VAULT_GRAPH_TENANT_ID
//     and AGENT_VAULT_GRAPH_CLIENT_ID (the Entra app) and
//     AGENT_VAULT_GRAPH_TOKEN_FILE (the projected service-account token,
//     audience api://AzureADTokenExchange) are all required;
//   - AGENT_VAULT_ENTITLEMENT_CACHE_SECONDS shortens the 5-minute cache;
//   - AGENT_VAULT_ENTITLEMENT_LOOKUPS_PER_MINUTE sets each person's directory
//     lookup budget, per cache: the HTTP adapter and the PostgreSQL broker
//     each load their own (default entitlement.DefaultLookupsPerMinute). It
//     may not exceed AGENT_VAULT_ENTITLEMENT_LOOKUPS_PER_MINUTE_MAX (default
//     entitlement.DefaultMaxLookupsPerMinute), so a mistyped budget fails at
//     start instead of removing the guard. Each broker replica keeps its own
//     budget, so the directory sees up to replicas times two times this.
//
// Without a verifier or a source, entries above T0 are refused on the pools
// that would need them.
func loadAuthorization(getenv func(string) string) (authorization, error) {
	var a authorization
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: runnerid.RefuseRedirects,
		Transport: &http.Transport{DialContext: netguard.SafeDialContext(netguard.AllowPrivateFromEnv()), TLSHandshakeTimeout: 5 * time.Second}}
	if url := getenv("AGENT_VAULT_RUNNER_JWKS_URL"); url != "" {
		if !strings.HasPrefix(url, "https://") {
			return a, fmt.Errorf("AGENT_VAULT_RUNNER_JWKS_URL must be https")
		}
		issuer := getenv("AGENT_VAULT_RUNNER_ISSUER")
		if issuer == "" {
			issuer = "ccr"
		}
		domains, err := personDomains("AGENT_VAULT_RUNNER_PERSON_DOMAINS", getenv)
		if err != nil {
			return a, err
		}
		a.runner = &runnerid.Verifier{JWKSURL: url, Issuer: issuer, PersonDomains: domains, Client: client}
	}
	sandbox, err := personDomains("AGENT_VAULT_SANDBOX_PERSON_DOMAINS", getenv)
	if err != nil {
		return a, err
	}
	a.sandbox = sandbox
	if audience := getenv("AGENT_VAULT_CURSOR_AUDIENCE"); audience != "" {
		cursor, err := cursorVerifier(audience, getenv, client)
		if err != nil {
			return a, err
		}
		a.cursor = cursor
	}
	ttl := entitlement.MaxCacheTTL
	if raw := getenv("AGENT_VAULT_ENTITLEMENT_CACHE_SECONDS"); raw != "" {
		seconds, err := strconv.Atoi(raw)
		if err != nil || seconds < 1 || time.Duration(seconds)*time.Second > entitlement.MaxCacheTTL {
			return a, fmt.Errorf("AGENT_VAULT_ENTITLEMENT_CACHE_SECONDS must be 1 to 300")
		}
		ttl = time.Duration(seconds) * time.Second
	}
	ceiling := entitlement.DefaultMaxLookupsPerMinute
	if raw := getenv("AGENT_VAULT_ENTITLEMENT_LOOKUPS_PER_MINUTE_MAX"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 {
			return a, fmt.Errorf("AGENT_VAULT_ENTITLEMENT_LOOKUPS_PER_MINUTE_MAX must be a positive whole number")
		}
		ceiling = n
	}
	lookups := entitlement.DefaultLookupsPerMinute
	if raw := getenv("AGENT_VAULT_ENTITLEMENT_LOOKUPS_PER_MINUTE"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 {
			return a, fmt.Errorf("AGENT_VAULT_ENTITLEMENT_LOOKUPS_PER_MINUTE must be a positive whole number")
		}
		lookups = n
	}
	if lookups > ceiling {
		return a, fmt.Errorf("AGENT_VAULT_ENTITLEMENT_LOOKUPS_PER_MINUTE (%d) is above AGENT_VAULT_ENTITLEMENT_LOOKUPS_PER_MINUTE_MAX (%d)", lookups, ceiling)
	}
	switch source := getenv("AGENT_VAULT_ENTITLEMENTS"); {
	case source == "":
	case strings.HasPrefix(source, "file:") && strings.HasPrefix(source, "file:/"):
		a.entitlements = &entitlement.Cache{Source: entitlement.FileSource{Path: strings.TrimPrefix(source, "file:")}, TTL: ttl, LookupsPerMinute: lookups}
	case source == "graph":
		g, err := graphSource(getenv, client)
		if err != nil {
			return a, err
		}
		a.entitlements = &entitlement.Cache{Source: g, TTL: ttl, LookupsPerMinute: lookups}
	default:
		return a, fmt.Errorf("AGENT_VAULT_ENTITLEMENTS must be unset, graph or file:/absolute/path")
	}
	return a, nil
}

// graphSource reads the Graph settings. Every one is required: a broker told to
// ask the directory that cannot fails at start, not at its first lookup.
func graphSource(getenv func(string) string, client *http.Client) (entitlement.GraphSource, error) {
	tenant, app, file := getenv("AGENT_VAULT_GRAPH_TENANT_ID"), getenv("AGENT_VAULT_GRAPH_CLIENT_ID"), getenv("AGENT_VAULT_GRAPH_TOKEN_FILE")
	if !uuidPattern.MatchString(tenant) || !uuidPattern.MatchString(app) {
		return entitlement.GraphSource{}, fmt.Errorf("AGENT_VAULT_ENTITLEMENTS=graph needs AGENT_VAULT_GRAPH_TENANT_ID and AGENT_VAULT_GRAPH_CLIENT_ID as lower-case GUIDs")
	}
	if !strings.HasPrefix(file, "/") {
		return entitlement.GraphSource{}, fmt.Errorf("AGENT_VAULT_ENTITLEMENTS=graph needs AGENT_VAULT_GRAPH_TOKEN_FILE as an absolute path")
	}
	token := &entitlement.FederatedToken{TenantID: tenant, ClientID: app, AssertionFile: file, Client: client}
	return entitlement.GraphSource{Endpoint: entitlement.GraphEndpoint, Token: token.Token, Client: client}, nil
}

// cursorVerifier reads the Cursor settings. A Cursor audience without a team
// is refused: Cursor does not allowlist audiences, so the team is what keeps
// another company's runs out.
func cursorVerifier(audience string, getenv func(string) string, client *http.Client) (*runnerid.CursorVerifier, error) {
	if !audiencePattern.MatchString(audience) {
		return nil, fmt.Errorf("AGENT_VAULT_CURSOR_AUDIENCE must be printable with no spaces")
	}
	var teams []string
	for _, t := range strings.Split(getenv("AGENT_VAULT_CURSOR_TEAM_IDS"), ",") {
		if !teamPattern.MatchString(t) {
			return nil, fmt.Errorf("AGENT_VAULT_CURSOR_TEAM_IDS must be Cursor team IDs (decimal), comma separated")
		}
		teams = append(teams, t)
	}
	domains, err := personDomains("AGENT_VAULT_CURSOR_PERSON_DOMAINS", getenv)
	if err != nil {
		return nil, err
	}
	people, err := cursorPeople(getenv("AGENT_VAULT_CURSOR_PEOPLE_FILE"))
	if err != nil {
		return nil, err
	}
	if people != nil && len(domains) > 0 {
		slog.Warn("AGENT_VAULT_CURSOR_PERSON_DOMAINS is ignored because AGENT_VAULT_CURSOR_PEOPLE_FILE is set; the file alone names Cursor persons")
	}
	url, issuer := getenv("AGENT_VAULT_CURSOR_JWKS_URL"), getenv("AGENT_VAULT_CURSOR_ISSUER")
	if url == "" {
		url = runnerid.CursorJWKSURL
	}
	if issuer == "" {
		issuer = runnerid.CursorIssuer
	}
	if !strings.HasPrefix(url, "https://") {
		return nil, fmt.Errorf("AGENT_VAULT_CURSOR_JWKS_URL must be https")
	}
	return &runnerid.CursorVerifier{JWKSURL: url, Issuer: issuer, Audience: audience, TeamIDs: teams, PersonDomains: domains, People: people, Client: client}, nil
}

// personDomains parses a person email domain list: lower-case DNS names only.
func personDomains(name string, getenv func(string) string) ([]string, error) {
	raw := getenv(name)
	if raw == "" {
		return nil, nil
	}
	var domains []string
	for _, d := range strings.Split(raw, ",") {
		if !domainPattern.MatchString(d) {
			return nil, fmt.Errorf("%s must be lower-case domain names, comma separated", name)
		}
		domains = append(domains, d)
	}
	return domains, nil
}

// cursorPeople reads AGENT_VAULT_CURSOR_PEOPLE_FILE: a JSON object of Cursor
// user ID to Entra object ID, the shape of the Cursor runner's reviewed map.
// "" (unset) is nil, which keeps naming persons by owner_email. Any other
// problem is an error: a bad map must stop startup, never widen who is named.
func cursorPeople(path string) (map[string]string, error) {
	if path == "" {
		return nil, nil
	}
	const name = "AGENT_VAULT_CURSOR_PEOPLE_FILE"
	if !strings.HasPrefix(path, "/") {
		return nil, fmt.Errorf("%s must be an absolute path", name)
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) > 1<<20 {
		return nil, fmt.Errorf("%s must be a readable file of at most 1 MiB", name)
	}
	bad := fmt.Errorf(`%s must be one JSON object of Cursor user ID to lower-case Entra object ID, with no duplicate IDs or object IDs`, name)
	dec := json.NewDecoder(bytes.NewReader(data))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil, bad
	}
	people, seen := map[string]string{}, map[string]bool{}
	for dec.More() {
		key, err := dec.Token()
		id, ok := key.(string)
		var oid string
		if err != nil || !ok || dec.Decode(&oid) != nil || !cursorUserID.MatchString(id) || !uuidPattern.MatchString(oid) {
			return nil, bad
		}
		if _, dup := people[id]; dup || seen[oid] {
			return nil, bad
		}
		people[id], seen[oid] = oid, true
	}
	if t, err := dec.Token(); err != nil || t != json.Delim('}') || dec.More() || len(people) == 0 {
		return nil, bad
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, bad
	}
	return people, nil
}

var (
	cursorUserID    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	domainPattern   = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)
	audiencePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,252}$`)
	teamPattern     = regexp.MustCompile(`^[0-9]{1,20}$`)
	uuidPattern     = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

// maxSubagentWaitSeconds caps AGENT_VAULT_SUBAGENT_WAIT_SECONDS so a huge value cannot overflow or hold a request for hours.
const maxSubagentWaitSeconds = 600

// sessionBinder is the store's runner-session pin table, or nil when it cannot hold one (claude-session pools then refuse every session).
// Subagents are served only when the store keeps registrations and pods reads admitted Pods.
func sessionBinder(st, pods any) authorize.Binder {
	b, ok := st.(authorize.Binder)
	if !ok {
		return nil
	}
	registry, hasRegistry := st.(authorize.SubagentStore)
	live, hasPods := pods.(brokercore.LivePods)
	if !hasRegistry || !hasPods {
		return b
	}
	return &authorize.Subagents{Binder: b, Registry: registry, Pods: live,
		Wait: time.Duration(min(intEnvValue("AGENT_VAULT_SUBAGENT_WAIT_SECONDS"), maxSubagentWaitSeconds)) * time.Second}
}

// subagentsServable refuses to start when the catalog grants subagents but the binder cannot serve them.
func subagentsServable(adapter *mitm.HeaderAdapter) error {
	if _, ok := adapter.Sessions.(*authorize.Subagents); ok || adapter.Catalog == nil {
		return nil
	}
	for _, p := range adapter.Catalog.Current().Pools() {
		if p.GrantsSubagents() {
			return fmt.Errorf("the catalog grants subagents, which need a store with registrations and live Pod reads (not AGENT_VAULT_WORKLOAD_ATTESTATION=tokenreview)")
		}
	}
	return nil
}

// gumloopVerifier is nil when no Gumloop setting is set (the issuer alone is a partial config and fails), and refuses Gumloop settings without the static-token port; else the JWKS URL (https) and audience are both required; the issuer env var overrides the default issuer.
func gumloopVerifier(getenv func(string) string) (*runnerid.GumloopVerifier, error) {
	url, audience, issuer := getenv("AGENT_VAULT_GUMLOOP_JWKS_URL"), getenv("AGENT_VAULT_GUMLOOP_AUDIENCE"), getenv("AGENT_VAULT_GUMLOOP_ISSUER")
	if url == "" && audience == "" && issuer == "" {
		return nil, nil
	}
	if getenv("AGENT_VAULT_STATIC_TOKEN_PORT") == "" {
		return nil, fmt.Errorf("AGENT_VAULT_GUMLOOP_* needs AGENT_VAULT_STATIC_TOKEN_PORT")
	}
	if !strings.HasPrefix(url, "https://") {
		return nil, fmt.Errorf("AGENT_VAULT_GUMLOOP_JWKS_URL must be https")
	}
	if !audiencePattern.MatchString(audience) {
		return nil, fmt.Errorf("AGENT_VAULT_GUMLOOP_AUDIENCE must be printable with no spaces")
	}
	if issuer == "" {
		issuer = runnerid.GumloopIssuer
	}
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: runnerid.RefuseRedirects,
		Transport: &http.Transport{DialContext: netguard.SafeDialContext(netguard.AllowPrivateFromEnv()), TLSHandshakeTimeout: 5 * time.Second}}
	return &runnerid.GumloopVerifier{JWKSURL: url, Issuer: issuer, Audience: audience, Client: client}, nil
}
