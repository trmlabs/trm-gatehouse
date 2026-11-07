package httpcatalog

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/Infisical/agent-vault/internal/imagerule"
	"github.com/Infisical/agent-vault/internal/runnerid"
)

// Harness is one agent runtime's profile: how its agents prove who they are, how they reach the broker, and whether access is decided per pool or per person. Every field is required unless marked optional; an incomplete or contradictory entry refuses the whole catalog.
type Harness struct {
	Name          string               `json:"name"`
	TrustDomain   HarnessTrustDomain   `json:"trustDomain"`
	Identity      HarnessIdentity      `json:"identity"`
	Path          HarnessPath          `json:"path"`
	Authorization HarnessAuthorization `json:"authorization"`
	Client        HarnessClient        `json:"client"`
}

// HarnessClient names the environment variables the worker render sets for the agent's own programs; the broker does not read them.
type HarnessClient struct {
	ProxyEnv  string `json:"proxyEnv"`
	CAFileEnv string `json:"caFileEnv"`
	// CASpkiEnv, optional, holds the CA's SPKI hash for browsers launched with a trust flag instead of a CA store.
	CASpkiEnv string `json:"caSpkiEnv,omitempty"`
}

// HarnessTrustDomain is the cluster whose service-account tokens the broker accepts. Keys "in-cluster" reads signing keys from the broker's cluster API, "remote" fetches the issuer's published keys, "pinned" holds them in configuration.
type HarnessTrustDomain struct {
	Issuer   string `json:"issuer"`
	Keys     string `json:"keys"`
	Audience string `json:"audience"`
}

// HarnessIdentity says how an agent proves who it is: "pod-token" (the Pod's projected token), "session-jwt" (Pod check plus a runner session token naming the person), "proxy-attested" (a shared proxy attests the Pod), or "static-token" (a per-agent bearer token with no Kubernetes identity; see validateStaticToken).
// OwnerKind is the Kubernetes kind of the controller that must own the Pod; ImageDigests are the images every container must run.
type HarnessIdentity struct {
	Kind         string   `json:"kind"`
	OwnerKind    string   `json:"ownerKind"`
	Namespaces   []string `json:"namespaces"`
	ImageDigests []string `json:"imageDigests,omitempty"`
	// ImagePrefix, proxy-attested only, admits any image under this registry path; ImageDigests then holds only the platform's own containers.
	ImagePrefix string            `json:"imagePrefix,omitempty"`
	Requester   *HarnessRequester `json:"requester,omitempty"` // optional
	// Token, signed-token only, is the platform's signed-token rules; see HarnessSignedToken.
	Token *HarnessSignedToken `json:"token,omitempty"`
}

// HarnessSignedToken is how the broker checks a platform's signed ID tokens (an OIDC-style JWT), so a new platform is a catalog entry and no new code. Every field is required unless marked optional.
// Issuer, one of JWKSURL or Discovery, Audiences and Algorithms say whose tokens are accepted and how; MaxLifetimeSeconds bounds exp minus iat; SubjectClaim names the agent (it is matched to an Automation's signedToken.subject) and GroupsClaim, optional, the groups.
type HarnessSignedToken struct {
	Issuer     string   `json:"issuer"`
	JWKSURL    string   `json:"jwksURL,omitempty"`
	Discovery  bool     `json:"discovery,omitempty"`
	Audiences  []string `json:"audiences"`
	Algorithms []string `json:"algorithms"`
	// MaxLifetimeSeconds is the longest a token may live from iat to exp, and the furthest ahead it may expire.
	MaxLifetimeSeconds int `json:"maxLifetimeSeconds"`
	// ClockSkewSeconds, optional (unset is 60; an explicit 0 is no skew), forgives a fast clock for iat and nbf, never for exp.
	ClockSkewSeconds *int   `json:"clockSkewSeconds,omitempty"`
	SubjectClaim     string `json:"subjectClaim"`
	GroupsClaim      string `json:"groupsClaim,omitempty"`
	// RequiredClaims, optional, are claims whose string value a token must carry exactly, checked together with the subject.
	RequiredClaims map[string]string `json:"requiredClaims,omitempty"`
	// KeyMaxAgeSeconds (default 3600) and RefreshBackoffSeconds (default 30), optional, tune the signing-key cache.
	KeyMaxAgeSeconds      int `json:"keyMaxAgeSeconds,omitempty"`
	RefreshBackoffSeconds int `json:"refreshBackoffSeconds,omitempty"`
}

// HarnessRequester is where the person behind a session comes from: "session-jwt", "cursor-oidc", "pod-annotation" (the login a shared proxy attests from the Pod's requester annotation) or "signed-assertion".
type HarnessRequester struct {
	Kind string `json:"kind"`
}

// HarnessPath is how the agent reaches the broker: a "sidecar", a "shared-proxy", or "direct" (static-token); CrossCluster means the agents run in another cluster.
type HarnessPath struct {
	Kind         string `json:"kind"`
	CrossCluster bool   `json:"crossCluster"`
}

// HarnessAuthorization decides access for the "pool", the "person" behind each session, or the "automation" that started each run; PoolName is the pool the agents are admitted into.
type HarnessAuthorization struct {
	Mode     string `json:"mode"`
	PoolName string `json:"poolName"`
}

const (
	IdentityPodToken      = "pod-token"
	IdentitySessionJWT    = "session-jwt"
	IdentityProxyAttested = "proxy-attested"
	IdentityStaticToken   = "static-token"
	IdentitySignedToken   = "signed-token"

	RequesterSessionJWT      = "session-jwt"
	RequesterCursorOIDC      = "cursor-oidc"
	RequesterSignedAssertion = "signed-assertion"
	RequesterPodAnnotation   = "pod-annotation"

	PathSidecar     = "sidecar"
	PathSharedProxy = "shared-proxy"
	PathDirect      = "direct"

	KeysInCluster = "in-cluster"
	KeysRemote    = "remote"
	KeysPinned    = "pinned"

	AuthorizePool       = "pool"
	AuthorizePerson     = "person"
	AuthorizeAutomation = "automation"
)

var (
	kubernetesKind = regexp.MustCompile(`^[A-Z][A-Za-z0-9]{0,62}$`)
	envName        = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,127}$`)
	audiencePat    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,252}$`)
	digestPattern  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	claimName      = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_:./-]{0,127}$`)
)

func (h Harness) validate() error {
	if !idPattern.MatchString(h.Name) {
		return errors.New("name must be a short identifier")
	}
	if h.Identity.Kind == IdentityStaticToken {
		return h.validateStaticToken()
	}
	if h.Identity.Kind == IdentitySignedToken {
		return h.validateSignedToken()
	}
	if h.Identity.Token != nil {
		return errors.New("identity.token is for signed-token harnesses")
	}
	td := h.TrustDomain
	u, err := url.Parse(td.Issuer)
	if td.Issuer == "" || err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || len(td.Issuer) > 512 {
		return errors.New("trustDomain.issuer must be an HTTPS URL")
	}
	if td.Keys != KeysInCluster && td.Keys != KeysRemote && td.Keys != KeysPinned {
		return fmt.Errorf("trustDomain.keys %q: in-cluster, remote or pinned", td.Keys)
	}
	if !audiencePat.MatchString(td.Audience) {
		return errors.New("trustDomain.audience is required")
	}
	id := h.Identity
	switch id.Kind {
	case IdentityPodToken, IdentitySessionJWT, IdentityProxyAttested:
	default:
		return fmt.Errorf("identity.kind %q: pod-token, session-jwt or proxy-attested", id.Kind)
	}
	if !kubernetesKind.MatchString(id.OwnerKind) {
		return errors.New("identity.ownerKind must be a Kubernetes kind")
	}
	// One harness may serve a namespace per tenant; the bound only guards against a malformed catalog.
	if len(id.Namespaces) == 0 || len(id.Namespaces) > 10000 {
		return errors.New("identity.namespaces needs 1 to 10,000 namespaces")
	}
	seen := map[string]bool{}
	for _, ns := range id.Namespaces {
		if !dnsLabel.MatchString(ns) || seen[ns] {
			return fmt.Errorf("identity namespace %q is invalid or repeated", ns)
		}
		seen[ns] = true
	}
	if id.ImagePrefix != "" && (id.Kind != IdentityProxyAttested || !imagerule.ValidPrefix(id.ImagePrefix)) {
		return errors.New("identity.imagePrefix is for proxy-attested harnesses: a repository or tenant path under AGENT_VAULT_IMAGE_REGISTRY, ending in /")
	}
	if id.ImagePrefix == "" && len(id.ImageDigests) == 0 {
		return errors.New("identity.imageDigests needs at least one digest unless an image prefix is set")
	}
	for _, d := range id.ImageDigests {
		if !digestPattern.MatchString(d) {
			return errors.New("identity image digest must be sha256: and 64 lowercase hex characters")
		}
	}
	requester := ""
	if id.Requester != nil {
		requester = id.Requester.Kind
		if requester != RequesterSessionJWT && requester != RequesterCursorOIDC && requester != RequesterSignedAssertion && requester != RequesterPodAnnotation {
			return fmt.Errorf("identity.requester.kind %q: session-jwt, cursor-oidc, pod-annotation or signed-assertion", requester)
		}
	}
	switch h.Path.Kind {
	case PathSidecar, PathSharedProxy:
	default:
		return fmt.Errorf("path.kind %q: sidecar or shared-proxy", h.Path.Kind)
	}
	switch h.Authorization.Mode {
	case AuthorizePool, AuthorizePerson, AuthorizeAutomation:
	default:
		return fmt.Errorf("authorization.mode %q: pool, person or automation", h.Authorization.Mode)
	}
	if !idPattern.MatchString(h.Authorization.PoolName) {
		return errors.New("authorization.poolName is required")
	}
	if err := h.Client.validate(); err != nil {
		return err
	}
	switch id.Kind {
	case IdentityPodToken:
		if h.Path.Kind != PathSidecar || requester != "" || h.Authorization.Mode != AuthorizePool {
			return errors.New("pod-token identity runs a sidecar, names no requester and authorizes the pool")
		}
	case IdentitySessionJWT:
		if h.Authorization.Mode == AuthorizeAutomation {
			if h.Path.Kind != PathSidecar || requester != RequesterCursorOIDC {
				return errors.New("an automation harness runs a sidecar and takes its automation from a Cursor run token (cursor-oidc)")
			}
			break
		}
		if h.Path.Kind != PathSidecar || requester == RequesterSignedAssertion || requester == RequesterPodAnnotation || h.Authorization.Mode != AuthorizePerson {
			return errors.New("session-jwt identity runs a sidecar, takes its person from the session and authorizes the person")
		}
	case IdentityProxyAttested:
		if h.Path.Kind != PathSharedProxy || requester == RequesterSessionJWT || requester == RequesterCursorOIDC || h.Authorization.Mode == AuthorizeAutomation {
			return errors.New("proxy-attested identity runs a shared proxy and takes no session token")
		}
		if requester == RequesterSignedAssertion {
			// Fail closed until the broker verifies assertions: a profile naming one must not silently run at pool level.
			return errors.New("signed-assertion requesters are not verified by this broker yet")
		}
		// A person comes only from the proxy's attested requester, and only where the person is authorized.
		if (requester == RequesterPodAnnotation) != (h.Authorization.Mode == AuthorizePerson) {
			return errors.New("a proxy-attested harness authorizes the person exactly when its requester is pod-annotation")
		}
		if len(id.Namespaces) != 1 {
			return errors.New("a proxy-attested harness names exactly one namespace")
		}
	}
	// An agent in another cluster is verified by that cluster's keys: a shared proxy attests it, or a sidecar is admitted only where a trust domain's pods are readable.
	if h.Path.CrossCluster != (td.Keys != KeysInCluster) {
		return errors.New("a cross-cluster path uses another cluster's keys (remote or pinned), and only it does")
	}
	return nil
}

func (c HarnessClient) validate() error {
	if !envName.MatchString(c.ProxyEnv) || !envName.MatchString(c.CAFileEnv) || (c.CASpkiEnv != "" && !envName.MatchString(c.CASpkiEnv)) {
		return errors.New("client needs proxyEnv and caFileEnv environment variable names")
	}
	if c.ProxyEnv == c.CAFileEnv || (c.CASpkiEnv != "" && (c.CASpkiEnv == c.ProxyEnv || c.CASpkiEnv == c.CAFileEnv)) {
		return errors.New("client environment variable names must differ")
	}
	return nil
}

// validateStaticToken refuses every Kubernetes field rather than ignoring it, since a trust domain, namespace or image would promise a check the broker never makes.
func (h Harness) validateStaticToken() error {
	id := h.Identity
	if h.TrustDomain != (HarnessTrustDomain{}) {
		return errors.New("a static-token harness has no trustDomain: it is not a Kubernetes identity")
	}
	if id.OwnerKind != "" || len(id.Namespaces) != 0 || len(id.ImageDigests) != 0 || id.ImagePrefix != "" || id.Requester != nil || id.Token != nil {
		return errors.New("a static-token harness takes no ownerKind, namespaces, images, requester or token")
	}
	if h.Path.Kind != PathDirect || h.Path.CrossCluster {
		return errors.New("a static-token harness reaches the broker directly (path.kind direct, crossCluster false)")
	}
	if h.Authorization.Mode != AuthorizeAutomation {
		return errors.New("a static-token harness authorizes the automation: each agent is one listed Automation")
	}
	if !idPattern.MatchString(h.Authorization.PoolName) {
		return errors.New("authorization.poolName is required")
	}
	return h.Client.validate()
}

// validateSignedToken refuses every Kubernetes field, as validateStaticToken does, and checks the token rules: an unproven token is refused at admission, so a rule left open here would be one the broker never makes.
func (h Harness) validateSignedToken() error {
	id := h.Identity
	if h.TrustDomain != (HarnessTrustDomain{}) {
		return errors.New("a signed-token harness has no trustDomain: it is not a Kubernetes identity")
	}
	if id.OwnerKind != "" || len(id.Namespaces) != 0 || len(id.ImageDigests) != 0 || id.ImagePrefix != "" || id.Requester != nil {
		return errors.New("a signed-token harness takes no ownerKind, namespaces, images or requester")
	}
	if h.Path.Kind != PathDirect || h.Path.CrossCluster {
		return errors.New("a signed-token harness reaches the broker directly (path.kind direct, crossCluster false)")
	}
	if h.Authorization.Mode != AuthorizeAutomation {
		return errors.New("a signed-token harness authorizes the automation: each agent is one listed Automation")
	}
	if !idPattern.MatchString(h.Authorization.PoolName) {
		return errors.New("authorization.poolName is required")
	}
	if err := id.Token.validate(); err != nil {
		return err
	}
	return h.Client.validate()
}

func httpsURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && raw != "" && len(raw) <= 512 && u.Scheme == "https" && u.Host != "" && u.User == nil && u.Fragment == ""
}

func (t *HarnessSignedToken) validate() error {
	if t == nil {
		return errors.New("a signed-token harness needs identity.token")
	}
	if !httpsURL(t.Issuer) {
		return errors.New("identity.token.issuer must be an HTTPS URL")
	}
	if slices.Contains([]string{runnerid.GoogleIssuer, runnerid.GumloopIssuer, runnerid.CursorIssuer}, strings.TrimSuffix(t.Issuer, "/")) {
		return errors.New("identity.token.issuer is verified in code for another platform and cannot be claimed by a harness")
	}
	if u, _ := url.Parse(t.Issuer); u.RawQuery != "" {
		return errors.New("identity.token.issuer must be an HTTPS URL with no query")
	}
	if t.Discovery == (t.JWKSURL != "") {
		return errors.New("identity.token needs exactly one of jwksURL and discovery")
	}
	if t.JWKSURL != "" && !httpsURL(t.JWKSURL) {
		return errors.New("identity.token.jwksURL must be an HTTPS URL")
	}
	if len(t.Audiences) == 0 {
		return errors.New("identity.token.audiences needs at least one audience")
	}
	seen := map[string]bool{}
	for _, a := range t.Audiences {
		if !audiencePat.MatchString(a) || seen[a] {
			return fmt.Errorf("identity.token audience %q is invalid or repeated", a)
		}
		seen[a] = true
	}
	if len(t.Algorithms) == 0 {
		return errors.New("identity.token.algorithms needs RS256, ES256 or both")
	}
	algs := map[string]bool{}
	for _, a := range t.Algorithms {
		if (a != "RS256" && a != "ES256") || algs[a] {
			return fmt.Errorf("identity.token algorithm %q: RS256 or ES256, once each", a)
		}
		algs[a] = true
	}
	if t.MaxLifetimeSeconds < 1 || t.MaxLifetimeSeconds > MaxSignedTokenLifetimeSeconds {
		return fmt.Errorf("identity.token.maxLifetimeSeconds must be from 1 to %d", MaxSignedTokenLifetimeSeconds)
	}
	if t.ClockSkewSeconds != nil && (*t.ClockSkewSeconds < 0 || *t.ClockSkewSeconds > 300) {
		return errors.New("identity.token.clockSkewSeconds must be from 0 to 300")
	}
	reserved := map[string]bool{"iss": true, "aud": true, "exp": true, "iat": true, "nbf": true}
	if !claimName.MatchString(t.SubjectClaim) || reserved[t.SubjectClaim] {
		return errors.New("identity.token.subjectClaim must name a claim that identifies the agent")
	}
	if t.GroupsClaim != "" && (!claimName.MatchString(t.GroupsClaim) || reserved[t.GroupsClaim] || t.GroupsClaim == t.SubjectClaim) {
		return errors.New("identity.token.groupsClaim must name a claim other than the subject claim")
	}
	if len(t.RequiredClaims) > 8 {
		return errors.New("identity.token.requiredClaims takes at most 8 claims")
	}
	for name, want := range t.RequiredClaims {
		if !claimName.MatchString(name) || reserved[name] || name == t.SubjectClaim || name == t.GroupsClaim || want == "" || len(want) > 256 || strings.ContainsAny(want, " \t\r\n") {
			return fmt.Errorf("identity.token.requiredClaims %q must name a claim other than the reserved, subject and groups claims, with a plain non-empty value", name)
		}
	}
	if t.KeyMaxAgeSeconds != 0 && (t.KeyMaxAgeSeconds < 60 || t.KeyMaxAgeSeconds > 86400) {
		return errors.New("identity.token.keyMaxAgeSeconds must be from 60 to 86400")
	}
	if t.RefreshBackoffSeconds != 0 && (t.RefreshBackoffSeconds < 1 || t.RefreshBackoffSeconds > 3600) {
		return errors.New("identity.token.refreshBackoffSeconds must be from 1 to 3600")
	}
	maxAge, backoff := t.KeyMaxAgeSeconds, t.RefreshBackoffSeconds
	if maxAge == 0 {
		maxAge = 3600
	}
	if backoff == 0 {
		backoff = 30
	}
	if backoff*2 > maxAge {
		return errors.New("identity.token.refreshBackoffSeconds must be at most half of keyMaxAgeSeconds (defaults 30 and 3600)")
	}
	return nil
}

// MaxSignedTokenLifetimeSeconds bounds maxLifetimeSeconds so a mistyped value cannot read as a standing credential: a signed token is replayable until it expires.
const MaxSignedTokenLifetimeSeconds = 24 * 60 * 60

// harnessClass sorts identities by how a pool may combine them: a Kubernetes harness, the one static-token harness, or any number of signed-token ones.
func harnessClass(h Harness) string {
	switch h.Identity.Kind {
	case IdentityStaticToken, IdentitySignedToken:
		return h.Identity.Kind
	}
	return "kubernetes"
}

// sharePool allows a pool that decides per Automation to have its Kubernetes harness, one static-token harness and any signed-token harnesses; any other pool belongs to one harness.
func sharePool(a, b Harness) bool {
	if a.Authorization.Mode != AuthorizeAutomation || b.Authorization.Mode != AuthorizeAutomation {
		return false
	}
	ca, cb := harnessClass(a), harnessClass(b)
	return ca != cb || ca == IdentitySignedToken
}

// validateHarnesses checks every profile and binds it to its pool; at most one harness uses a static-token identity, since the broker finds a token's pool through it.
func validateHarnesses(harnesses []Harness, pools map[string]Pool) (map[string][]Harness, error) {
	if len(harnesses) == 0 {
		return nil, nil
	}
	byPool := map[string][]Harness{}
	static := ""
	signedIssuers := map[string]string{} // issuer to harness
	names := map[string]bool{}
	attested := map[string]string{} // issuer and namespace to harness
	prefixes := map[string]string{} // harness to image prefix
	for _, h := range harnesses {
		if err := h.validate(); err != nil {
			return nil, fmt.Errorf("harness %q: %w", h.Name, err)
		}
		if names[h.Name] {
			return nil, fmt.Errorf("duplicate harness %q", h.Name)
		}
		names[h.Name] = true
		pool, ok := pools[h.Authorization.PoolName]
		if !ok {
			return nil, fmt.Errorf("harness %q names undefined pool %q", h.Name, h.Authorization.PoolName)
		}
		for _, other := range byPool[pool.Name] {
			if !sharePool(other, h) {
				return nil, fmt.Errorf("pool %q belongs to more than one harness", pool.Name)
			}
		}
		if h.Identity.Kind == IdentityStaticToken {
			if static != "" {
				return nil, fmt.Errorf("harnesses %q and %q both use static-token identity; one serves every agent with a token", static, h.Name)
			}
			static = h.Name
		}
		if t := h.Identity.Token; h.Identity.Kind == IdentitySignedToken && t != nil {
			if other, ok := signedIssuers[t.Issuer]; ok {
				return nil, fmt.Errorf("harnesses %q and %q both name issuer %q; the broker picks a harness by issuer", other, h.Name, t.Issuer)
			}
			signedIssuers[t.Issuer] = h.Name
		}
		personPool, person := personIdentities[pool.Identity]
		if person != (h.Authorization.Mode == AuthorizePerson) || (pool.Identity == IdentityCursorAutomation) != (h.Authorization.Mode == AuthorizeAutomation) {
			return nil, fmt.Errorf("harness %q authorizes the %s, but pool %q has identity %q", h.Name, h.Authorization.Mode, pool.Name, pool.Identity)
		}
		requester := (Profile{Harness: h}).RequesterKind()
		if person && requester != personPool {
			return nil, fmt.Errorf("harness %q takes its person from %q, but pool %q has identity %q", h.Name, requester, pool.Name, pool.Identity)
		}
		if harnessClass(h) == "kubernetes" && pool.Namespace != "" && !contains(h.Identity.Namespaces, pool.Namespace) {
			return nil, fmt.Errorf("harness %q does not list pool %q's namespace", h.Name, pool.Name)
		}
		if h.Identity.ImagePrefix != "" {
			for other, prefix := range prefixes {
				if imagerule.Overlap(prefix, h.Identity.ImagePrefix) {
					return nil, fmt.Errorf("harnesses %q and %q claim overlapping image prefixes", other, h.Name)
				}
			}
			prefixes[h.Name] = h.Identity.ImagePrefix
		}
		if h.Identity.Kind == IdentityProxyAttested {
			key := h.TrustDomain.Issuer + " " + h.Identity.Namespaces[0]
			if other, ok := attested[key]; ok {
				return nil, fmt.Errorf("harnesses %q and %q both claim namespace %q of one trust domain", other, h.Name, h.Identity.Namespaces[0])
			}
			attested[key] = h.Name
		}
		byPool[pool.Name] = append(byPool[pool.Name], h)
	}
	for issuer, name := range signedIssuers {
		for _, h := range harnesses {
			if h.TrustDomain.Issuer != "" && strings.TrimSuffix(h.TrustDomain.Issuer, "/") == strings.TrimSuffix(issuer, "/") {
				return nil, fmt.Errorf("harness %q names issuer %q, which is harness %q's trustDomain.issuer; the broker would check its tokens as a Kubernetes identity", name, issuer, h.Name)
			}
		}
	}
	for name := range pools {
		if _, ok := byPool[name]; !ok {
			return nil, fmt.Errorf("pool %q has no harness", name)
		}
	}
	return byPool, nil
}

// Profile is the harness a pool's agents are admitted under; Explicit is false when no harnesses are declared and it is derived from the pool's identity alone.
type Profile struct {
	Harness
	Explicit bool
}

func (p Pool) Profile() Profile {
	if p.harness != nil {
		return Profile{Harness: *p.harness, Explicit: true}
	}
	h := Harness{Name: p.Name, Identity: HarnessIdentity{Kind: IdentityPodToken}, Path: HarnessPath{Kind: PathSidecar},
		Authorization: HarnessAuthorization{Mode: AuthorizePool, PoolName: p.Name}}
	switch p.Identity {
	case "claude-session":
		h.Identity = HarnessIdentity{Kind: IdentitySessionJWT, Requester: &HarnessRequester{Kind: RequesterSessionJWT}}
		h.Authorization.Mode = AuthorizePerson
	case "cursor-session":
		h.Identity = HarnessIdentity{Kind: IdentitySessionJWT, Requester: &HarnessRequester{Kind: RequesterCursorOIDC}}
		h.Authorization.Mode = AuthorizePerson
	case IdentityCursorAutomation:
		h.Identity = HarnessIdentity{Kind: IdentitySessionJWT, Requester: &HarnessRequester{Kind: RequesterCursorOIDC}}
		h.Authorization.Mode = AuthorizeAutomation
	}
	return Profile{Harness: h}
}

// StaticToken returns the pool's static-token profile; a static-token client is never admitted by Profile's Kubernetes harness.
func (p Pool) StaticToken() (Profile, bool) {
	if p.staticHarness == nil {
		return Profile{}, false
	}
	return Profile{Harness: *p.staticHarness, Explicit: true}, true
}

// StaticAgent finds the Automation a static token claims to be and its pool; only a block with a token hash is listed, so it is never reachable by a Cursor run's id and vice versa.
func (c Catalog) StaticAgent(id string) (Automation, string, bool) {
	a, ok := c.automations[id]
	if !ok || !a.HasToken() {
		return Automation{}, "", false
	}
	for _, h := range c.harnesses {
		if h.Identity.Kind == IdentityStaticToken {
			return a, h.Authorization.PoolName, true
		}
	}
	return Automation{}, "", false
}

// GumloopAgent finds the Automation naming a verified Gumloop org and owner (the owner's block, else the org's) and its pool.
func (c Catalog) GumloopAgent(orgID, ownerID string) (Automation, string, bool) {
	if orgID == "" {
		return Automation{}, "", false
	}
	var found, orgWide *Automation
	for id := range c.automations {
		a := c.automations[id]
		switch {
		case a.Gumloop == nil || a.Gumloop.OrgID != orgID:
		case a.Gumloop.OwnerID == "":
			orgWide = &a
		case a.Gumloop.OwnerID == ownerID:
			found = &a
		}
	}
	if found == nil {
		found = orgWide
	}
	if found == nil {
		return Automation{}, "", false
	}
	for _, h := range c.harnesses {
		if h.Identity.Kind == IdentityStaticToken {
			return *found, h.Authorization.PoolName, true
		}
	}
	return Automation{}, "", false
}

// GoogleAgent finds the Automation naming a verified Google service account unique ID and its pool.
func (c Catalog) GoogleAgent(uniqueID string) (Automation, string, bool) {
	if uniqueID == "" {
		return Automation{}, "", false
	}
	for id := range c.automations {
		a := c.automations[id]
		if a.GoogleServiceAccount == nil || a.GoogleServiceAccount.UniqueID != uniqueID {
			continue
		}
		for _, h := range c.harnesses {
			if h.Identity.Kind == IdentityStaticToken {
				return a, h.Authorization.PoolName, true
			}
		}
		return Automation{}, "", false
	}
	return Automation{}, "", false
}

// RequesterKind is where the person behind a session comes from, or "".
func (p Profile) RequesterKind() string {
	if p.Identity.Requester != nil {
		return p.Identity.Requester.Kind
	}
	if p.Identity.Kind == IdentitySessionJWT {
		return RequesterSessionJWT
	}
	return ""
}

var personIdentities = map[string]string{
	"claude-session":  RequesterSessionJWT,
	"cursor-session":  RequesterCursorOIDC,
	"attested-person": RequesterPodAnnotation,
}

// AttestedPool is the pool a proxy-attested profile of this issuer claims the namespace for, never an external-ceiling pool.
func (c Catalog) AttestedPool(namespace, issuer string) (string, bool) {
	for _, h := range c.harnesses {
		if h.Identity.Kind == IdentityProxyAttested && h.TrustDomain.Issuer == issuer && h.Identity.Namespaces[0] == namespace {
			return h.Authorization.PoolName, !c.externalPool(h.Authorization.PoolName)
		}
	}
	return "", false
}

// AttestedNamespaces lists the namespaces AttestedPool serves in the trust domain with this issuer.
func (c Catalog) AttestedNamespaces(issuer string) []string {
	var out []string
	for _, h := range c.harnesses {
		if h.Identity.Kind == IdentityProxyAttested && h.TrustDomain.Issuer == issuer && !c.externalPool(h.Authorization.PoolName) {
			out = append(out, h.Identity.Namespaces[0])
		}
	}
	return out
}

func (c Catalog) externalPool(name string) bool {
	p, ok := c.Pool(name)
	return !ok || p.Ceiling == CeilingExternal
}

// Harnesses returns the declared profiles.
func (c Catalog) Harnesses() []Harness { return append([]Harness(nil), c.harnesses...) }

// SignedTokenHarness is the signed-token harness for a token's issuer; validation allows one harness per issuer.
func (c Catalog) SignedTokenHarness(issuer string) (Harness, bool) {
	for _, h := range c.harnesses {
		if h.Identity.Kind == IdentitySignedToken && h.Identity.Token != nil && h.Identity.Token.Issuer == issuer {
			return h, true
		}
	}
	return Harness{}, false
}

// SignedTokenAgent finds the Automation naming a verified subject of a signed-token harness, and that harness's pool.
func (c Catalog) SignedTokenAgent(harness, subject string) (Automation, string, bool) {
	id, ok := c.signedAgents[harness+"\x00"+subject]
	if !ok {
		return Automation{}, "", false
	}
	a, ok := c.automations[id]
	if !ok {
		return Automation{}, "", false
	}
	for _, h := range c.harnesses {
		if h.Name == harness && h.Identity.Kind == IdentitySignedToken {
			return a, h.Authorization.PoolName, true
		}
	}
	return Automation{}, "", false
}

// AdmitsToken reports whether the pool takes the Automation's own proof: a static-token or Gumloop block needs the pool's static-token harness, a signed-token block the harness it names.
func (p Pool) AdmitsToken(a Automation) bool {
	if a.SignedToken != nil {
		for _, h := range p.signedHarnesses {
			if h.Name == a.SignedToken.Harness {
				return true
			}
		}
		return false
	}
	_, ok := p.StaticToken()
	return ok
}
