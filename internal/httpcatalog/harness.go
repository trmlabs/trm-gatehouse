package httpcatalog

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"

	"github.com/Infisical/agent-vault/internal/imagerule"
)

// Harness is one agent runtime's profile: how its agents prove who they are,
// how they reach the broker, and whether access is decided for the pool or
// for the person behind each session. A new runtime is a new entry here, and
// needs code only if it brings a new identity kind. Every field is required
// unless marked optional, and an incomplete or contradictory entry refuses
// the whole catalog.
type Harness struct {
	Name          string               `json:"name"`
	TrustDomain   HarnessTrustDomain   `json:"trustDomain"`
	Identity      HarnessIdentity      `json:"identity"`
	Path          HarnessPath          `json:"path"`
	Authorization HarnessAuthorization `json:"authorization"`
	Client        HarnessClient        `json:"client"`
}

// HarnessClient names the environment variables the worker render sets for
// the agent's own programs, since some runtimes already use the standard
// ones (Cursor's HTTPS_PROXY points at its own control gateway). The broker
// does not read them; the HTTP and browser renders do.
type HarnessClient struct {
	// ProxyEnv holds Gatehouse's HTTP proxy URL (HTTPS_PROXY where free).
	ProxyEnv string `json:"proxyEnv"`
	// CAFileEnv holds the path of Gatehouse's interception CA file.
	CAFileEnv string `json:"caFileEnv"`
	// CASpkiEnv, optional, holds the CA's SPKI hash for browsers launched
	// with a trust flag instead of a CA store (no certutil in the image).
	CASpkiEnv string `json:"caSpkiEnv,omitempty"`
}

// HarnessTrustDomain is the cluster whose service-account tokens the broker
// accepts for this harness. Keys "in-cluster" reads the signing keys from the
// broker's own cluster API; "remote" fetches the issuer's published keys;
// "pinned" holds them in the broker's identity configuration, fetched never.
type HarnessTrustDomain struct {
	Issuer   string `json:"issuer"`
	Keys     string `json:"keys"`
	Audience string `json:"audience"`
}

// HarnessIdentity says how an agent proves who it is.
//
//   - "pod-token": the agent Pod's own projected token, checked against the
//     live Pod and the connection's source address (Cursor workers).
//   - "session-jwt": the same Pod check, plus a runner session token naming
//     the person, pinned to the first Pod that presents it (Claude sessions,
//     and Cursor runs whose sidecar mints the run's identity token).
//   - "proxy-attested": a shared proxy in the agent's cluster runs the Pod
//     check and presents its own token; the broker trusts that one proxy
//     account and the Pod it attests (agent-sandbox).
//   - "static-token": a client with no Kubernetes identity at all presents a
//     per-agent bearer token, checked against a hash in that agent's
//     Automation block. Only Kubernetes-free fields are allowed, and the
//     harness authorizes per Automation (see validateStaticToken).
//
// OwnerKind is the Kubernetes kind of the controller that must own the
// agent's Pod. ImageDigests are the images every container must run.
type HarnessIdentity struct {
	Kind         string   `json:"kind"`
	OwnerKind    string   `json:"ownerKind"`
	Namespaces   []string `json:"namespaces"`
	ImageDigests []string `json:"imageDigests,omitempty"`
	// ImagePrefix, proxy-attested only, admits any image pulled from under
	// this repository path in the agent image registry; ImageDigests then
	// holds only the platform's own containers, and may be empty.
	ImagePrefix string            `json:"imagePrefix,omitempty"`
	Requester   *HarnessRequester `json:"requester,omitempty"` // optional
}

// HarnessRequester is where the person behind a session comes from:
// "session-jwt" (a Claude runner session token), "cursor-oidc" (a Cursor
// run's identity token, minted by the sidecar from the worker's per-run
// socket), "pod-annotation" (the login a shared proxy attests from the agent
// Pod's requester annotation, which admission policy fixes to the creator of
// its controller) or "signed-assertion" (a statement the launching runtime
// signs onto the agent's controller object).
type HarnessRequester struct {
	Kind string `json:"kind"`
}

// HarnessPath is how the agent reaches the broker: a "sidecar" in the agent's
// own Pod, a "shared-proxy" serving many agents, or "direct" for a client
// that connects to the broker's own listener (static-token). CrossCluster says
// the agents run in another cluster than the broker.
type HarnessPath struct {
	Kind         string `json:"kind"`
	CrossCluster bool   `json:"crossCluster"`
}

// HarnessAuthorization decides access for the "pool" (its ceiling and fixed
// entitlements), for the "person" behind each session (their groups), or for
// the "automation" that started each run (the entries the catalog lists for
// it, and nothing about a person).
// PoolName is the catalog pool the harness's agents are admitted into.
type HarnessAuthorization struct {
	Mode     string `json:"mode"`
	PoolName string `json:"poolName"`
}

// Identity kinds, path kinds and authorization modes.
const (
	IdentityPodToken      = "pod-token"
	IdentitySessionJWT    = "session-jwt"
	IdentityProxyAttested = "proxy-attested"
	IdentityStaticToken   = "static-token"

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
)

// validate checks one profile on its own; validateHarnesses checks it against
// the pools.
func (h Harness) validate() error {
	if !idPattern.MatchString(h.Name) {
		return errors.New("name must be a short identifier")
	}
	if h.Identity.Kind == IdentityStaticToken {
		return h.validateStaticToken()
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
	// One harness may serve a namespace per tenant, so the list is fleet
	// sized; the bound only guards against a malformed catalog.
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
	// No upper bound on digests: each is short and fixed-size, and the
	// catalog's own size limit bounds the list.
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
	// The combinations that hold together. Each refusal names the reason.
	switch id.Kind {
	case IdentityPodToken:
		if h.Path.Kind != PathSidecar || requester != "" || h.Authorization.Mode != AuthorizePool {
			return errors.New("pod-token identity runs a sidecar, names no requester and authorizes the pool")
		}
	case IdentitySessionJWT:
		if h.Authorization.Mode == AuthorizeAutomation {
			// Only a Cursor run's token names the Automation that started it.
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
			// Fail closed until the broker verifies assertions: a profile that
			// names one must not silently run at pool level.
			return errors.New("signed-assertion requesters are not verified by this broker yet")
		}
		// A person only from the proxy's attested requester, and the
		// requester only where the person is authorized: a pool-mode
		// namespace never borrows one.
		if (requester == RequesterPodAnnotation) != (h.Authorization.Mode == AuthorizePerson) {
			return errors.New("a proxy-attested harness authorizes the person exactly when its requester is pod-annotation")
		}
		// The broker picks a proxy's profile by namespace, so each names one.
		if len(id.Namespaces) != 1 {
			return errors.New("a proxy-attested harness names exactly one namespace")
		}
	}
	// An agent in another cluster is verified by that cluster's keys: a
	// shared proxy there attests its agents, and a sidecar there is admitted
	// directly only where the broker's identity configuration reads that
	// cluster's Pods (a trust domain's pods), which refuses it otherwise.
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

// validateStaticToken checks a static-token profile. Its agents are not
// Kubernetes workloads, so every Kubernetes field is refused rather than
// ignored: a profile that names a trust domain, namespace or image would
// promise a check the broker never makes. It reaches the broker directly,
// authorizes per Automation, and names no person.
func (h Harness) validateStaticToken() error {
	id := h.Identity
	if h.TrustDomain != (HarnessTrustDomain{}) {
		return errors.New("a static-token harness has no trustDomain: it is not a Kubernetes identity")
	}
	if id.OwnerKind != "" || len(id.Namespaces) != 0 || len(id.ImageDigests) != 0 || id.ImagePrefix != "" || id.Requester != nil {
		return errors.New("a static-token harness takes no ownerKind, namespaces, images or requester")
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

// sharePool reports whether two harnesses may name the same pool. A pool says
// who decides access (here, each listed Automation); the harness says how an
// agent proves it is one, so a pool that decides per Automation may have its
// Kubernetes harness and, beside it, one static-token harness. Exactly one of
// the two is static-token, which is also all Parse keeps apart. Any other pool
// belongs to one harness.
func sharePool(a, b Harness) bool {
	return a.Authorization.Mode == AuthorizeAutomation && b.Authorization.Mode == AuthorizeAutomation &&
		(a.Identity.Kind == IdentityStaticToken) != (b.Identity.Kind == IdentityStaticToken)
}

// validateHarnesses checks every profile and binds it to its pool. When a
// catalog declares harnesses, each pool belongs to exactly one, except that a
// pool deciding per Automation may add one static-token harness (sharePool), and
// the pool's identity agrees with the profile's authorization. At most one
// harness uses a static-token identity, since the broker finds a token's pool
// through it.
func validateHarnesses(harnesses []Harness, pools map[string]Pool) (map[string][]Harness, error) {
	if len(harnesses) == 0 {
		return nil, nil
	}
	byPool := map[string][]Harness{}
	static := ""
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
		personPool, person := personIdentities[pool.Identity]
		if person != (h.Authorization.Mode == AuthorizePerson) || (pool.Identity == IdentityCursorAutomation) != (h.Authorization.Mode == AuthorizeAutomation) {
			return nil, fmt.Errorf("harness %q authorizes the %s, but pool %q has identity %q", h.Name, h.Authorization.Mode, pool.Name, pool.Identity)
		}
		// Each source of a person is trusted only on its own kind of pool.
		requester := (Profile{Harness: h}).RequesterKind()
		if person && requester != personPool {
			return nil, fmt.Errorf("harness %q takes its person from %q, but pool %q has identity %q", h.Name, requester, pool.Name, pool.Identity)
		}
		if h.Identity.Kind != IdentityStaticToken && pool.Namespace != "" && !contains(h.Identity.Namespaces, pool.Namespace) {
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
	for name := range pools {
		if _, ok := byPool[name]; !ok {
			return nil, fmt.Errorf("pool %q has no harness", name)
		}
	}
	return byPool, nil
}

// Profile is the harness a pool's agents are admitted under. Explicit is
// false for a catalog that declares no harnesses: the profile is then derived
// from the pool's identity alone, and names no trust domain, namespaces or
// images to check, which is how the broker behaved before profiles.
type Profile struct {
	Harness
	Explicit bool
}

// Profile returns the pool's profile.
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

// StaticToken returns the pool's static-token profile, when the pool has one.
// Profile still names the pool's Kubernetes harness, which is what the
// admission of a Pod checks; a static-token client is never admitted by it.
func (p Pool) StaticToken() (Profile, bool) {
	if p.staticHarness == nil {
		return Profile{}, false
	}
	return Profile{Harness: *p.staticHarness, Explicit: true}, true
}

// StaticAgent finds the Automation a static token claims to be, and the pool
// its harness serves. It lists an Automation only when its block carries a
// token hash, so a block meant for a Cursor run (which has none) can never be
// reached with a guessed id, and a block with a token can never be reached by
// a Cursor run.
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

// personIdentities maps each pool identity that names a person to the only
// requester kind that may name it.
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
