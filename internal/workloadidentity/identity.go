// Package workloadidentity admits projected Kubernetes service-account tokens, never exchanging them for a standing broker token or caching authentication.
// They are bearer proofs: possession permits replay until expiry or revocation.
package workloadidentity

import (
	"bytes"
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/store"
	"github.com/jackc/pgx/v5/pgconn"
)

// Binding maps one account to broker authorization records; PodUID optionally restricts admission to one pod. A pool binding may omit AgentID and VaultID (see ProvisionPools).
type Binding struct {
	Namespace         string `json:"namespace"`
	ServiceAccount    string `json:"serviceAccount"`
	ServiceAccountUID string `json:"serviceAccountUID"`
	PodUID            string `json:"podUID"`
	AgentID           string `json:"agentID"`
	VaultID           string `json:"vaultID"`
	// Pool bindings (OwnerUIDs set) admit any live Pod of this account owned by these controllers, by local token verification plus its address.
	OwnerUIDs     []string `json:"ownerUIDs,omitempty"`
	ContainerName string   `json:"containerName,omitempty"`
	MaxPodSeconds int64    `json:"maxPodSeconds,omitempty"`
	Pool          string   `json:"pool,omitempty"` // catalog pool name reported as ProxyScope.Pool
	// ImageDigests lists the digests (sha256:<64 hex>) every container of a pool Pod must run, so a swapped image is no longer admitted.
	ImageDigests []string `json:"imageDigests,omitempty"`
	// ListAgents is valid only in observer policy, to read each agent's outstanding cleanup by agent and Pod UID.
	ListAgents bool `json:"listAgents,omitempty"`
	// TrustDomain names the listed trust domain whose tokens this binding admits; empty is the broker's own cluster.
	TrustDomain string `json:"trustDomain,omitempty"`
	// Service admits any live Pod of this account in the namespace, with no controller or lifetime rule, and gives it Pool; ImageDigests are required unless AllowUnpinnedImages is set. A service session ends with its token or Config.MaxServiceSessionSeconds, and the Pod re-attests with a fresh token. Pods of a long-lived service roll over by Deployment, so deployments must restrict who may create Pods under the account (admission policy, not shipped here).
	Service bool `json:"service,omitempty"`
	// AllowUnpinnedImages is the explicit opt-in for a service binding with no ImageDigests; any Pod of the account is then admitted whatever image it runs.
	AllowUnpinnedImages bool `json:"allowUnpinnedImages,omitempty"`
	// Proxy makes this a shared proxy's binding; see ProxyBinding.
	Proxy *ProxyBinding `json:"proxy,omitempty"`
}

// Config selects the broker's own trust domain, remote ones and workload grants; empty API/CA/reviewer paths select the in-cluster defaults.
type Config struct {
	APIServer               string    `json:"apiServer"`
	CAFile                  string    `json:"caFile"`
	ReviewerTokenFile       string    `json:"reviewerTokenFile"`
	Issuer                  string    `json:"issuer"`
	Audience                string    `json:"audience"`
	TimeoutSeconds          int       `json:"timeoutSeconds"`
	MaxTokenLifetimeSeconds int64     `json:"maxTokenLifetimeSeconds"`
	Bindings                []Binding `json:"bindings"`
	// TrustDomains are other clusters, each verified by its published keys.
	TrustDomains []TrustDomain `json:"trustDomains,omitempty"`
	// MaxSessionSeconds is the ceiling on every pool binding's Pod lifetime and proxy session (default a day, at most 30 days).
	MaxSessionSeconds int64 `json:"maxSessionSeconds,omitempty"`
	// MaxServiceSessionSeconds bounds a service binding's session from its token's issue time (default the smaller of an hour and MaxSessionSeconds); a session also ends when its token expires, and with service bindings it must be at least 300 s above the kubelet rotation point (80% of the longest service token lifetime) so rotation never leaves the Pod locked out.
	MaxServiceSessionSeconds int64 `json:"maxServiceSessionSeconds,omitempty"`
}

// DefaultServiceSessionLimit is MaxServiceSessionSeconds when unset.
const DefaultServiceSessionLimit = time.Hour

func (c *Config) serviceSessionLimit() int64 {
	if c.MaxServiceSessionSeconds == 0 {
		return min(int64(DefaultServiceSessionLimit/time.Second), c.sessionCeiling())
	}
	return c.MaxServiceSessionSeconds
}

// DefaultSessionCeiling is MaxSessionSeconds when unset.
const DefaultSessionCeiling = 24 * time.Hour

const maxSessionCeiling = 30 * 24 * time.Hour

func (c *Config) sessionCeiling() int64 {
	if c.MaxSessionSeconds == 0 {
		return int64(DefaultSessionCeiling / time.Second)
	}
	return c.MaxSessionSeconds
}

// Store supplies current broker identity and grant state for every decision.
type Store interface {
	GetAgentByID(context.Context, string) (*store.Agent, error)
	GetVaultByID(context.Context, string) (*store.Vault, error)
	GetVaultRole(context.Context, string, string) (string, error)
}

// Resolver verifies each proof online and implements both proxy admissions.
type Resolver struct {
	config Config
	client *http.Client
	store  Store
	now    func() time.Time
	jwks   *signingKeys // the broker's own cluster's keys: domains[0].keys
	// domains are the trust domains, the broker's own cluster first.
	domains []*domain
	// profiles, when set, holds each pool's declared harness profile.
	profiles atomic.Pointer[profileSource]
	// namespaces, when set, names the catalog pools a catalogPools proxy binding serves.
	namespaces atomic.Pointer[namespaceSource]
	logger     *slog.Logger
}

// SetLogger sets where refusal reasons are logged; workers still see only a generic refusal.
func (r *Resolver) SetLogger(l *slog.Logger) {
	if l != nil {
		r.logger = l
	}
}

var _ brokercore.SessionResolver = (*Resolver)(nil)

var imageDigest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

const (
	// maxConfigBytes bounds the configuration file: room for a proxy serving 10,000 tenant namespaces.
	maxConfigBytes = 16 << 20
	// maxListItems guards against a malformed file's short lists (owner UIDs, source ranges).
	maxListItems = 1024
	// maxProxyProfiles is how many namespaces one shared proxy may serve.
	maxProxyProfiles = 10000
)

// LoadConfig reads a bounded JSON policy and rejects unknown fields.
func LoadConfig(path string) (Config, error) {
	var c Config
	f, err := os.Open(path)
	if err != nil {
		return c, errors.New("cannot open workload identity configuration")
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxConfigBytes+1))
	if err != nil || len(data) > maxConfigBytes {
		return c, errors.New("workload identity configuration exceeds size limit or cannot be read")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return c, errors.New("invalid workload identity configuration")
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return c, errors.New("trailing workload identity configuration")
	}
	return c, nil
}

// New validates policy and builds a TLS-verifying client with no redirect or environment-proxy fallback; it keeps no positive authentication cache.
func New(c Config, s Store) (*Resolver, error) {
	return newResolver(c, s, false)
}

func newResolver(c Config, s Store, observer bool) (*Resolver, error) {
	if c.APIServer == "" {
		c.APIServer = "https://kubernetes.default.svc"
	}
	if c.CAFile == "" {
		c.CAFile = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	}
	if c.ReviewerTokenFile == "" {
		c.ReviewerTokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	}
	u, err := url.Parse(c.APIServer)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("workload identity apiServer must be an HTTPS origin")
	}
	if observer && len(c.TrustDomains) != 0 {
		return nil, errors.New("observer policy must not list trust domains")
	}
	if (!observer && s == nil) || c.CAFile == "" || c.ReviewerTokenFile == "" || c.Issuer == "" || c.Audience == "" || len(c.Bindings) == 0 {
		return nil, errors.New("workload identity requires trust, reviewer token, issuer, audience, store and bindings")
	}
	if c.TimeoutSeconds == 0 {
		c.TimeoutSeconds = 5
	}
	if c.TimeoutSeconds < 1 || c.TimeoutSeconds > 30 {
		return nil, errors.New("workload identity timeoutSeconds must be between 1 and 30")
	}
	if c.MaxTokenLifetimeSeconds == 0 {
		c.MaxTokenLifetimeSeconds = 3600
	}
	if c.MaxSessionSeconds != 0 && (c.MaxSessionSeconds < 60 || c.MaxSessionSeconds > int64(maxSessionCeiling/time.Second)) {
		return nil, errors.New("workload identity maxSessionSeconds must be between 60 s and 30 days")
	}
	ceiling := c.sessionCeiling()
	if c.MaxTokenLifetimeSeconds < 600 || c.MaxTokenLifetimeSeconds > 3600 {
		return nil, errors.New("workload identity maxTokenLifetimeSeconds must be between 600 and 3600")
	}
	tokenLifetime := func(domain string) int64 {
		for _, td := range c.TrustDomains {
			if td.Name == domain {
				return cmp.Or(td.MaxTokenLifetimeSeconds, 3600)
			}
		}
		return c.MaxTokenLifetimeSeconds
	}
	// Any domain may carry a service binding, so the explicit limit may reach the longest lifetime; the rotation floor follows only the domains service bindings name.
	longest, serviceLongest := c.MaxTokenLifetimeSeconds, int64(0)
	for _, td := range c.TrustDomains {
		longest = max(longest, tokenLifetime(td.Name))
	}
	for _, b := range c.Bindings {
		if b.Service {
			serviceLongest = max(serviceLongest, tokenLifetime(b.TrustDomain))
		}
	}
	if c.MaxServiceSessionSeconds != 0 && (c.MaxServiceSessionSeconds < 60 || c.MaxServiceSessionSeconds > min(ceiling, longest)) {
		return nil, errors.New("workload identity maxServiceSessionSeconds must be between 60 s and the smaller of maxSessionSeconds and the longest token lifetime")
	}
	if serviceLongest != 0 && c.serviceSessionLimit() < min(serviceLongest*4/5+300, serviceLongest) {
		return nil, errors.New("workload identity service session limit must be at least 300 s above the kubelet rotation point (80% of the longest service token lifetime)")
	}
	seen := map[string]bool{}
	proxyNamespaces := map[string]bool{}
	catalogBindings := map[string]bool{}
	for _, b := range c.Bindings {
		if !pathSegment(b.Namespace) || !pathSegment(b.ServiceAccount) || b.ServiceAccountUID == "" || (!observer && (b.AgentID == "" || b.VaultID == "")) {
			return nil, errors.New("workload identity binding requires namespace, account, account UID, agent and vault")
		}
		if observer && (b.AgentID != "" || b.VaultID != "") {
			return nil, errors.New("observer policy must not contain proxy grants")
		}
		if !b.Service && b.AllowUnpinnedImages {
			return nil, errors.New("allowUnpinnedImages applies only to service bindings")
		}
		if b.Service {
			if observer || b.Proxy != nil || b.Pool == "" || !pathSegment(b.Pool) || len(b.OwnerUIDs) != 0 || b.PodUID != "" || b.MaxPodSeconds != 0 || b.ContainerName != "" {
				return nil, errors.New("service binding requires a pool and takes no owner UIDs, Pod UID, Pod lifetime, container or proxy")
			}
			if len(b.ImageDigests) == 0 && !b.AllowUnpinnedImages {
				return nil, errors.New("service binding requires image digests or allowUnpinnedImages")
			}
			if len(b.ImageDigests) != 0 && b.AllowUnpinnedImages {
				return nil, errors.New("service binding sets both allowUnpinnedImages and image digests")
			}
			for _, digest := range b.ImageDigests {
				if !imageDigest.MatchString(digest) {
					return nil, errors.New("service binding image digest must be sha256: and 64 lowercase hex characters")
				}
			}
		} else if b.Proxy == nil && (len(b.OwnerUIDs) != 0 || b.ContainerName != "" || b.MaxPodSeconds != 0 || b.Pool != "" || len(b.ImageDigests) != 0) {
			if b.Pool != "" && !pathSegment(b.Pool) {
				return nil, errors.New("pool binding name must be a lowercase DNS-style name")
			}
			if observer || len(b.OwnerUIDs) == 0 || len(b.OwnerUIDs) > maxListItems || b.PodUID != "" || b.MaxPodSeconds < 60 || b.MaxPodSeconds > ceiling || (b.ContainerName != "" && !pathSegment(b.ContainerName)) {
				return nil, errors.New("pool binding requires owner UIDs (at most 1,024), no Pod UID and a Pod lifetime from 60 s to maxSessionSeconds")
			}
			for _, owner := range b.OwnerUIDs {
				if owner == "" {
					return nil, errors.New("pool binding owner UID must be non-empty")
				}
			}
			// No upper bound: digests are short fixed-size strings and the configuration file's size limit bounds the list.
			if len(b.ImageDigests) == 0 {
				return nil, errors.New("pool binding requires at least one image digest")
			}
			for _, digest := range b.ImageDigests {
				if !imageDigest.MatchString(digest) {
					return nil, errors.New("pool binding image digest must be sha256: and 64 lowercase hex characters")
				}
			}
		}
		if !observer && b.ListAgents {
			return nil, errors.New("proxy policy must not contain observer access")
		}
		if b.TrustDomain != "" && !listedDomain(c.TrustDomains, b.TrustDomain) {
			return nil, errors.New("workload identity binding names an unlisted trust domain")
		}
		if b.Proxy != nil {
			if observer || b.PodUID != "" || len(b.OwnerUIDs) != 0 || b.ContainerName != "" || b.MaxPodSeconds != 0 || len(b.ImageDigests) != 0 || b.Pool != "" {
				return nil, errors.New("a proxy binding takes its pools from its profiles and no Pod, owner or image settings of its own")
			}
			if err := b.Proxy.validate(ceiling); err != nil {
				return nil, err
			}
			if b.Proxy.CatalogPools {
				// Two such bindings would each admit every catalog namespace.
				if catalogBindings[b.TrustDomain] {
					return nil, errors.New("only one proxy binding of a trust domain may read its pools from the catalog")
				}
				catalogBindings[b.TrustDomain] = true
			}
			// Within one trust domain, a namespace names one profile.
			for _, pp := range b.Proxy.Profiles {
				key := b.TrustDomain + "/" + pp.Namespace
				if proxyNamespaces[key] {
					return nil, errors.New("a namespace is served by two proxy bindings of one trust domain")
				}
				proxyNamespaces[key] = true
			}
		}
		if b.TrustDomain != "" && b.Proxy == nil && ((len(b.OwnerUIDs) == 0 && !b.Service) || !readsPods(c.TrustDomains, b.TrustDomain)) {
			// TokenReview runs only in the broker's own cluster; the pool Pod check only where the broker can read the domain's Pods.
			return nil, errors.New("a remote trust domain admits proxy bindings, and pool bindings only where the broker reads its Pods")
		}
		key := b.TrustDomain + "/" + b.Namespace + ":" + b.ServiceAccount
		if seen[key] {
			return nil, errors.New("ambiguous workload identity binding")
		}
		seen[key] = true
	}
	pem, err := os.ReadFile(c.CAFile)
	if err != nil {
		return nil, errors.New("cannot read workload identity CA")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("invalid workload identity CA")
	}
	c.APIServer = strings.TrimSuffix(c.APIServer, "/")
	c.Bindings = append([]Binding(nil), c.Bindings...)
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}}
	r := &Resolver{config: c, store: s, now: time.Now, logger: slog.Default(), client: &http.Client{
		Timeout: time.Duration(c.TimeoutSeconds) * time.Second, Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
	if err := r.buildDomains(c); err != nil {
		return nil, err
	}
	r.jwks = r.domains[0].keys
	return r, nil
}

// readsPods reports whether the trust domain gives the broker its cluster's Pods.
func readsPods(domains []TrustDomain, name string) bool {
	for _, d := range domains {
		if d.Name == name {
			return d.Pods != nil
		}
	}
	return false
}

func listedDomain(domains []TrustDomain, name string) bool {
	for _, d := range domains {
		if d.Name == name {
			return true
		}
	}
	return false
}

func pathSegment(s string) bool {
	if s == "" || s == "." || s == ".." {
		return false
	}
	for _, c := range s {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '.' {
			return false
		}
	}
	return true
}

type claims struct {
	Issuer     string   `json:"iss"`
	Subject    string   `json:"sub"`
	Audience   []string `json:"aud"`
	Expires    int64    `json:"exp"`
	Issued     int64    `json:"iat"`
	NotBefore  int64    `json:"nbf"`
	Kubernetes struct {
		Namespace      string `json:"namespace"`
		ServiceAccount struct {
			Name string `json:"name"`
			UID  string `json:"uid"`
		} `json:"serviceaccount"`
		Pod struct {
			Name string `json:"name"`
			UID  string `json:"uid"`
		} `json:"pod"`
	} `json:"kubernetes.io"`
}

type review struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Spec       struct {
		Token     string   `json:"token"`
		Audiences []string `json:"audiences"`
	} `json:"spec"`
	Status struct {
		Authenticated bool     `json:"authenticated"`
		Error         string   `json:"error"`
		Audiences     []string `json:"audiences"`
		User          struct {
			Username string              `json:"username"`
			UID      string              `json:"uid"`
			Extra    map[string][]string `json:"extra"`
		} `json:"user"`
	} `json:"status"`
}

func (r *Resolver) verifyProof(ctx context.Context, token string) (*Binding, claims, error) {
	deny := brokercore.ErrInvalidSession
	if len(token) == 0 || len(token) > 32768 {
		return nil, claims{}, deny
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[2] == "" {
		return nil, claims{}, deny
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, claims{}, deny
	}
	var c claims
	if json.Unmarshal(payload, &c) != nil {
		return nil, claims{}, deny
	}
	// Only single-audience broker proofs are accepted, narrower than standard JWT audience membership.
	now := r.now().Unix()
	if c.Issuer != r.config.Issuer || !exactly(c.Audience, r.config.Audience) || c.Expires <= now || c.Issued <= 0 || c.Issued > now || c.NotBefore > now || c.Expires <= c.Issued || c.Expires-c.Issued > r.config.MaxTokenLifetimeSeconds {
		return nil, claims{}, deny
	}
	k := c.Kubernetes
	if k.Pod.UID == "" || !pathSegment(k.Pod.Name) || !pathSegment(k.Namespace) || c.Subject != "system:serviceaccount:"+k.Namespace+":"+k.ServiceAccount.Name {
		return nil, claims{}, deny
	}
	var binding *Binding
	for i := range r.config.Bindings {
		b := &r.config.Bindings[i]
		if b.Namespace == k.Namespace && b.ServiceAccount == k.ServiceAccount.Name && b.ServiceAccountUID == k.ServiceAccount.UID && (b.PodUID == "" || b.PodUID == k.Pod.UID) {
			binding = b
			break
		}
	}
	if binding == nil {
		return nil, claims{}, deny
	}
	// Claims above only narrow policy; they become authenticated by a successful online TokenReview of the exact original token.
	var req review
	req.APIVersion, req.Kind = "authentication.k8s.io/v1", "TokenReview"
	req.Spec.Token, req.Spec.Audiences = token, []string{r.config.Audience}
	body, _ := json.Marshal(req)
	var verified review
	if err := r.api(ctx, http.MethodPost, "/apis/authentication.k8s.io/v1/tokenreviews", body, &verified); err != nil {
		if kubeUnavailable(err) {
			return nil, claims{}, errTokenReviewUnavailable
		}
		return nil, claims{}, deny
	}
	s := verified.Status
	if verified.APIVersion != req.APIVersion || verified.Kind != req.Kind || !s.Authenticated || s.Error != "" || !exactly(s.Audiences, r.config.Audience) || s.User.Username != c.Subject || s.User.UID != k.ServiceAccount.UID || !exactly(s.User.Extra["authentication.kubernetes.io/pod-uid"], k.Pod.UID) || !exactly(s.User.Extra["authentication.kubernetes.io/pod-name"], k.Pod.Name) {
		return nil, claims{}, deny
	}
	// TokenReview permits a deletion grace period; an explicit Pod read denies terminating or deleted pods at once and pins the object's UID.
	var pod struct {
		Metadata struct {
			UID               string  `json:"uid"`
			Name              string  `json:"name"`
			Namespace         string  `json:"namespace"`
			DeletionTimestamp *string `json:"deletionTimestamp"`
		} `json:"metadata"`
		Spec struct {
			ServiceAccountName string `json:"serviceAccountName"`
		} `json:"spec"`
	}
	if err := r.api(ctx, http.MethodGet, "/api/v1/namespaces/"+url.PathEscape(k.Namespace)+"/pods/"+url.PathEscape(k.Pod.Name), nil, &pod); err != nil {
		if kubeUnavailable(err) {
			return nil, claims{}, errPodLookupUnavailable
		}
		return nil, claims{}, deny
	}
	if pod.Metadata.UID != k.Pod.UID || pod.Metadata.Name != k.Pod.Name || pod.Metadata.Namespace != k.Namespace || pod.Metadata.DeletionTimestamp != nil || pod.Spec.ServiceAccountName != k.ServiceAccount.Name {
		return nil, claims{}, deny
	}
	if c.Expires <= r.now().Unix() {
		return nil, claims{}, deny
	}
	return binding, c, nil
}

// BindingsAuthorized reports whether every binding still resolves to an active agent with a proxy, member or admin role on its vault, without a proof; store errors are returned.
func (r *Resolver) BindingsAuthorized(ctx context.Context) (bool, error) {
	if len(r.config.Bindings) == 0 {
		return false, nil
	}
	for _, binding := range r.config.Bindings {
		a, err := r.store.GetAgentByID(ctx, binding.AgentID)
		if err != nil {
			return false, err
		}
		if a == nil || a.ID != binding.AgentID || a.Status != "active" || a.RevokedAt != nil {
			return false, nil
		}
		v, err := r.store.GetVaultByID(ctx, binding.VaultID)
		if err != nil {
			return false, err
		}
		if v == nil || v.ID != binding.VaultID {
			return false, nil
		}
		role, err := r.store.GetVaultRole(ctx, a.ID, v.ID)
		if err != nil {
			return false, err
		}
		if role != "proxy" && role != "member" && role != "admin" {
			return false, nil
		}
	}
	return true, nil
}

// ResolveForProxy verifies proof for every admission and reauthorization, with no local or session-token fallback.
func (r *Resolver) ResolveForProxy(ctx context.Context, token, vaultHint string) (*brokercore.ProxyScope, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Duration(r.config.TimeoutSeconds)*time.Second)
	defer cancel()
	binding, c, err := r.verifyProof(ctx, token)
	if err != nil {
		return nil, err
	}
	deny := brokercore.ErrInvalidSession
	if len(binding.OwnerUIDs) != 0 || binding.Service || binding.Proxy != nil || binding.TrustDomain != "" || brokercore.AttestationFrom(ctx) != "" {
		// Pool and proxy bindings are admitted only with the connection's peer address; only a proxy binding may present an attestation.
		return nil, deny
	}
	scope, err := r.grant(ctx, binding, vaultHint)
	if err != nil {
		return nil, err
	}
	// Store calls may consume the rest of the proof lifetime or timeout; never return a scope after either deadline.
	if c.Expires <= r.now().Unix() {
		return nil, deny
	}
	if ctx.Err() != nil {
		return nil, unfinished(ctx, deny)
	}
	scope.WorkloadID, scope.IdentityKind = c.Kubernetes.Pod.UID, brokercore.KindTokenReview
	return scope, nil
}

func (r *Resolver) grant(ctx context.Context, binding *Binding, vaultHint string) (*brokercore.ProxyScope, error) {
	a, err := r.store.GetAgentByID(ctx, binding.AgentID)
	if storeUnavailable(err) {
		return nil, errStoreUnavailable
	}
	if err != nil || a == nil || a.ID != binding.AgentID || a.Status != "active" || a.RevokedAt != nil {
		return nil, brokercore.ErrInvalidSession
	}
	v, err := r.store.GetVaultByID(ctx, binding.VaultID)
	if storeUnavailable(err) {
		return nil, errStoreUnavailable
	}
	if err != nil || v == nil || v.ID != binding.VaultID {
		return nil, brokercore.ErrVaultAccessDenied
	}
	if vaultHint != "" && vaultHint != v.Name {
		return nil, brokercore.ErrVaultHintMismatch
	}
	role, err := r.store.GetVaultRole(ctx, a.ID, v.ID)
	if storeUnavailable(err) {
		return nil, errStoreUnavailable
	}
	if err != nil || (role != "proxy" && role != "member" && role != "admin") {
		return nil, brokercore.ErrVaultAccessDenied
	}
	return &brokercore.ProxyScope{AgentID: a.ID, VaultID: v.ID, VaultName: v.Name, VaultRole: role}, nil
}

func exactly(values []string, value string) bool { return len(values) == 1 && values[0] == value }

// Refusals for a check the broker could not complete; each is ErrInvalidSession to callers, so no caller admits on one.
var (
	errStoreUnavailable       = brokercore.Unavailable("store_unavailable")
	errTokenReviewUnavailable = brokercore.Unavailable("token_review_unavailable")
	errPodLookupUnavailable   = brokercore.Unavailable("pod_lookup_unavailable")
	errCheckTimeout           = brokercore.Unavailable("check_timeout")
)

// unfinished is the refusal for a check whose context ended: retryable at its deadline, deny when the caller went away.
func unfinished(ctx context.Context, deny error) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return errCheckTimeout
	}
	return deny
}

// transientSQLClasses are the SQLSTATE classes of a store that did not answer: connection, login, resources and operator intervention.
var transientSQLClasses = []string{"08", "28", "53", "57"}

// storeUnavailable reports whether a store read failed without an answer: no connection, a refused login, exhausted resources or its deadline; any other error is an answer.
func storeUnavailable(err error) bool {
	if errors.Is(err, context.Canceled) {
		return false
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return len(pgErr.Code) == 5 && slices.Contains(transientSQLClasses, pgErr.Code[:2])
	}
	var netErr net.Error
	var connectErr *pgconn.ConnectError
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, driver.ErrBadConn) || errors.Is(err, sql.ErrConnDone) ||
		errors.Is(err, io.ErrUnexpectedEOF) || errors.As(err, &netErr) || errors.As(err, &connectErr) || pgconn.Timeout(err) || pgconn.SafeToRetry(err)
}

// errVerifierUnreachable is a Kubernetes API call that got no answer: a transport failure or the check's deadline.
var errVerifierUnreachable = errors.New("workload verifier did not answer")

// kubeUnavailable reports whether a Kubernetes API call failed without an answer about the workload: unreachable, throttled or a server error.
func kubeUnavailable(err error) bool {
	var refused *kubeStatusError
	if errors.As(err, &refused) {
		return refused.code == http.StatusTooManyRequests || refused.code >= 500
	}
	return errors.Is(err, errVerifierUnreachable)
}

func (r *Resolver) api(ctx context.Context, method, path string, body []byte, out any) error {
	// Re-read the broker's projected reviewer token so kubelet rotation works.
	bearer, err := readBearer(r.config.ReviewerTokenFile)
	if err != nil {
		return errors.New("workload verifier unavailable")
	}
	return kubeCall(ctx, r.client, r.config.APIServer, bearer, method, path, body, out)
}

// readBearer reads a bearer token file: one line, no whitespace inside.
func readBearer(path string) (string, error) {
	credential, err := os.ReadFile(path) //nolint:gosec // G304: an operator-configured token path, not request input
	if err != nil {
		return "", errors.New("workload verifier unavailable")
	}
	bearer := strings.TrimSpace(string(credential))
	if bearer == "" || strings.ContainsAny(bearer, "\r\n") {
		return "", errors.New("workload verifier unavailable")
	}
	return bearer, nil
}

// kubeStatusError is a Kubernetes API answer other than 200 or 201.
type kubeStatusError struct{ code int }

func (e *kubeStatusError) Error() string {
	return fmt.Sprintf("workload verifier refused request (status %d)", e.code)
}

// kubeCall makes one JSON call to a Kubernetes API server and decodes a
// bounded 200 or 201 answer into out.
func kubeCall(ctx context.Context, client *http.Client, server, bearer, method, path string, body []byte, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, server+path, bytes.NewReader(body))
	if err != nil {
		return errors.New("workload verifier unavailable")
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		if errors.Is(ctx.Err(), context.Canceled) {
			return errors.New("workload verifier call canceled")
		}
		return errVerifierUnreachable
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return &kubeStatusError{resp.StatusCode}
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil {
		return errVerifierUnreachable
	}
	if len(b) > 1<<20 || json.Unmarshal(b, out) != nil {
		return errors.New("invalid workload verifier response")
	}
	return nil
}
