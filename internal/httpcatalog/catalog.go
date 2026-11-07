// Package httpcatalog holds the operator-owned list of HTTP destinations the broker may reach for a worker; anything absent is refused.
package httpcatalog

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
)

// Entry is one binding: a host, the allowed paths and methods, where the key goes and lives in Vault, and which pools may use it.
type Entry struct {
	Name         string   `json:"name"`
	Host         string   `json:"host"`
	Port         int      `json:"port,omitempty"` // default 443
	PathPrefixes []string `json:"pathPrefixes"`
	// DeniedPaths and ReadOnlyPaths are browser-session path templates (see browser_paths.go).
	DeniedPaths   []string `json:"deniedPaths,omitempty"`
	ReadOnlyPaths []string `json:"readOnlyPaths,omitempty"`
	Methods       []string `json:"methods"`
	// Header carries the key; Scheme, when set, prefixes it ("Bearer").
	Header string `json:"header"`
	Scheme string `json:"scheme,omitempty"`
	// BasicUser sends the key as an HTTP Basic user name with an empty password; header and scheme are fixed.
	BasicUser bool `json:"basicUser,omitempty"`
	// BasicPair keeps the password broker-only; its user must be non-secret.
	// BasicPairs requires that public user to select a fixed Vault reference.
	BasicPair  bool              `json:"basicPair,omitempty"`
	BasicPairs BasicPairBindings `json:"basicPairs,omitempty"`
	// PairUserHeader names a second header in which the client also sends a Basic pair's user name, such as X-Langfuse-Public-Key.
	// Its value must be the stored user name; basicPair entries only.
	PairUserHeader string `json:"pairUserHeader,omitempty"`
	// Placeholder is what a worker may send in Header instead of the key, so
	// SDKs that insist on a key still work. Only BasicPairs requires Header.
	Placeholder string `json:"placeholder"`
	Key         KeyRef `json:"key"`
	// ClientCertificate, header entries only, is a Vault certificate and key presented to the upstream in the TLS handshake; neither reaches the worker.
	ClientCertificate *ClientCertificateRef `json:"clientCertificate,omitempty"`
	// ClientCredentials, header entries only, makes the key an access token minted from an OAuth client in Vault.
	ClientCredentials *ClientCredentialsBinding `json:"clientCredentials,omitempty"`
	Pools             []string                  `json:"pools"`
	// ForwardHeaders are extra request headers the vendor needs; every other caller header outside a fixed safe set is dropped.
	ForwardHeaders   []string `json:"forwardHeaders,omitempty"`
	MaxRequestBytes  int64    `json:"maxRequestBytes,omitempty"`  // default 1 MiB; git 1 GiB (a push)
	MaxResponseBytes int64    `json:"maxResponseBytes,omitempty"` // default 32 MiB; git and github-api 4 GiB
	// RequestFields limit request parameters to listed values; header entries only, and a Slack entry must limit channel.
	RequestFields []RequestField `json:"requestFields,omitempty"`
	// RequestHeaders limit request headers to listed values; header entries only, and a groundcover MCP entry should limit X-Backend-Id.
	RequestHeaders []RequestHeader `json:"requestHeaders,omitempty"`
	// Transcript marks a model API: its bodies quote whatever the agent read, so a decoy credential found only in one is not treated as presented. Header entries only.
	Transcript bool `json:"transcript,omitempty"`
	// Kind selects a derived binding: "git" (smart-HTTP), "github-api" (pull request work and the reads and writes the repositories grant, via an installation token minted per repository), "browser-session" (see BrowserSessionBinding).
	Kind           string                 `json:"kind,omitempty"`
	Git            *GitBinding            `json:"git,omitempty"`
	Postgres       *PostgresBinding       `json:"postgres,omitempty"`
	Memgraph       *MemgraphBinding       `json:"memgraph,omitempty"`
	BrowserSession *BrowserSessionBinding `json:"browserSession,omitempty"`
	GCP            *GCPBinding            `json:"gcp,omitempty"`
	// HTTP2 lets workers speak HTTP/2 to the host, which gRPC needs; header and gcp entries only, and every entry on one host and port must agree.
	HTTP2 bool `json:"http2,omitempty"`
	// Tier is T0 (default; any worker on the pool), T1 (a verified person in every Requires group) or T2 (T1 with time-boxed groups). Requires lists Entra group object IDs, mandatory for T1 and T2.
	Tier     string   `json:"tier,omitempty"`
	Requires []string `json:"requires,omitempty"`
}

// GitBinding names the GitHub App installation and the repositories a pool may reach, read-only or read-write.
type GitBinding struct {
	AppID          int64     `json:"appID"`
	InstallationID int64     `json:"installationID"`
	Repos          []GitRepo `json:"repos"`
	// MaxPushCommandBytes, git entries only, bounds the push command list the broker reads (default DefaultMaxPushCommandBytes, at most maxRequestBytes); a longer push is refused.
	MaxPushCommandBytes int64 `json:"maxPushCommandBytes,omitempty"`
}

// DefaultMaxPushCommandBytes is 16 MiB, about 75,000 refs at once.
const DefaultMaxPushCommandBytes = 16 << 20

// GitRepo is one repository. RefPrefixes limit which refs a push may touch for every pool; PoolRefPrefixes add per-pool ones (see PushPrefixes).
// Once either is listed a pool pushes only under shared and its own prefixes; {requester}/ (RequesterToken) confines each requester to its own segment.
type GitRepo struct {
	Repo            string       `json:"repo"` // owner/name
	Access          string       `json:"access"`
	RefPrefixes     []string     `json:"refPrefixes,omitempty"`
	PoolRefPrefixes PoolPrefixes `json:"poolRefPrefixes,omitempty"`
	// Operations (github-api entries only) are what the pool may do here, from githubOperations; unset means DefaultGitHubOperations.
	Operations []string `json:"operations,omitempty"`
	// PullRequestPrefixes are head branch names (refs/heads/ removed) of pull requests the pool may also comment on, label, edit and mark ready, besides its own. It never opens one from them.
	PullRequestPrefixes []string `json:"pullRequestPrefixes,omitempty"`
	// PoolPullRequestPrefixes are PullRequestPrefixes for one pool each.
	PoolPullRequestPrefixes PoolPrefixes `json:"poolPullRequestPrefixes,omitempty"`
	Labels                  []string     `json:"labels,omitempty"`
	// DispatchEvents are the only repository_dispatch event types dispatch may send; the run uses the default branch and its client_payload pull request must be in the pool's reach.
	DispatchEvents []string `json:"dispatchEvents,omitempty"`
	// PoolOperations narrow Operations per pool; an unlisted pool gets the repository's operations, except a cursor-automation pool, which gets none until listed (see forPool).
	PoolOperations PoolOperations `json:"poolOperations,omitempty"`
}

type PoolPrefixes map[string][]string

type PoolOperations map[string][]string

func (p *PoolOperations) UnmarshalJSON(data []byte) error {
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return errors.New("poolOperations may not be null; list each pool with its operations, or leave the field out")
	}
	var m map[string][]string
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	*p = m
	return nil
}

// errNullPoolPrefixes refuses null, which decodes as absent and would fail open: a repository listing no push prefix would let every pool push anywhere.
var errNullPoolPrefixes = errors.New("poolRefPrefixes and poolPullRequestPrefixes may not be null; list each pool with its prefixes, or leave the field out")

func (p *PoolPrefixes) UnmarshalJSON(data []byte) error {
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return errNullPoolPrefixes
	}
	var m map[string][]string
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	*p = m
	return nil
}

var DefaultGitHubOperations = []string{"pr.open", "pr.read", "pr.comment"}

// githubOperations is the reviewed vocabulary of github-api operations and the token scope each needs; routes are in githubAPIRoutes.
var githubOperations = map[string]string{
	// graphql opts a repository into POST /graphql; each field still needs its own operation. A broker without it drops any entry listing it, so deploy the broker first.
	"graphql":          "pull-requests",
	"pr.open":          "pull-requests",  // POST /pulls, head under the pool's push prefixes
	"pr.read":          "pull-requests",  // GET /pulls/{n}, GET /issues/{n}/labels, GET /issues/comments/{id}
	"pr.list":          "pull-requests",  // GET /pulls, GET /issues/{n}/comments
	"pr.comment":       "pull-requests",  // POST comments and review replies on a pull request in reach
	"pr.edit":          "pull-requests",  // PATCH a body, or the App's own comment, in reach
	"pr.label":         "pull-requests",  // POST /issues/{n}/labels, listed labels only, in reach
	"pr.ready":         "update-branch",  // mark a draft in reach ready: one GraphQL mutation, which GitHub refuses without contents write
	"dispatch":         "contents-write", // POST /dispatches, listed event types only
	"actions.read":     "actions",        // workflow runs, jobs, logs and artifacts; a commit's check runs and statuses
	"deployments.read": "deployments",    // deployments and their statuses

	// CI restarts act only on a branch the pool may push to, for a requester the git entry authorizes (see GitHubAPIMatch).
	"pr.update_branch":     "update-branch", // PUT /pulls/{n}/update-branch merges the base into the head
	"actions.rerun":        "actions-write", // POST /actions/runs/{id}/rerun, a push or pull_request run
	"actions.rerun_failed": "actions-write", // POST /actions/runs/{id}/rerun-failed-jobs, likewise
}

// githubReadOperations change nothing on GitHub; an Automation without a write grant uses these and no other.
var githubReadOperations = map[string]bool{
	"pr.read": true, "pr.list": true, "actions.read": true, "deployments.read": true, "graphql": true,
}

// GitHubOperationWrites is true for every operation outside githubReadOperations, so a new operation is a write until listed as a read.
func GitHubOperationWrites(op string) bool { return !githubReadOperations[op] }

// githubRouteScopes are the scopes an operation's routes need besides its own; actions.read also reads a commit's check runs and statuses.
var githubRouteScopes = map[string][]string{
	"actions.read": {"checks", "statuses"},
}

// PushPrefixes returns the ref prefixes pool may push to: the shared RefPrefixes, then its own. limited is false when none are listed for any pool, so only branch protection holds a push.
func (r GitRepo) PushPrefixes(pool string) (prefixes []string, limited bool) {
	prefixes = append(append([]string(nil), r.RefPrefixes...), r.PoolRefPrefixes[pool]...)
	return prefixes, len(r.RefPrefixes) > 0 || len(r.PoolRefPrefixes) > 0
}

func (r GitRepo) pullRequestHeads(pool string) []string {
	return append(append([]string(nil), r.PullRequestPrefixes...), r.PoolPullRequestPrefixes[pool]...)
}

func (r GitRepo) operations() []string {
	if r.Operations == nil {
		return DefaultGitHubOperations
	}
	return r.Operations
}

func (r GitRepo) Allows(op string) bool { return contains(r.operations(), op) }

// forPool returns the repository as pool sees it, with Operations narrowed to its poolOperations line, or none for an unlisted cursor-automation pool.
func (c Catalog) forPool(r GitRepo, pool string) GitRepo {
	ops, listed := r.PoolOperations[pool]
	p, defined := c.Pool(pool)
	switch {
	case listed:
		r.Operations = append([]string{}, ops...)
	case defined && p.Identity == IdentityCursorAutomation:
		r.Operations = []string{}
	}
	return r
}

func (r GitRepo) GrantsScope(scope string) bool { return r.grantsScope(scope) }

func (r GitRepo) grantsScope(scope string) bool {
	for _, op := range r.operations() {
		if githubOperations[op] == scope || contains(githubRouteScopes[op], scope) {
			return true
		}
	}
	return false
}

type KeyRef struct {
	Mount string `json:"mount"`
	Path  string `json:"path"`
	Field string `json:"field"`
}

type Catalog struct {
	entries     []Entry
	pools       []Pool
	harnesses   []Harness
	automations map[string]Automation // by id
	// signedAgents maps a signed-token harness and subject (joined by NUL) to the Automation id that claims it.
	signedAgents map[string]string
}

type Pool struct {
	Name           string `json:"name"`
	Namespace      string `json:"namespace"`
	ServiceAccount string `json:"serviceAccount"`
	// Identity says who can stand behind a request: "none" (default), "claude-session", "cursor-session", "attested-person" (a shared proxy's attestation naming the Pod's requester), "cursor-automation" (decided per listed Automation) or "workload" (CI: Entitlements, never a person).
	Identity string `json:"identity,omitempty"`
	// Ceiling is the highest tier the pool may reach (default T0). "external" is below T0: the pool reaches nothing and no entry may grant it.
	Ceiling      string   `json:"ceiling,omitempty"`
	CCPoolID     string   `json:"ccpoolID,omitempty"`
	BaseGroup    string   `json:"baseGroup,omitempty"`
	Entitlements []string `json:"entitlements,omitempty"`
	// AutomationRunsAsPerson, cursor-session only, serves a Cursor Automation's run as the person its token names, with this pool's entries and that person's groups. Off by default: the run is refused (automation_on_person_pool).
	AutomationRunsAsPerson bool `json:"automationRunsAsPerson,omitempty"`

	harness         *Harness              // the declared profile naming this pool, if any: its Kubernetes harness, else its static-token one
	staticHarness   *Harness              // the pool's static-token harness, if any
	signedHarnesses []Harness             // the pool's signed-token harnesses
	automations     map[string]Automation // the catalog's Automations, on a cursor-automation pool
}

func (c Catalog) Pool(name string) (Pool, bool) {
	for _, p := range c.pools {
		if p.Name == name {
			return p, true
		}
	}
	return Pool{}, false
}

type PostgresBinding struct {
	Database string `json:"database"`
	Mount    string `json:"mount"`
	Role     string `json:"role"`
	SSLMode  string `json:"sslmode,omitempty"`  // default verify-full
	MaxConns int    `json:"maxConns,omitempty"` // 0: the broker's default budget
	// Access is "read" (default) or "write", and must be "write" exactly when the role is a -readwrite role.
	Access string `json:"access,omitempty"`
	// CA, when set, is the only trust for the database's certificate: public PEM certificates, each a CA or the server's own self-signed certificate.
	CA string `json:"ca,omitempty"`
	// ServerName is the name the certificate must carry when it is not the host.
	ServerName string `json:"serverName,omitempty"`
}

func (c Catalog) Current() Catalog { return c }

func (c Catalog) Pools() []Pool { return append([]Pool(nil), c.pools...) }

var (
	ErrUnlisted = errors.New("destination not in catalog")
	ErrMethod   = errors.New("method not allowed for destination")
	ErrPool     = errors.New("pool not granted destination")
	ErrReadOnly = errors.New("repository binding is read-only")
	repoPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,38}/[a-z0-9._-]{1,100}$`)
	refPattern  = regexp.MustCompile(`^refs/[A-Za-z0-9._/-]+$`)
	// branchPrefixPattern is a pull request head prefix: a branch name ending in "/".
	branchPrefixPattern = regexp.MustCompile(`^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*/$`)
	labelPattern        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._:/-]{0,49}$`)
	eventPattern        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`)
	dnsLabel            = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	pgName              = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,62}$`)
	vaultSegment        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	placeholder         = regexp.MustCompile(`^__vault_[A-Z][A-Z0-9_]*__$`)
	hostPattern         = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)
	tokenPattern        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]*$`)
	idPattern           = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	kvPattern           = regexp.MustCompile(`^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$`)
	// Shapes that are safe inside a Vault policy path.
	vendorKeyPath = regexp.MustCompile(`^vendors(/[a-z0-9][a-z0-9_-]*)+$`)
	vaultMount    = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*(/[a-z0-9][a-z0-9_-]*)*$`)
)

func ValidMount(mount string) bool { return len(mount) <= 127 && vaultMount.MatchString(mount) }

// Environment (AGENT_VAULT_CATALOG_ENVIRONMENT, such as staging), when set, requires every database role to follow the role naming rule (SetRolePattern), or its "gatehouse-" prefixed variant.
var Environment atomic.Value // string

func environment() string {
	env, _ := Environment.Load().(string)
	return env
}

// rolesWithoutEnvironment keeps the plain role rule when no environment is set; only the e2e build and tests set it, so the rule cannot be skipped by omission.
var rolesWithoutEnvironment bool

func validRole(role string) bool {
	env := environment()
	if env == "" {
		return rolesWithoutEnvironment && vaultSegment.MatchString(role)
	}
	return vaultSegment.MatchString(role) && environmentRole(env).MatchString(role)
}

var allowedMethods = map[string]bool{"GET": true, "HEAD": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true}

// Headers a caller may never set, because they change routing, method, identity or framing.
var reservedHeaders = map[string]bool{
	"Host": true, "Connection": true, "Proxy-Authorization": true, "Proxy-Connection": true, "Te": true, "Trailer": true,
	"Transfer-Encoding": true, "Upgrade": true, "Keep-Alive": true, "Content-Length": true, "Content-Encoding": true,
	"Cookie": true, "Forwarded": true, "X-Forwarded-For": true, "X-Forwarded-Host": true, "X-Forwarded-Proto": true,
	"X-Http-Method-Override": true, "X-Method-Override": true, "X-Original-Url": true, "X-Rewrite-Url": true,
	"Authorization": true, "X-Api-Key": true, "Accept-Encoding": true,
}

const maxCatalogFile = 256 << 20

func Load(path string) (Catalog, error) {
	f, err := os.Open(path)
	if err != nil {
		return Catalog{}, errors.New("cannot open HTTP catalog")
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxCatalogFile+1))
	if err != nil || len(data) > maxCatalogFile {
		return Catalog{}, errors.New("HTTP catalog exceeds size limit or cannot be read")
	}
	return Parse(data)
}

func Parse(data []byte) (Catalog, error) {
	var file struct {
		Harnesses   []Harness    `json:"harnesses,omitempty"`
		Pools       []Pool       `json:"pools,omitempty"`
		Entries     []Entry      `json:"entries"`
		Automations []Automation `json:"automations,omitempty"`
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&file); err != nil {
		return Catalog{}, fmt.Errorf("invalid HTTP catalog: %w", err)
	}
	if d.More() {
		return Catalog{}, errors.New("trailing HTTP catalog data")
	}
	if len(file.Entries) == 0 {
		return Catalog{}, errors.New("HTTP catalog has no entries")
	}
	poolNames := map[string]bool{}
	pools := map[string]Pool{}
	for _, pool := range file.Pools {
		if !idPattern.MatchString(pool.Name) || poolNames[pool.Name] || !dnsLabel.MatchString(pool.Namespace) || !dnsLabel.MatchString(pool.ServiceAccount) {
			return Catalog{}, fmt.Errorf("invalid or duplicate pool %q", pool.Name)
		}
		if err := pool.validate(); err != nil {
			return Catalog{}, fmt.Errorf("pool %q: %w", pool.Name, err)
		}
		poolNames[pool.Name] = true
		pools[pool.Name] = pool
	}
	profiles, err := validateHarnesses(file.Harnesses, pools)
	if err != nil {
		return Catalog{}, err
	}
	for i := range file.Pools {
		// A static-token harness sharing the pool is kept apart (staticHarness) so the Kubernetes checks never read it.
		for _, h := range profiles[file.Pools[i].Name] {
			if h.Identity.Kind == IdentityStaticToken {
				file.Pools[i].staticHarness = &h
				continue
			}
			if h.Identity.Kind == IdentitySignedToken {
				file.Pools[i].signedHarnesses = append(file.Pools[i].signedHarnesses, h)
				continue
			}
			file.Pools[i].harness = &h
		}
		if file.Pools[i].harness == nil {
			file.Pools[i].harness = file.Pools[i].staticHarness
		}
		if file.Pools[i].harness == nil && len(file.Pools[i].signedHarnesses) > 0 {
			file.Pools[i].harness = &file.Pools[i].signedHarnesses[0]
		}
	}
	names := map[string]bool{}
	entryKinds := map[string]string{} // entry name: its kind
	users := map[KVRef]string{}
	routes := map[string]string{}
	kinds := map[string]string{}
	http2Hosts := map[string]bool{}
	gitRepos := map[string]string{}   // repository: the first git entry listing it
	perRequester := map[string]bool{} // repository: a git entry listing it has {requester} push prefixes
	for i := range file.Entries {
		e := &file.Entries[i]
		if err := e.normalize(); err != nil {
			return Catalog{}, fmt.Errorf("HTTP catalog entry %d: %w", i, err)
		}
		if names[e.Name] {
			return Catalog{}, fmt.Errorf("duplicate HTTP catalog entry %q", e.Name)
		}
		names[e.Name] = true
		entryKinds[e.Name] = e.Kind
		if err := e.validateTier(); err != nil {
			return Catalog{}, fmt.Errorf("HTTP catalog entry %q: %w", e.Name, err)
		}
		for _, pool := range e.Pools {
			if len(poolNames) > 0 && !poolNames[pool] {
				return Catalog{}, fmt.Errorf("HTTP catalog entry %q grants undefined pool %q", e.Name, pool)
			}
			if err := grantable(*e, pool, pools[pool], len(poolNames) > 0); err != nil {
				return Catalog{}, fmt.Errorf("HTTP catalog entry %q to pool %q: %w", e.Name, pool, err)
			}
		}
		hostKey := fmt.Sprintf("%s:%d", e.Host, e.Port)
		if kind, ok := kinds[hostKey]; ok && (kind != e.Kind || e.Kind == "browser-session") {
			return Catalog{}, fmt.Errorf("host %s mixes entry kinds or repeats a browser-session host", hostKey)
		}
		kinds[hostKey] = e.Kind
		if h2, ok := http2Hosts[hostKey]; ok && h2 != e.HTTP2 {
			return Catalog{}, fmt.Errorf("entries on host %s disagree on http2", hostKey)
		}
		http2Hosts[hostKey] = e.HTTP2
		if e.BrowserSession != nil {
			if other, ok := users[e.BrowserSession.User]; ok {
				return Catalog{}, fmt.Errorf("browser-session entries %q and %q share a test user", other, e.Name)
			}
			users[e.BrowserSession.User] = e.Name
			appKey := fmt.Sprintf("%s:%d", e.BrowserSession.AppHost, e.Port)
			if _, ok := kinds[appKey]; ok {
				return Catalog{}, fmt.Errorf("browser app host %s is already in the catalog", appKey)
			}
			kinds[appKey] = "browser-session-app"
		}
		if e.Git != nil {
			for _, repo := range e.Git.Repos {
				route := hostKey + " " + e.Kind + " " + repo.Repo
				if other, ok := routes[route]; ok {
					return Catalog{}, fmt.Errorf("HTTP catalog entries %q and %q share repository %s", other, e.Name, repo.Repo)
				}
				routes[route] = e.Name
				if e.Kind != "git" {
					continue
				}
				other, listed := gitRepos[repo.Repo]
				perRequester[repo.Repo] = perRequester[repo.Repo] || repo.perRequester()
				if listed && perRequester[repo.Repo] {
					return Catalog{}, fmt.Errorf("HTTP catalog entries %q and %q share repository %s: %w", other, e.Name, repo.Repo, errRequesterRepo)
				}
				if !listed {
					gitRepos[repo.Repo] = e.Name
				}
			}
		}
		for _, prefix := range e.PathPrefixes {
			route := fmt.Sprintf("%s:%d%s", e.Host, e.Port, prefix)
			if other, ok := routes[route]; ok {
				return Catalog{}, fmt.Errorf("HTTP catalog entries %q and %q share a route", other, e.Name)
			}
			routes[route] = e.Name
		}
	}
	for _, e := range file.Entries {
		if crossings := pullRequestCrossings(e, file.Entries); len(crossings) > 0 {
			return Catalog{}, fmt.Errorf("HTTP catalog entries %q and %q: %w", e.Name, crossings[0].git, crossings[0].err)
		}
	}
	automations, err := indexAutomations(file.Automations, entryKinds)
	if err != nil {
		return Catalog{}, err
	}
	signedAgents, err := indexSignedAgents(automations, file.Harnesses)
	if err != nil {
		return Catalog{}, err
	}
	for i := range file.Pools {
		if file.Pools[i].Identity == IdentityCursorAutomation {
			file.Pools[i].automations = automations
		}
	}
	return Catalog{entries: file.Entries, pools: file.Pools, harnesses: file.Harnesses, automations: automations, signedAgents: signedAgents}, nil
}

func (e *Entry) normalize() error {
	if !idPattern.MatchString(e.Name) {
		return errors.New("name must be a short identifier")
	}
	if e.BasicPairs != nil {
		if err := e.normalizeBasicPairs(); err != nil {
			return err
		}
	}
	e.Host = strings.ToLower(e.Host)
	labels := strings.Split(e.Host, ".")
	if !hostPattern.MatchString(e.Host) || len(e.Host) > 253 || strings.Trim(labels[len(labels)-1], "0123456789") == "" {
		return errors.New("host must be an exact DNS name; wildcards and IPs are not allowed")
	}
	if e.Port == 0 {
		e.Port = 443
		if e.Kind == "postgres" {
			e.Port = 5432
		}
		if e.Kind == "memgraph" {
			e.Port = 7687
		}
	}
	if e.Port < 1 || e.Port > 65535 {
		return errors.New("invalid port")
	}
	if e.Kind != "" && len(e.RequestFields) > 0 {
		return errors.New("requestFields apply to header entries only")
	}
	if e.Kind != "" && len(e.RequestHeaders) > 0 {
		return errors.New("requestHeaders apply to header entries only")
	}
	if e.Kind != "" && e.Transcript {
		return errors.New("transcript applies to header entries only")
	}
	if e.Kind != "browser-session" && (len(e.DeniedPaths) > 0 || len(e.ReadOnlyPaths) > 0) {
		return errors.New("deniedPaths and readOnlyPaths apply to browser-session entries only")
	}
	if e.HTTP2 && e.Kind != "" && e.Kind != "gcp" {
		return errors.New("http2 applies to header and gcp entries only")
	}
	if e.ClientCertificate != nil && (e.Kind != "" || !e.ClientCertificate.valid()) {
		prefix, _ := keyPath()
		return fmt.Errorf("clientCertificate applies to header entries only and needs a KV mount and a path under %s/", prefix)
	}
	if e.ClientCredentials != nil && (e.Kind != "" || !e.HeaderCredential()) {
		return errors.New("clientCredentials applies to header entries with a header only")
	}
	switch e.Kind {
	case "postgres":
		return e.normalizePostgres()
	case "memgraph":
		return e.normalizeMemgraph()
	case "git":
		return e.normalizeGit()
	case "github-api":
		if e.Git != nil && e.Git.MaxPushCommandBytes != 0 {
			return errors.New("maxPushCommandBytes is for git entries only")
		}
		// A write body is small JSON; a response keeps the git default, since downloads stream hundreds of MiB.
		if e.MaxRequestBytes == 0 {
			e.MaxRequestBytes = 1 << 20
		}
		if err := e.normalizeGit(); err != nil {
			return err
		}
		for _, r := range e.Git.Repos {
			if r.Access != "write" || len(r.RefPrefixes) > 0 || len(r.PoolRefPrefixes) > 0 {
				return fmt.Errorf("github-api repository %s must have access write (open pull requests) and no ref prefixes", r.Repo)
			}
			if err := r.normalizeGitHubAPI(e.Pools); err != nil {
				return err
			}
		}
		if e.MaxRequestBytes > 16<<20 {
			return errors.New("github-api request limit is at most 16 MiB")
		}
		return nil
	case "browser-session":
		return e.normalizeBrowser()
	case "gcp":
		return e.normalizeGCP()
	case "":
		if e.Git != nil || e.Postgres != nil || e.Memgraph != nil || e.BrowserSession != nil || e.GCP != nil {
			return errors.New("git, postgres, memgraph, browserSession or gcp settings require their kind")
		}
	default:
		return fmt.Errorf("unknown kind %q", e.Kind)
	}
	if len(e.PathPrefixes) == 0 {
		return errors.New("at least one path prefix is required")
	}
	for _, p := range e.PathPrefixes {
		if !strings.HasPrefix(p, "/") || strings.ContainsAny(p, "?#%*{} \\;") || strings.Contains(p, "//") || strings.Contains(p, "/..") || strings.Contains(p, "/./") || strings.Contains(p, "__") {
			return fmt.Errorf("invalid path prefix %q", p)
		}
	}
	if len(e.Methods) == 0 {
		return errors.New("at least one method is required")
	}
	for i, m := range e.Methods {
		e.Methods[i] = strings.ToUpper(m)
		if !allowedMethods[e.Methods[i]] {
			return fmt.Errorf("method %q not supported", m)
		}
	}
	if e.HeaderCredential() {
		if err := e.normalizeHeaderCredential(); err != nil {
			return err
		}
	} else if e.ClientCertificate == nil || e.Scheme != "" || e.BasicUser || e.BasicPair || e.Placeholder != "" || e.Key != (KeyRef{}) {
		return errors.New("a header entry needs a header, placeholder and key, unless it has a clientCertificate and none of them")
	}
	if len(e.Pools) == 0 {
		return errors.New("at least one pool is required")
	}
	for _, pool := range e.Pools {
		if !idPattern.MatchString(pool) {
			return fmt.Errorf("invalid pool %q", pool)
		}
	}
	for i, h := range e.ForwardHeaders {
		e.ForwardHeaders[i] = http.CanonicalHeaderKey(h)
		if !tokenPattern.MatchString(h) || reservedHeaders[e.ForwardHeaders[i]] || e.ForwardHeaders[i] == e.Header {
			return fmt.Errorf("forward header %q not allowed", h)
		}
	}
	if e.PairUserHeader != "" {
		h := e.PairUserHeader
		e.PairUserHeader = http.CanonicalHeaderKey(h)
		if !e.BasicPair || !tokenPattern.MatchString(h) || reservedHeaders[e.PairUserHeader] || e.ForwardsHeader(e.PairUserHeader) {
			return errors.New("pairUserHeader needs basicPair and a plain header name that is neither reserved nor otherwise forwarded")
		}
	}
	if e.MaxRequestBytes == 0 {
		e.MaxRequestBytes = 1 << 20
	}
	if e.MaxResponseBytes == 0 {
		e.MaxResponseBytes = 32 << 20
	}
	if e.MaxRequestBytes < 0 || e.MaxRequestBytes > 16<<20 || e.MaxResponseBytes < 1 || e.MaxResponseBytes > 1<<30 {
		return errors.New("size limits out of range")
	}
	if err := e.normalizeRequestFields(); err != nil {
		return err
	}
	if err := e.normalizeRequestHeaders(); err != nil {
		return err
	}
	sort.Strings(e.Methods)
	return nil
}

func (e *Entry) HeaderCredential() bool { return e.Header != "" }

func (e *Entry) normalizeHeaderCredential() error {
	e.Header = http.CanonicalHeaderKey(e.Header)
	if !tokenPattern.MatchString(e.Header) || (reservedHeaders[e.Header] && e.Header != "Authorization" && e.Header != "X-Api-Key") {
		return errors.New("header must be a plain header name that does not affect routing")
	}
	if e.Scheme != "" && !tokenPattern.MatchString(e.Scheme) {
		return errors.New("scheme must be a single token such as Bearer")
	}
	if e.BasicUser && (e.Header != "Authorization" || e.Scheme != "") {
		return errors.New("basicUser needs header Authorization and no scheme")
	}
	if e.BasicPair && (e.Header != "Authorization" || e.Scheme != "" || e.BasicUser) {
		return errors.New("basicPair needs header Authorization, no scheme and no basicUser")
	}
	if !placeholder.MatchString(e.Placeholder) {
		return errors.New("placeholder must look like __vault_NAME__")
	}
	if e.ClientCredentials != nil {
		return e.normalizeClientCredentials()
	}
	if prefix, _ := keyPath(); e.BasicPairs == nil && !e.Key.valid() {
		return fmt.Errorf("key needs a KV mount, a path under %s/ and a field", prefix)
	}
	return nil
}

func (e *Entry) normalizePostgres() error {
	if len(e.PathPrefixes) > 0 || len(e.Methods) > 0 || e.Header != "" || e.Scheme != "" || e.BasicUser || e.BasicPair || e.PairUserHeader != "" || e.Placeholder != "" || e.Key != (KeyRef{}) ||
		len(e.ForwardHeaders) > 0 || e.Git != nil || e.Memgraph != nil || e.BrowserSession != nil || e.GCP != nil || e.MaxRequestBytes != 0 || e.MaxResponseBytes != 0 {
		return errors.New("postgres entries take only host, port, pools and postgres settings")
	}
	p := e.Postgres
	if environment() == "" && !rolesWithoutEnvironment {
		return errors.New("database entries need AGENT_VAULT_CATALOG_ENVIRONMENT (or validate --environment), which names their roles")
	}
	if p == nil || !pgName.MatchString(p.Database) || !validRole(p.Role) {
		return errors.New("postgres entries need a database name and a Vault role")
	}
	if !ValidMount(p.Mount) {
		return errors.New("invalid Vault database mount")
	}
	writes := strings.HasSuffix(p.Role, "-readwrite")
	switch {
	case p.Access == "":
		p.Access = "read"
	case p.Access != "read" && p.Access != "write":
		return fmt.Errorf("access %q: read or write", p.Access)
	}
	if (p.Access == "write") != writes {
		return errors.New("access is write exactly when the role is a -readwrite role")
	}
	// Modes that skip the certificate check let anyone on the network path relay SCRAM and hold a session as the minted user.
	switch {
	case p.SSLMode == "":
		p.SSLMode = "verify-full"
	case p.SSLMode == "verify-full":
	case p.SSLMode == "disable" && plaintextDatabases.Load() && clusterLocal(e.Host):
	default:
		return fmt.Errorf("sslmode %q: catalog databases use verify-full", p.SSLMode)
	}
	if (p.CA != "" || p.ServerName != "") && p.SSLMode != "verify-full" {
		return errors.New("ca and serverName need sslmode verify-full")
	}
	if p.CA != "" {
		if err := validPinnedCA(p.CA); err != nil {
			return err
		}
	}
	if p.ServerName != "" && !hostPattern.MatchString(p.ServerName) {
		if _, err := netip.ParseAddr(p.ServerName); err != nil {
			return fmt.Errorf("serverName %q: a lowercase DNS name or an IP address", p.ServerName)
		}
	}
	if p.MaxConns < 0 || p.MaxConns > 1000 {
		return errors.New("maxConns out of range")
	}
	if len(e.Pools) == 0 {
		return errors.New("at least one pool is required")
	}
	for _, pool := range e.Pools {
		if !idPattern.MatchString(pool) {
			return fmt.Errorf("invalid pool %q", pool)
		}
	}
	return nil
}

// Database returns the postgres entry a pool asks for; unknown is ErrUnlisted, no grant is ErrPool.
func (c Catalog) Database(name, pool string) (*Entry, error) {
	for i := range c.entries {
		e := &c.entries[i]
		if e.Kind != "postgres" || e.Name != name {
			continue
		}
		if !contains(e.Pools, pool) {
			return e, ErrPool
		}
		return e, nil
	}
	return nil, ErrUnlisted
}

// CheckHosts requires every host to end with one of suffixes, so CI can hold the catalog inside the ranges the network policy allows.
func (c Catalog) CheckHosts(suffixes []string) error {
	for _, e := range c.entries {
		ok := false
		for _, suffix := range suffixes {
			suffix = strings.ToLower(strings.TrimSpace(suffix))
			if suffix != "" && (e.Host == strings.TrimPrefix(suffix, ".") || strings.HasSuffix(e.Host, "."+strings.TrimPrefix(suffix, "."))) {
				ok = true
			}
		}
		if !ok {
			return fmt.Errorf("entry %q host %s is outside the allowed domains", e.Name, e.Host)
		}
	}
	return nil
}

func (e *Entry) normalizeGit() error {
	if e.Postgres != nil || e.Memgraph != nil || e.BrowserSession != nil || e.GCP != nil {
		return errors.New("postgres settings require kind postgres")
	}
	if len(e.PathPrefixes) > 0 || len(e.Methods) > 0 || e.Header != "" || e.Scheme != "" || e.BasicUser || e.BasicPair || e.PairUserHeader != "" || e.Placeholder != "" || e.Key != (KeyRef{}) || len(e.ForwardHeaders) > 0 {
		return errors.New("git entries derive paths, methods and credentials; leave them unset")
	}
	g := e.Git
	if g == nil || g.AppID <= 0 || g.InstallationID <= 0 || len(g.Repos) == 0 {
		return errors.New("git entries need an App ID, an installation ID and repositories")
	}
	if len(e.Pools) == 0 {
		return errors.New("at least one pool is required")
	}
	for _, pool := range e.Pools {
		if !idPattern.MatchString(pool) {
			return fmt.Errorf("invalid pool %q", pool)
		}
	}
	seen := map[string]bool{}
	for i := range g.Repos {
		r := &g.Repos[i]
		r.Repo = strings.ToLower(r.Repo)
		if e.Kind == "git" && (r.Operations != nil || r.PoolOperations != nil || len(r.PullRequestPrefixes) > 0 || len(r.PoolPullRequestPrefixes) > 0 || len(r.Labels) > 0 || len(r.DispatchEvents) > 0) {
			return fmt.Errorf("repository %s: operations, pool operations, pull request prefixes, labels and dispatch events belong to a github-api entry", r.Repo)
		}
		if !repoPattern.MatchString(r.Repo) || strings.Contains(r.Repo, "..") || strings.HasSuffix(r.Repo, ".git") || seen[r.Repo] {
			return fmt.Errorf("invalid or duplicate repository %q", r.Repo)
		}
		seen[r.Repo] = true
		if r.Access != "read" && r.Access != "write" {
			return fmt.Errorf("repository %s access must be read or write", r.Repo)
		}
		if r.Access == "read" && (len(r.RefPrefixes) > 0 || len(r.PoolRefPrefixes) > 0) {
			return fmt.Errorf("repository %s is read-only; ref prefixes apply to pushes", r.Repo)
		}
		for _, prefix := range r.RefPrefixes {
			if !validRefPrefix(prefix) {
				return fmt.Errorf("invalid ref prefix %q", prefix)
			}
		}
		if err := checkPoolPrefixes(r.Repo, "ref prefix", r.RefPrefixes, r.PoolRefPrefixes, e.Pools, validRefPrefix); err != nil {
			return err
		}
		if err := checkPoolPrefixes(r.Repo, "pull request prefix", r.PullRequestPrefixes, r.PoolPullRequestPrefixes, e.Pools, validPullRequestPrefix); err != nil {
			return err
		}
	}
	if e.MaxRequestBytes == 0 {
		e.MaxRequestBytes = 1 << 30
	}
	if e.MaxResponseBytes == 0 {
		e.MaxResponseBytes = 4 << 30
	}
	if e.MaxRequestBytes < 1 || e.MaxRequestBytes > 2<<30 || e.MaxResponseBytes < 1 || e.MaxResponseBytes > 8<<30 {
		return errors.New("size limits out of range")
	}
	if e.Kind == "git" && g.MaxPushCommandBytes == 0 {
		g.MaxPushCommandBytes = min(DefaultMaxPushCommandBytes, e.MaxRequestBytes)
	}
	if g.MaxPushCommandBytes < 0 || g.MaxPushCommandBytes > e.MaxRequestBytes {
		return errors.New("maxPushCommandBytes is out of range: at most maxRequestBytes")
	}
	return nil
}

func validRefPrefix(prefix string) bool {
	if IsRequesterTemplate(prefix) {
		return validRequesterTemplate(prefix)
	}
	return validPlainRefPrefix(prefix)
}

func validPlainRefPrefix(prefix string) bool {
	return refPattern.MatchString(prefix) && !strings.Contains(prefix, "..") && !strings.Contains(prefix, "//")
}

func validPullRequestPrefix(prefix string) bool {
	return branchPrefixPattern.MatchString(prefix) && !strings.Contains(prefix, "..") && !strings.HasPrefix(prefix, "refs/")
}

// checkPoolPrefixes requires a present map to name at least one pool (empty reads as no limit), each pool granted by the entry, with distinct valid prefixes that overlap no other holder's.
func checkPoolPrefixes(repo, what string, shared []string, byPool map[string][]string, pools []string, valid func(string) bool) error {
	if byPool == nil {
		return overlappingPrefixes(repo, what, shared, nil)
	}
	if len(byPool) == 0 {
		return fmt.Errorf("repository %s: list a pool with its %ses, or leave the per-pool field out", repo, what)
	}
	for pool, prefixes := range byPool {
		if !contains(pools, pool) {
			return fmt.Errorf("repository %s: %s for pool %q, which the entry does not grant", repo, what, pool)
		}
		if len(prefixes) == 0 {
			return fmt.Errorf("repository %s: list at least one %s for pool %q, or leave the pool out", repo, what, pool)
		}
		seen := map[string]bool{}
		for _, prefix := range prefixes {
			if !valid(prefix) || seen[strings.ToLower(prefix)] {
				return fmt.Errorf("repository %s: invalid or duplicate %s %q for pool %q", repo, what, prefix, pool)
			}
			seen[strings.ToLower(prefix)] = true
		}
	}
	return overlappingPrefixes(repo, what, shared, byPool)
}

// overlappingPrefixes refuses a prefix that starts or is started by another holder's (ignoring case), so each pool's branches are its own.
// A {requester} prefix is compared by the part before the token and held apart from every other prefix, so each requester's branches are theirs alone.
func overlappingPrefixes(repo, what string, shared []string, byPool map[string][]string) error {
	type owned struct{ holder, prefix, spelled string } // prefix lowercased; spelled as written
	var all []owned
	own := func(pool, prefix string) owned {
		if static, ok := requesterTemplate(prefix); ok {
			return owned{pool + requesterHolder + strings.ToLower(static), strings.ToLower(static), prefix}
		}
		return owned{pool, strings.ToLower(prefix), prefix}
	}
	for _, prefix := range shared {
		all = append(all, own("", prefix)) // "" is no pool: every pool of the entry
	}
	for pool, prefixes := range byPool {
		for _, prefix := range prefixes {
			all = append(all, own(pool, prefix))
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].prefix < all[j].prefix })
	for i := range all {
		for j := i + 1; j < len(all) && strings.HasPrefix(all[j].prefix, all[i].prefix); j++ {
			if all[j].holder != all[i].holder {
				return fmt.Errorf("repository %s: %s %q (%s) overlaps %q (%s)", repo, what, all[j].spelled, holder(all[j].holder), all[i].spelled, holder(all[i].holder))
			}
		}
	}
	return nil
}

const requesterHolder = "\x00"

func holder(key string) string {
	pool, _, perRequester := strings.Cut(key, requesterHolder)
	switch {
	case pool == "" && perRequester:
		return "each requester's own, in every pool"
	case pool == "":
		return "shared by every pool"
	case perRequester:
		return "each requester's own, in pool " + strconv.Quote(pool)
	}
	return "pool " + strconv.Quote(pool)
}

// pullRequestCrossing is a github-api entry whose pull request prefixes reach a pool's push prefixes in another entry (pairedGit).
type pullRequestCrossing struct {
	git string // the git entry's name
	err error
}

// pullRequestCrossings checks each github-api repository against every git entry listing it, on any host or port: no pull request prefix may start or be started by a push prefix there that a pool it reaches does not hold.
// Otherwise comment, edit, label and ready routes would act on branches only other pools push to. A {requester} push prefix is held by no pool whole; a write repository with no push prefixes counts as a shared refs/heads/.
func pullRequestCrossings(api Entry, entries []Entry) []pullRequestCrossing {
	if api.Kind != "github-api" || api.Git == nil {
		return nil
	}
	type owned struct {
		prefix, spelled string // prefix: the ref, lowercased; spelled: as written
		push            bool
		pool            string // "": shared by every pool of its entry; for a {requester} prefix, followed by requesterHolder
	}
	pushed := func(pool, prefix string) owned {
		if static, ok := requesterTemplate(prefix); ok {
			return owned{strings.ToLower(static), prefix, true, pool + requesterHolder}
		}
		return owned{strings.ToLower(prefix), prefix, true, pool}
	}
	var out []pullRequestCrossing
	for _, r := range api.Git.Repos {
		for _, listing := range gitListings(entries, r.Repo) {
			git, gr := listing.entry, listing.repo
			var all []owned
			// A write repository that lists no push prefixes lets each pool push any branch: a shared refs/heads/.
			if gr.Access == "write" && len(gr.RefPrefixes) == 0 && len(gr.PoolRefPrefixes) == 0 {
				all = append(all, owned{"refs/heads/", "refs/heads/", true, ""})
			}
			for _, prefix := range gr.RefPrefixes {
				all = append(all, pushed("", prefix))
			}
			for pool, prefixes := range gr.PoolRefPrefixes {
				for _, prefix := range prefixes {
					all = append(all, pushed(pool, prefix))
				}
			}
			for _, prefix := range r.PullRequestPrefixes {
				all = append(all, owned{"refs/heads/" + strings.ToLower(prefix), prefix, false, ""})
			}
			for pool, prefixes := range r.PoolPullRequestPrefixes {
				for _, prefix := range prefixes {
					all = append(all, owned{"refs/heads/" + strings.ToLower(prefix), prefix, false, pool})
				}
			}
			sort.Slice(all, func(i, j int) bool { return all[i].prefix < all[j].prefix })
			crosses := func(a, b owned) bool {
				if a.push == b.push {
					return false // each field's own overlaps are checkPoolPrefixes'
				}
				push, head := a, b
				if b.push {
					push, head = b, a
				}
				holds := func(pool string) bool {
					if strings.Contains(push.pool, requesterHolder) {
						return false // each requester's own: never a whole pool's
					}
					if push.pool == "" {
						return contains(git.Pools, pool)
					}
					return pool == push.pool
				}
				if head.pool != "" {
					return !holds(head.pool)
				}
				for _, pool := range api.Pools {
					if !holds(pool) {
						return true
					}
				}
				return false
			}
		scan:
			for i := range all {
				for j := i + 1; j < len(all) && strings.HasPrefix(all[j].prefix, all[i].prefix); j++ {
					if crosses(all[i], all[j]) {
						push, head := all[i], all[j]
						if all[j].push {
							push, head = all[j], all[i]
						}
						out = append(out, pullRequestCrossing{git.Name, fmt.Errorf("repository %s: pull request prefix %q (%s) in entry %q overlaps push prefix %q (%s) in entry %q",
							r.Repo, head.spelled, holder(head.pool), api.Name, push.spelled, holder(push.pool), git.Name)})
						break scan
					}
				}
			}
		}
	}
	return out
}

type gitListing struct {
	entry *Entry
	repo  *GitRepo
}

func gitListings(entries []Entry, repo string) []gitListing {
	var out []gitListing
	for i := range entries {
		e := &entries[i]
		if e.Kind != "git" || e.Git == nil {
			continue
		}
		for j := range e.Git.Repos {
			if e.Git.Repos[j].Repo == repo {
				out = append(out, gitListing{e, &e.Git.Repos[j]})
			}
		}
	}
	return out
}

// normalizeGitHubAPI checks every operation is in the vocabulary, lists are distinct and well formed, labels come exactly with pr.label, dispatch events exactly with dispatch, and poolOperations name a granted pool and only the repository's operations.
func (r *GitRepo) normalizeGitHubAPI(pools []string) error {
	if r.Operations != nil && len(r.Operations) == 0 {
		return fmt.Errorf("repository %s: list at least one operation, or leave operations unset for the default", r.Repo)
	}
	seenOp := map[string]bool{}
	for _, op := range r.Operations {
		if _, ok := githubOperations[op]; !ok || seenOp[op] {
			return fmt.Errorf("repository %s: unknown or duplicate operation %q", r.Repo, op)
		}
		seenOp[op] = true
	}
	switch {
	case r.Allows("pr.label") != (len(r.Labels) > 0):
		return fmt.Errorf("repository %s: pr.label needs labels, and labels need pr.label", r.Repo)
	case r.Allows("dispatch") != (len(r.DispatchEvents) > 0):
		return fmt.Errorf("repository %s: dispatch needs dispatchEvents, and dispatchEvents need dispatch", r.Repo)
	case (len(r.PullRequestPrefixes) > 0 || len(r.PoolPullRequestPrefixes) > 0) && !r.Allows("pr.comment") && !r.Allows("pr.edit") && !r.Allows("pr.label") && !r.Allows("pr.ready"):
		return fmt.Errorf("repository %s: pullRequestPrefixes and poolPullRequestPrefixes need pr.comment, pr.edit, pr.label or pr.ready", r.Repo)
	}
	check := func(what string, values []string, pattern *regexp.Regexp) error {
		seen := map[string]bool{}
		for _, v := range values {
			if !pattern.MatchString(v) || strings.Contains(v, "..") || seen[strings.ToLower(v)] {
				return fmt.Errorf("repository %s: invalid or duplicate %s %q", r.Repo, what, v)
			}
			seen[strings.ToLower(v)] = true
		}
		return nil
	}
	if err := check("pull request prefix", r.PullRequestPrefixes, branchPrefixPattern); err != nil {
		return err
	}
	for _, prefix := range r.PullRequestPrefixes {
		if strings.HasPrefix(prefix, "refs/") {
			return fmt.Errorf("repository %s: pull request prefix %q is a branch name, without refs/heads/", r.Repo, prefix)
		}
	}
	if err := check("label", r.Labels, labelPattern); err != nil {
		return err
	}
	if err := check("dispatch event", r.DispatchEvents, eventPattern); err != nil {
		return err
	}
	if r.PoolOperations != nil && len(r.PoolOperations) == 0 {
		return fmt.Errorf("repository %s: list a pool with its operations, or leave poolOperations out", r.Repo)
	}
	for pool, ops := range r.PoolOperations {
		if !contains(pools, pool) {
			return fmt.Errorf("repository %s: operations for pool %q, which the entry does not grant", r.Repo, pool)
		}
		if len(ops) == 0 {
			return fmt.Errorf("repository %s: list at least one operation for pool %q, or leave the pool out", r.Repo, pool)
		}
		seen := map[string]bool{}
		for _, op := range ops {
			if _, ok := githubOperations[op]; !ok || seen[op] {
				return fmt.Errorf("repository %s: unknown or duplicate operation %q for pool %q", r.Repo, op, pool)
			}
			if !r.Allows(op) {
				return fmt.Errorf("repository %s: operation %q for pool %q is not one of the repository's operations", r.Repo, op, pool)
			}
			seen[op] = true
		}
	}
	return nil
}

type GitRequest struct {
	Entry *Entry
	Repo  GitRepo
	Write bool // receive-pack: the push service; for github-api, a POST
	// RefPrefixes are the refs a push may touch: shared prefixes and the pool's own, none when unlimited. A {requester} prefix matches nothing until ForRequester narrows it.
	RefPrefixes []string
	// Limited marks a push to a repository that limits refs: only RefPrefixes, none when ForRequester left no prefix.
	Limited bool
	// OpensPullRequest marks a request that opens a pull request; its head must start with one of HeadPrefixes.
	OpensPullRequest bool
	HeadPrefixes     []string
	// CommentsOn is the pull request a comment targets; its head must be one of HeadPrefixes.
	CommentsOn int64
	// CloneEntry is the git entry a code-returning route or CI restart relies on; the requester is authorized against it too, so a read never reaches further than a clone.
	CloneEntry *Entry
	// Route (see githubAPIRoutes), Operation and Method describe every github-api request.
	Route     string
	Operation string
	Method    string
	// PullRequest is the pull request number the path names, 0 for none.
	PullRequest int64
	// Branch is the branch or ref a read route names, as the caller sent it.
	Branch string
	// Target is the pull request a write acts on; the broker acts only when its head is under HeadPrefixes.
	// CommentID is the comment an edit or read targets: an edit must be the App's own, a read must be on a pull request in reach.
	Target    int64
	CommentID int64
	Query     string
	// Permissions is the token scope the route needs, such as "pull-requests", "contents-write", "actions", "update-branch" or "actions-write".
	Permissions string
	// Download marks a route GitHub answers with a redirect to a signed URL, which the broker follows without the token.
	Download bool
	// RestartOf is the pull request or workflow run a CI restart acts on, allowed only when its head is under HeadPrefixes (CloneEntry's push prefixes).
	RestartOf int64
}

// WriteEntries returns the entries whose write grant a request needs: the git entry for a push, the github-api entry for a write (no operation counts as a write), and for a CI restart the git entry too.
// A GraphQL request names its operations only once parsed, so its caller asks GitHubOperationWrites for each.
func (g GitRequest) WriteEntries() []string {
	if g.Entry == nil {
		return nil
	}
	switch {
	case g.Entry.Kind == "git" && g.Write:
		return []string{g.Entry.Name}
	case g.Entry.Kind == "github-api" && GitHubOperationWrites(g.Operation):
		if g.RestartOf > 0 && g.CloneEntry != nil {
			return []string{g.Entry.Name, g.CloneEntry.Name}
		}
		return []string{g.Entry.Name}
	}
	return nil
}

// GitMatch routes a request to a git entry; ok is false when the host has none. Only info/refs with one service parameter and POST to git-upload-pack or git-receive-pack exist; a push needs write access.
func (c Catalog) GitMatch(host string, port int, method, path, rawQuery, pool string) (GitRequest, bool, error) {
	host = strings.ToLower(host)
	var hostEntries []*Entry
	for i := range c.entries {
		if e := &c.entries[i]; e.Kind == "git" && e.Host == host && e.Port == port {
			hostEntries = append(hostEntries, e)
		}
	}
	if len(hostEntries) == 0 {
		return GitRequest{}, false, nil
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if !strings.HasPrefix(path, "/") || len(parts) < 3 {
		return GitRequest{}, true, ErrUnlisted
	}
	repo := strings.ToLower(parts[0] + "/" + strings.TrimSuffix(parts[1], ".git"))
	endpoint := strings.Join(parts[2:], "/")
	var write bool
	switch {
	case endpoint == "info/refs" && (rawQuery == "service=git-upload-pack" || rawQuery == "service=git-receive-pack"):
		if method != "GET" {
			return GitRequest{}, true, ErrMethod
		}
		write = rawQuery == "service=git-receive-pack"
	case (endpoint == "git-upload-pack" || endpoint == "git-receive-pack") && rawQuery == "":
		if method != "POST" {
			return GitRequest{}, true, ErrMethod
		}
		write = endpoint == "git-receive-pack"
	default:
		return GitRequest{}, true, ErrUnlisted
	}
	for _, e := range hostEntries {
		for _, r := range e.Git.Repos {
			if r.Repo != repo {
				continue
			}
			matched := GitRequest{Entry: e, Repo: r, Write: write}
			switch {
			case !contains(e.Pools, pool):
				return matched, true, ErrPool
			case write && r.Access != "write":
				return matched, true, ErrReadOnly
			}
			if write {
				if matched.RefPrefixes, matched.Limited = r.PushPrefixes(pool); matched.Limited && len(matched.RefPrefixes) == 0 {
					// The repository holds every pool to its own prefixes and this pool has none: clone and fetch only.
					return matched, true, ErrReadOnly
				}
			}
			return matched, true, nil
		}
	}
	return GitRequest{}, true, ErrUnlisted
}

// GitHubAPIMatch routes a request to a github-api entry; ok is false when the host has none. Only routes in githubAPIRoutes exist.
// A route whose operation the pool lacks is ErrPool (forPool); reviews, merging and other pushes are unlisted.
func (c Catalog) GitHubAPIMatch(host string, port int, method, path, rawQuery, pool string) (GitRequest, bool, error) {
	host = strings.ToLower(host)
	var hostEntries []*Entry
	for i := range c.entries {
		if e := &c.entries[i]; e.Kind == "github-api" && e.Host == host && e.Port == port {
			hostEntries = append(hostEntries, e)
		}
	}
	if len(hostEntries) == 0 {
		return GitRequest{}, false, nil
	}
	parts := strings.Split(path, "/")
	if len(parts) < 4 || parts[0] != "" || parts[1] != "repos" {
		return GitRequest{}, true, ErrUnlisted
	}
	routes := githubAPIRoutes(parts[4:])
	if len(routes) == 0 {
		return GitRequest{}, true, ErrUnlisted
	}
	repo := strings.ToLower(parts[2] + "/" + parts[3])
	for _, e := range hostEntries {
		for _, r := range e.Git.Repos {
			if r.Repo != repo {
				continue
			}
			var route *githubRoute
			for i := range routes {
				if routes[i].granted(r) {
					if routes[i].method == method {
						route = &routes[i]
						break
					}
					route = &githubRoute{} // the path exists here, with another method
				}
			}
			switch {
			case route == nil:
				return GitRequest{}, true, ErrUnlisted
			case route.name == "":
				return GitRequest{Entry: e, Repo: r}, true, ErrMethod
			}
			query, ok := githubQuery(rawQuery, route.query)
			if !ok {
				return GitRequest{}, true, ErrUnlisted
			}
			permissions := githubOperations[route.op]
			if route.scope != "" {
				permissions = route.scope
			}
			matched := GitRequest{Entry: e, Repo: r, Write: method != http.MethodGet, Route: route.name, Operation: route.op, Method: method,
				Query: query, Permissions: permissions, Download: route.download, CommentID: route.comment,
				PullRequest: pathPullRequest(parts[4:]), Branch: requestBranch(parts[4:], query)}
			if !contains(e.Pools, pool) {
				return matched, true, ErrPool
			}
			// The pool's own operations (forPool) decide from here.
			if r = c.forPool(r, pool); !r.Allows(route.op) {
				return matched, true, ErrPool
			}
			matched.Repo = r
			if route.code {
				// A file list or compare returns code: only for a pool whose git entry lets it clone, and a requester that entry authorizes.
				if matched.CloneEntry = c.cloneEntry(host, repo, pool); matched.CloneEntry == nil {
					return GitRequest{}, true, ErrUnlisted
				}
			}
			if route.restart > 0 {
				// A CI restart acts only on a branch the pool could push to itself, for a requester the git entry authorizes.
				git := c.cloneEntry(host, repo, pool)
				if matched.HeadPrefixes = pushPrefixes(git, repo, pool); len(matched.HeadPrefixes) == 0 {
					return GitRequest{}, true, ErrUnlisted
				}
				matched.CloneEntry, matched.RestartOf = git, route.restart
			}
			switch {
			case route.name == "open-pull":
				matched.OpensPullRequest, matched.HeadPrefixes = true, c.pushBranchPrefixes(repo, pool)
			case route.target > 0:
				matched.Target = route.target
				matched.HeadPrefixes = append(c.pushBranchPrefixes(repo, pool), r.pullRequestHeads(pool)...)
				if route.name == "comment" {
					matched.CommentsOn = route.target
				}
			case route.name == "dispatch":
				// The target comes from the body (client_payload.pr_number) and is held to the same reach as any write's.
				matched.HeadPrefixes = append(c.pushBranchPrefixes(repo, pool), r.pullRequestHeads(pool)...)
			case route.comment > 0:
				matched.HeadPrefixes = append(c.pushBranchPrefixes(repo, pool), r.pullRequestHeads(pool)...)
			}
			return matched, true, nil
		}
	}
	return GitRequest{}, true, ErrUnlisted
}

// GitHubAPIRepos returns every repository the host's entries list that the pool is granted, with head prefixes as for a REST write.
func (c Catalog) GitHubAPIRepos(host string, port int, pool string) ([]GitRequest, bool) {
	host = strings.ToLower(host)
	var out []GitRequest
	found := false
	for i := range c.entries {
		e := &c.entries[i]
		if e.Kind != "github-api" || e.Host != host || e.Port != port {
			continue
		}
		found = true
		if !contains(e.Pools, pool) {
			continue
		}
		for _, r := range e.Git.Repos {
			out = append(out, GitRequest{Entry: e, Repo: c.forPool(r, pool), Write: true, Route: "graphql", Method: http.MethodPost,
				Permissions: "pull-requests", HeadPrefixes: append(c.pushBranchPrefixes(r.Repo, pool), r.pullRequestHeads(pool)...)})
		}
	}
	return out, found
}

// GitHubAPIRepository is the GraphQL counterpart of GitHubAPIMatch; unlisted is ErrUnlisted, other pools only is ErrPool.
func (c Catalog) GitHubAPIRepository(host string, port int, repo, pool string) (GitRequest, error) {
	repo = strings.ToLower(repo)
	var listed *Entry
	for i := range c.entries {
		e := &c.entries[i]
		if e.Kind != "github-api" || e.Host != strings.ToLower(host) || e.Port != port {
			continue
		}
		for _, r := range e.Git.Repos {
			if r.Repo == repo && listed == nil {
				listed = e
			}
		}
	}
	granted, _ := c.GitHubAPIRepos(host, port, pool)
	for _, g := range granted {
		if g.Repo.Repo == repo {
			return g, nil
		}
	}
	if listed != nil {
		return GitRequest{Entry: listed}, ErrPool
	}
	return GitRequest{}, ErrUnlisted
}

// pushBranchPrefixes are the branch names a pool may push to in a repository; a pull request may come only from one, and none means none may be opened.
func (c Catalog) pushBranchPrefixes(repo, pool string) []string {
	var out []string
	for i := range c.entries {
		if e := &c.entries[i]; e.Kind == "git" && contains(e.Pools, pool) {
			out = append(out, pushPrefixes(e, repo, pool)...)
		}
	}
	return out
}

// requestBranch is the branch or ref a read route names in its path or query, else "".
func requestBranch(rest []string, query string) string {
	if len(rest) == 0 {
		return ""
	}
	values, _ := url.ParseQuery(query)
	switch {
	case len(rest) == 2 && rest[0] == "branches":
		return rest[1]
	case len(rest) == 3 && rest[0] == "rules":
		return rest[2]
	case len(rest) == 2 && rest[0] == "compare":
		_, head, _ := strings.Cut(rest[1], "...")
		return head
	case rest[0] == "contents":
		return values.Get("ref")
	case rest[0] == "actions":
		return values.Get("branch")
	}
	return ""
}

// pathPullRequest is the number in a pulls/{n} or issues/{n} path, else 0.
func pathPullRequest(rest []string) int64 {
	if len(rest) < 2 || rest[0] != "pulls" && rest[0] != "issues" {
		return 0
	}
	n, err := strconv.ParseInt(rest[1], 10, 64)
	if err != nil || n <= 0 {
		return 0
	}
	return n
}

type githubRoute struct {
	name, method, op string
	target, comment  int64    // the pull request a write acts on; the comment an edit targets
	query            []string // the query keys allowed, each at most once
	download         bool
	scope            string // the token scope when not the operation's own (githubRouteScopes)
	code             bool   // reads repository content: only for a pool that can clone the repository
	restart          int64  // the pull request or workflow run a CI restart acts on
}

func (g githubRoute) granted(r GitRepo) bool { return r.Allows(g.op) }

var (
	pageQuery       = []string{"page", "per_page"}
	pullListQuery   = []string{"base", "direction", "head", "page", "per_page", "sort", "state"}
	commentQuery    = []string{"page", "per_page", "since"}
	runQuery        = []string{"branch", "created", "event", "exclude_pull_requests", "head_sha", "page", "per_page", "status"}
	jobQuery        = []string{"filter", "page", "per_page"}
	checkRunQuery   = []string{"app_id", "check_name", "filter", "page", "per_page", "status"}
	artifactQuery   = []string{"name", "page", "per_page"}
	deploymentQuery = []string{"environment", "page", "per_page", "ref", "sha", "task"}
	rulesetQuery    = []string{"includes_parents", "page", "per_page"}
	workflowFile    = regexp.MustCompile(`^([1-9][0-9]{0,11}|[A-Za-z0-9][A-Za-z0-9_.-]{0,99}\.ya?ml)$`)
	queryValue      = regexp.MustCompile(`^[A-Za-z0-9 _.,:/+()-]{0,200}$`) // () for matrix job names such as `build (ubuntu-latest)`
	commitSHA       = regexp.MustCompile(`^[0-9a-f]{7,40}$`)
	// contentSegment is one directory or file name in a contents path: no slash, never . or ..
	contentSegment = regexp.MustCompile(`^([A-Za-z0-9_][A-Za-z0-9_.-]{0,99}|\.[A-Za-z0-9_][A-Za-z0-9_.-]{0,98})$`)
	// compareRef is one side of a compare: a branch or commit with no slash and never "..".
	compareRef = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}$`)
)

func compareRange(s string) bool {
	base, head, ok := strings.Cut(s, "...")
	return ok && compareRef.MatchString(base) && compareRef.MatchString(head) &&
		!strings.Contains(base, "..") && !strings.Contains(head, "..")
}

// contentPath reports whether every segment is a plain file or directory name.
func contentPath(segments []string) bool {
	for _, s := range segments {
		if !contentSegment.MatchString(s) {
			return false
		}
	}
	return true
}

func githubAPIRoutes(rest []string) []githubRoute {
	number := func(s string) int64 {
		if s == "" || len(s) > 12 {
			return 0
		}
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil || n <= 0 || strconv.FormatInt(n, 10) != s {
			return 0
		}
		return n
	}
	n := len(rest)
	at := func(i int) string {
		if i < n {
			return rest[i]
		}
		return ""
	}
	switch {
	case n == 0:
		return []githubRoute{{name: "read-repo", method: http.MethodGet, op: "pr.read"}}
	case n == 1 && rest[0] == "branches":
		return []githubRoute{{name: "branches", method: http.MethodGet, op: "pr.read", query: pageQuery}}
	case n == 2 && rest[0] == "branches" && compareRef.MatchString(rest[1]) && !strings.Contains(rest[1], ".."):
		return []githubRoute{{name: "branch", method: http.MethodGet, op: "pr.read"}}
	case n == 3 && rest[0] == "rules" && rest[1] == "branches" && compareRef.MatchString(rest[2]) && !strings.Contains(rest[2], ".."):
		return []githubRoute{{name: "branch-rules", method: http.MethodGet, op: "pr.read", query: pageQuery}}
	case n == 1 && rest[0] == "rulesets":
		return []githubRoute{{name: "rulesets", method: http.MethodGet, op: "pr.read", query: rulesetQuery}}
	case n == 2 && rest[0] == "rulesets" && number(rest[1]) > 0:
		return []githubRoute{{name: "ruleset", method: http.MethodGet, op: "pr.read"}}
	case n == 3 && rest[0] == "pulls" && number(rest[1]) > 0 && rest[2] == "commits":
		return []githubRoute{{name: "pull-commits", method: http.MethodGet, op: "pr.read", query: pageQuery}}
	case n >= 2 && n <= 13 && rest[0] == "contents" && contentPath(rest[1:]):
		return []githubRoute{{name: "contents", method: http.MethodGet, op: "pr.read", query: []string{"ref"}, code: true}}
	case n == 1 && rest[0] == "pulls":
		return []githubRoute{{name: "open-pull", method: http.MethodPost, op: "pr.open"},
			{name: "list-pulls", method: http.MethodGet, op: "pr.list", query: pullListQuery}}
	case n == 2 && rest[0] == "pulls" && number(rest[1]) > 0:
		return []githubRoute{{name: "read-pull", method: http.MethodGet, op: "pr.read"},
			{name: "edit-pull", method: http.MethodPatch, op: "pr.edit", target: number(rest[1])}}
	case n == 3 && rest[0] == "pulls" && number(rest[1]) > 0 && rest[2] == "files":
		return []githubRoute{{name: "pull-files", method: http.MethodGet, op: "pr.read", query: pageQuery, code: true}}
	case n == 2 && rest[0] == "compare" && compareRange(rest[1]):
		return []githubRoute{{name: "compare", method: http.MethodGet, op: "pr.read", query: pageQuery, code: true}}
	case n == 3 && rest[0] == "commits" && commitSHA.MatchString(rest[1]) && (rest[2] == "status" || rest[2] == "statuses"):
		return []githubRoute{{name: "statuses", method: http.MethodGet, op: "actions.read", query: pageQuery, scope: "statuses"}}
	case n == 3 && rest[0] == "commits" && commitSHA.MatchString(rest[1]) && rest[2] == "check-runs":
		return []githubRoute{{name: "check-runs", method: http.MethodGet, op: "actions.read", query: checkRunQuery, scope: "checks"}}
	case n == 2 && rest[0] == "check-runs" && number(rest[1]) > 0:
		return []githubRoute{{name: "check-run", method: http.MethodGet, op: "actions.read", scope: "checks"}}
	case n == 3 && rest[0] == "check-runs" && number(rest[1]) > 0 && rest[2] == "annotations":
		return []githubRoute{{name: "check-annotations", method: http.MethodGet, op: "actions.read", query: pageQuery, scope: "checks"}}
	case n == 3 && rest[0] == "pulls" && number(rest[1]) > 0 && rest[2] == "update-branch":
		return []githubRoute{{name: "update-branch", method: http.MethodPut, op: "pr.update_branch", restart: number(rest[1])}}
	case n == 3 && rest[0] == "pulls" && number(rest[1]) > 0 && rest[2] == "ready":
		// Not a GitHub REST route: a draft is marked ready only through GraphQL, so the broker makes that mutation itself.
		return []githubRoute{{name: "ready", method: http.MethodPost, op: "pr.ready", target: number(rest[1])}}
	case n == 3 && rest[0] == "issues" && number(rest[1]) > 0 && rest[2] == "comments":
		return []githubRoute{{name: "comment", method: http.MethodPost, op: "pr.comment", target: number(rest[1])},
			{name: "list-comments", method: http.MethodGet, op: "pr.list", query: commentQuery}}
	case n == 3 && rest[0] == "pulls" && number(rest[1]) > 0 && rest[2] == "comments":
		return []githubRoute{{name: "comment", method: http.MethodPost, op: "pr.comment", target: number(rest[1])}}
	case n == 5 && rest[0] == "pulls" && number(rest[1]) > 0 && rest[2] == "comments" && number(rest[3]) > 0 && rest[4] == "replies":
		return []githubRoute{{name: "comment", method: http.MethodPost, op: "pr.comment", target: number(rest[1])}}
	case n == 3 && rest[0] == "issues" && rest[1] == "comments" && number(rest[2]) > 0:
		// Reading a comment by id is pr.read; like an edit it is held to a comment on a pull request in reach.
		return []githubRoute{{name: "edit-comment", method: http.MethodPatch, op: "pr.edit", comment: number(rest[2])},
			{name: "read-comment", method: http.MethodGet, op: "pr.read", comment: number(rest[2])}}
	case n == 3 && rest[0] == "issues" && number(rest[1]) > 0 && rest[2] == "labels":
		// Its token holds pull requests only, so GitHub refuses a plain issue's labels.
		return []githubRoute{{name: "label", method: http.MethodPost, op: "pr.label", target: number(rest[1])},
			{name: "list-labels", method: http.MethodGet, op: "pr.read", query: pageQuery}}
	case n == 1 && rest[0] == "dispatches":
		return []githubRoute{{name: "dispatch", method: http.MethodPost, op: "dispatch"}}
	case at(0) == "actions":
		read := func(query []string) []githubRoute {
			return []githubRoute{{name: "actions", method: http.MethodGet, op: "actions.read", query: query}}
		}
		download := []githubRoute{{name: "actions-download", method: http.MethodGet, op: "actions.read", download: true}}
		switch {
		case n == 2 && rest[1] == "runs":
			return read(runQuery)
		case n == 3 && rest[1] == "runs" && number(rest[2]) > 0:
			return read([]string{"exclude_pull_requests"})
		case n == 4 && rest[1] == "runs" && number(rest[2]) > 0 && rest[3] == "jobs":
			return read(jobQuery)
		case n == 5 && rest[1] == "runs" && number(rest[2]) > 0 && rest[3] == "attempts" && number(rest[4]) > 0:
			return read([]string{"exclude_pull_requests"})
		case n == 6 && rest[1] == "runs" && number(rest[2]) > 0 && rest[3] == "attempts" && number(rest[4]) > 0 && rest[5] == "jobs":
			return read(jobQuery)
		case n == 4 && rest[1] == "runs" && number(rest[2]) > 0 && rest[3] == "artifacts":
			return read(artifactQuery)
		case n == 4 && rest[1] == "runs" && number(rest[2]) > 0 && rest[3] == "logs":
			return download
		case n == 4 && rest[1] == "runs" && number(rest[2]) > 0 && rest[3] == "rerun":
			return []githubRoute{{name: "rerun", method: http.MethodPost, op: "actions.rerun", restart: number(rest[2])}}
		case n == 4 && rest[1] == "runs" && number(rest[2]) > 0 && rest[3] == "rerun-failed-jobs":
			return []githubRoute{{name: "rerun-failed", method: http.MethodPost, op: "actions.rerun_failed", restart: number(rest[2])}}
		case n == 4 && rest[1] == "workflows" && workflowFile.MatchString(rest[2]) && rest[3] == "runs":
			return read(runQuery)
		case n == 3 && rest[1] == "workflows" && workflowFile.MatchString(rest[2]):
			return read(nil)
		case n == 3 && rest[1] == "jobs" && number(rest[2]) > 0:
			return read(nil)
		case n == 4 && rest[1] == "jobs" && number(rest[2]) > 0 && rest[3] == "logs":
			return download
		case n == 3 && rest[1] == "artifacts" && number(rest[2]) > 0:
			return read(nil)
		case n == 4 && rest[1] == "artifacts" && number(rest[2]) > 0 && rest[3] == "zip":
			return download
		}
	case n == 1 && rest[0] == "deployments":
		return []githubRoute{{name: "deployments", method: http.MethodGet, op: "deployments.read", query: deploymentQuery}}
	case n == 2 && rest[0] == "deployments" && number(rest[1]) > 0:
		return []githubRoute{{name: "deployments", method: http.MethodGet, op: "deployments.read"}}
	case n == 3 && rest[0] == "deployments" && number(rest[1]) > 0 && rest[2] == "statuses":
		return []githubRoute{{name: "deployments", method: http.MethodGet, op: "deployments.read", query: pageQuery}}
	}
	return nil
}

// githubQuery rebuilds a query string from its allowed keys; ok is false for another key, a repeated key or a value outside queryValue.
func githubQuery(raw string, allowed []string) (string, bool) {
	if raw == "" {
		return "", true
	}
	values, err := url.ParseQuery(raw)
	if err != nil {
		return "", false
	}
	for key, v := range values {
		if !contains(allowed, key) || len(v) != 1 || !queryValue.MatchString(v[0]) {
			return "", false
		}
	}
	return values.Encode(), true
}

// Match returns the entry for a request by the longest path prefix on a segment boundary: ErrUnlisted for a host or path outside the catalog, ErrMethod for another method, ErrPool only after the route matched.
func (c Catalog) Match(host string, port int, method, path, pool string) (*Entry, error) {
	host = strings.ToLower(host)
	var best *Entry
	bestLen := -1
	for i := range c.entries {
		e := &c.entries[i]
		if e.Kind != "" || e.Host != host || e.Port != port {
			continue
		}
		for _, prefix := range e.PathPrefixes {
			if pathWithin(path, prefix) && len(prefix) > bestLen {
				best, bestLen = e, len(prefix)
			}
		}
	}
	if best == nil {
		return nil, ErrUnlisted
	}
	if !contains(best.Methods, method) {
		return best, ErrMethod
	}
	if !contains(best.Pools, pool) {
		return best, ErrPool
	}
	return best, nil
}

// PathPrefix is the longest listed path prefix on host and port that path falls within, or "" when none does.
func (c Catalog) PathPrefix(host string, port int, path string) string {
	host = strings.ToLower(host)
	var best string
	for i := range c.entries {
		e := &c.entries[i]
		if databaseKind(e.Kind) || e.Host != host || e.Port != port {
			continue
		}
		for _, prefix := range e.PathPrefixes {
			if pathWithin(path, prefix) && len(prefix) > len(best) {
				best = prefix
			}
		}
	}
	return best
}

func (c Catalog) HasHost(host string, port int) bool {
	host = strings.ToLower(host)
	for _, e := range c.entries {
		if !databaseKind(e.Kind) && e.Host == host && e.Port == port {
			return true
		}
		if e.BrowserSession != nil && e.BrowserSession.AppHost == host && e.Port == port {
			return true
		}
	}
	return false
}

// HasHostForPool reports whether an entry granted to pool names host and port, so a caller learns nothing about other pools' hosts.
func (c Catalog) HasHostForPool(host string, port int, pool string) bool {
	host = strings.ToLower(host)
	for _, e := range c.entries {
		if !contains(e.Pools, pool) {
			continue
		}
		if !databaseKind(e.Kind) && e.Host == host && e.Port == port {
			return true
		}
		if e.BrowserSession != nil && e.BrowserSession.AppHost == host && e.Port == port {
			return true
		}
	}
	return false
}

func (c Catalog) HTTP2Host(host string, port int) bool {
	host = strings.ToLower(host)
	for _, e := range c.entries {
		if e.HTTP2 && e.Host == host && e.Port == port {
			return true
		}
	}
	return false
}

// HasAuth0Domain reports whether host is a browser-session entry's Auth0 domain, one of the only hosts the broker's own logins may reach.
func (c Catalog) HasAuth0Domain(host string) bool {
	host = strings.ToLower(host)
	for _, e := range c.entries {
		if e.BrowserSession != nil && e.BrowserSession.Auth0.Domain == host {
			return true
		}
	}
	return false
}

// HasAutomatedAuth reports whether addr is a browser-session entry's automated-auth service, the only other place the broker's own logins may reach.
func (c Catalog) HasAutomatedAuth(addr string) bool {
	addr = strings.ToLower(addr)
	for _, e := range c.entries {
		if e.BrowserSession != nil && e.BrowserSession.AutomatedAuth != nil && e.BrowserSession.AutomatedAuth.Addr() == addr {
			return true
		}
	}
	return false
}

func (c Catalog) Entries() []Entry { return append([]Entry(nil), c.entries...) }

// GitGranted reports whether some entry still lets the installation's tokens reach repo at a scope, such as "contents-read", "contents-write", "pull-requests", "actions" or "actions-write".
func (c Catalog) GitGranted(installation int64, repo, scope string) bool {
	for _, e := range c.entries {
		if e.Git == nil || e.Git.InstallationID != installation {
			continue
		}
		for _, r := range e.Git.Repos {
			if !strings.EqualFold(r.Repo, repo) {
				continue
			}
			switch {
			case e.Kind == "git" && scope == "contents-read",
				e.Kind == "git" && scope == "contents-write" && r.Access == "write",
				e.Kind == "github-api" && r.grantsScope(scope):
				return true
			}
		}
	}
	return false
}

type GitHubScope struct {
	Repos                                                []string
	PullRequests, Actions, Deployments, Checks, Statuses bool
	ActionsWrite                                         bool
}

// GitScope returns every repository the catalog lists for an installation and which token scopes its github-api entries need.
func (c Catalog) GitScope(installation int64) GitHubScope {
	var s GitHubScope
	for _, e := range c.entries {
		if e.Git == nil || e.Git.InstallationID != installation {
			continue
		}
		for _, r := range e.Git.Repos {
			s.Repos = append(s.Repos, r.Repo)
			if e.Kind == "github-api" {
				s.PullRequests = s.PullRequests || r.grantsScope("pull-requests") || r.grantsScope("update-branch")
				s.Actions = s.Actions || r.grantsScope("actions")
				s.Deployments = s.Deployments || r.grantsScope("deployments")
				s.Checks = s.Checks || r.grantsScope("checks")
				s.Statuses = s.Statuses || r.grantsScope("statuses")
				s.ActionsWrite = s.ActionsWrite || r.grantsScope("actions-write")
			}
		}
	}
	return s
}

// cloneGitPort is git over HTTPS on 443; an entry on another port is a different endpoint.
const cloneGitPort = 443

// GitHubCloneEntry is cloneEntry for a GraphQL request that reads a pull request's files.
func (c Catalog) GitHubCloneEntry(apiHost, repo, pool string) *Entry {
	return c.cloneEntry(strings.ToLower(apiHost), strings.ToLower(repo), pool)
}

// cloneEntry returns the git entry a clone of repo would use, or nil when none or it does not grant the pool.
func (c Catalog) cloneEntry(apiHost, repo, pool string) *Entry {
	e, _ := pairedGit(c.entries, apiHost, repo)
	if e == nil || !contains(e.Pools, pool) {
		return nil
	}
	return e
}

// pairedGit returns the git entry a clone of repo would use for a github-api entry, chosen as GitMatch does: the entry on the git host (the API host without "api.") and cloneGitPort that lists the repository.
func pairedGit(entries []Entry, apiHost, repo string) (*Entry, *GitRepo) {
	gitHost := strings.TrimPrefix(apiHost, "api.")
	for i := range entries {
		e := &entries[i]
		if e.Kind != "git" || e.Git == nil || e.Host != gitHost || e.Port != cloneGitPort {
			continue
		}
		for j := range e.Git.Repos {
			if e.Git.Repos[j].Repo == repo {
				return e, &e.Git.Repos[j]
			}
		}
	}
	return nil, nil
}

// pushPrefixes are the branch names git entry e lets pool push to in repo; none when e is nil, read-only, or the pool has no prefixes.
func pushPrefixes(e *Entry, repo, pool string) []string {
	if e == nil || e.Git == nil {
		return nil
	}
	var out []string
	for _, r := range e.Git.Repos {
		if r.Repo != repo || r.Access != "write" {
			continue
		}
		prefixes, _ := r.PushPrefixes(pool)
		for _, prefix := range prefixes {
			if branch, ok := strings.CutPrefix(prefix, "refs/heads/"); ok && branch != "" {
				out = append(out, branch)
			}
		}
	}
	return out
}

func clusterLocal(host string) bool {
	return strings.HasSuffix(host, ".svc.cluster.local") || strings.HasSuffix(host, ".svc")
}

// plaintextDatabases lets a Kubernetes Service host use sslmode disable or plain http; only an e2e-tag binary can set it (plaintext_e2e.go).
var plaintextDatabases atomic.Bool

func pathWithin(path, prefix string) bool {
	if !strings.HasPrefix(path, prefix) {
		return false
	}
	return len(path) == len(prefix) || strings.HasSuffix(prefix, "/") || path[len(prefix)] == '/'
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

func (e *Entry) ForwardsHeader(name string) bool {
	switch name = http.CanonicalHeaderKey(name); name {
	case "Accept", "Accept-Language", "Content-Type", "User-Agent":
		return true
	}
	return e.forwardsGRPCHeader(name) || contains(e.ForwardHeaders, name)
}

// grpcForwardHeaders are the gRPC headers a client sets; the broker sets te and grpc-accept-encoding itself and refuses a compressed request so messages can be checked.
var grpcForwardHeaders = []string{"Grpc-Timeout"}

func (e *Entry) forwardsGRPCHeader(name string) bool {
	return e.HTTP2 && contains(grpcForwardHeaders, name)
}

var (
	groupID  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	ccpoolID = regexp.MustCompile(`^ccpool_[A-Za-z0-9]{1,120}$`)
	tierRank = map[string]int{"": 0, "T0": 0, "T1": 1, "T2": 2}
)

func ValidID(s string) bool { return idPattern.MatchString(s) }

const CeilingExternal = "external"

func (p Pool) validate() error {
	if p.Ceiling == CeilingExternal {
		if p.Identity != "" && p.Identity != "none" {
			return fmt.Errorf("an external pool has no verified identity")
		}
	} else if _, ok := tierRank[p.Ceiling]; !ok {
		return fmt.Errorf("unknown ceiling %q", p.Ceiling)
	}
	for _, g := range append(append([]string(nil), p.Entitlements...), p.BaseGroup) {
		if g != "" && !groupID.MatchString(g) {
			return fmt.Errorf("groups must be Entra object IDs")
		}
	}
	if p.AutomationRunsAsPerson && p.Identity != "cursor-session" {
		return fmt.Errorf("automationRunsAsPerson is for cursor-session pools only")
	}
	switch p.Identity {
	case "", "none":
		if p.CCPoolID != "" || len(p.Entitlements) != 0 || p.BaseGroup != "" || tierRank[p.Ceiling] > 0 {
			return fmt.Errorf("a pool with no verified identity reaches T0 only and takes no runner or workload settings")
		}
	case "claude-session":
		if !ccpoolID.MatchString(p.CCPoolID) || len(p.Entitlements) != 0 {
			return fmt.Errorf("a claude-session pool needs its ccpool_ ID and takes no fixed entitlements")
		}
	case "cursor-session":
		// No session start gate exists for Cursor, so a base group would promise nothing.
		if p.CCPoolID != "" || p.BaseGroup != "" || len(p.Entitlements) != 0 {
			return fmt.Errorf("a cursor-session pool takes no ccpool_ ID, base group or fixed entitlements")
		}
	case "attested-person":
		// The person comes from the proxy's attestation; a base group would gate nothing.
		if p.CCPoolID != "" || p.BaseGroup != "" || len(p.Entitlements) != 0 {
			return fmt.Errorf("an attested-person pool takes no ccpool_ ID, base group or fixed entitlements")
		}
	case IdentityCursorAutomation:
		if p.CCPoolID != "" || p.BaseGroup != "" || len(p.Entitlements) != 0 {
			return fmt.Errorf("a cursor-automation pool takes no ccpool_ ID, base group or fixed entitlements")
		}
	case "workload":
		if p.CCPoolID != "" || p.BaseGroup != "" || tierRank[p.Ceiling] > 1 {
			return fmt.Errorf("a workload pool takes fixed entitlements only and never reaches T2")
		}
	default:
		return fmt.Errorf("unknown identity %q", p.Identity)
	}
	return nil
}

func (e *Entry) validateTier() error {
	rank, ok := tierRank[e.Tier]
	if !ok {
		return fmt.Errorf("unknown tier %q", e.Tier)
	}
	if rank == 0 && len(e.Requires) != 0 {
		return fmt.Errorf("a T0 entry requires no groups")
	}
	if rank > 0 && len(e.Requires) == 0 {
		return fmt.Errorf("a %s entry must name its required groups", e.Tier)
	}
	// Any number of groups: the audit row records the full list, under its MAC.
	for _, g := range e.Requires {
		if !groupID.MatchString(g) {
			return fmt.Errorf("required groups must be Entra object IDs")
		}
	}
	return nil
}

// grantable is the CI rule: an entry above T0 never goes to a pool that cannot carry it, and a {requester} push prefix goes only to a pool that names who runs each request.
func grantable(e Entry, name string, p Pool, defined bool) error {
	if p.Ceiling == CeilingExternal {
		return fmt.Errorf("a pool at the external ceiling holds no entries")
	}
	if err := requesterGrantable(e, name, p, defined); err != nil {
		return err
	}
	rank := tierRank[e.Tier]
	if rank == 0 {
		return nil
	}
	if !defined {
		return fmt.Errorf("%s entries need defined pools", e.Tier)
	}
	if rank > tierRank[p.Ceiling] {
		return fmt.Errorf("%s exceeds the pool's ceiling", e.Tier)
	}
	switch p.Identity {
	case "claude-session", "cursor-session", "attested-person", IdentityCursorAutomation:
		return nil
	case "workload":
		if rank >= 2 {
			return fmt.Errorf("T2 is never granted to a workload pool")
		}
		have := map[string]bool{}
		for _, g := range p.Entitlements {
			have[g] = true
		}
		for _, g := range e.Requires {
			if !have[g] {
				return fmt.Errorf("the workload pool lacks a required group")
			}
		}
		return nil
	}
	return fmt.Errorf("%s entries are never granted to a pool with no verified identity", e.Tier)
}

func (e *Entry) Credential(v string) string {
	switch {
	case e.BasicUser:
		return "Basic " + base64.StdEncoding.EncodeToString([]byte(v+":"))
	case e.BasicPair:
		return "Basic " + base64.StdEncoding.EncodeToString([]byte(v))
	case e.Scheme != "":
		return e.Scheme + " " + v
	}
	return v
}

// CallerCredential is the value a worker sends in Header: the placeholder encoded as the key would be.
// For a Basic pair it is the placeholder as user name and password for a single Key; BasicPairs instead requires a listed public user.
func (e *Entry) CallerCredential() string {
	if e.BasicPair {
		return e.Credential(e.Placeholder + ":" + e.Placeholder)
	}
	return e.Credential(e.Placeholder)
}

// CallerPairUser is the user name when value is Basic credentials with the worker's own user and the placeholder as password; served only when it equals the stored one.
func (e *Entry) CallerPairUser(value string) (string, bool) {
	encoded, ok := strings.CutPrefix(value, "Basic ")
	if !e.BasicPair || !ok {
		return "", false
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || base64.StdEncoding.EncodeToString(decoded) != encoded {
		return "", false
	}
	user, ok := strings.CutSuffix(string(decoded), ":"+e.Placeholder)
	if !ok || user == "" || strings.Contains(user, ":") {
		return "", false
	}
	return user, true
}

// SplitPair splits a Basic pair key; false unless "user:password" with both halves set.
func SplitPair(v string) (user, password string, ok bool) {
	user, password, ok = strings.Cut(v, ":")
	return user, password, ok && user != "" && password != ""
}
