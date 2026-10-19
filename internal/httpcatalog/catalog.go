// Package httpcatalog holds the operator-owned list of HTTP destinations the
// broker may reach on a worker's behalf, and the Vault-backed keys it injects.
// A destination absent from the catalog is refused.
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

// Entry is one binding: an exact host, the paths and methods allowed on it,
// where the key goes, where the key lives in Vault, and which pools may use it.
type Entry struct {
	Name         string   `json:"name"`
	Host         string   `json:"host"`
	Port         int      `json:"port,omitempty"` // default 443
	PathPrefixes []string `json:"pathPrefixes"`
	// DeniedPaths and ReadOnlyPaths are browser-session path templates (see
	// browser_paths.go): every method is refused at or below a denied one,
	// and all but GET, HEAD and OPTIONS below a read-only one.
	DeniedPaths   []string `json:"deniedPaths,omitempty"`
	ReadOnlyPaths []string `json:"readOnlyPaths,omitempty"`
	Methods       []string `json:"methods"`
	// Header carries the key. Scheme, when set, prefixes it ("Bearer").
	Header string `json:"header"`
	Scheme string `json:"scheme,omitempty"`
	// BasicUser sends the key as an HTTP Basic user name with an empty
	// password, the way clients such as axios and curl -u encode it. The
	// header is Authorization and the scheme is Basic, so neither is set.
	BasicUser bool `json:"basicUser,omitempty"`
	// BasicPair sends the key, stored as "user:password", as HTTP Basic
	// credentials, for vendors that issue a key pair (a public and a secret
	// key). The worker sends the placeholder as both user name and password,
	// or the stored user name, which is not secret, and the placeholder as
	// the password. The header is Authorization and the scheme is Basic, so
	// neither is set.
	BasicPair bool `json:"basicPair,omitempty"`
	// PairUserHeader names a second header in which the client also sends a
	// Basic pair's user name, such as Langfuse's X-Langfuse-Public-Key. Its
	// value must be the stored user name. basicPair entries only.
	PairUserHeader string `json:"pairUserHeader,omitempty"`
	// Placeholder is what a worker may send in Header instead of the key, so
	// SDKs that insist on a key still work. The worker may also omit Header.
	Placeholder string `json:"placeholder"`
	Key         KeyRef `json:"key"`
	// ClientCertificate, header entries only, is a certificate and key in
	// Vault the broker presents to the upstream in the TLS handshake, for a
	// service that accepts only client certificates (mutual TLS). An entry
	// with one may leave out header, placeholder and key, so the worker sends
	// no credential at all. Neither the certificate nor the key reaches the
	// worker. See ClientCertificateRef.
	ClientCertificate *ClientCertificateRef `json:"clientCertificate,omitempty"`
	// Pools are the broker agent IDs of the worker pools granted this entry.
	Pools []string `json:"pools"`
	// ForwardHeaders are extra request headers the vendor needs, such as an
	// API version. Every other caller header except a fixed safe set is dropped.
	ForwardHeaders   []string `json:"forwardHeaders,omitempty"`
	MaxRequestBytes  int64    `json:"maxRequestBytes,omitempty"`  // default 1 MiB; git 1 GiB (a push)
	MaxResponseBytes int64    `json:"maxResponseBytes,omitempty"` // default 32 MiB; git and github-api 4 GiB
	// RequestFields limit request parameters to listed values (see
	// RequestField). Header entries only; a Slack entry must limit channel.
	RequestFields []RequestField `json:"requestFields,omitempty"`
	// Transcript marks a model API: its request bodies carry an agent's
	// conversation, which quotes whatever the agent read, so a decoy
	// credential found only in one is not treated as presented. Headers and
	// the URL are still checked. Header entries only.
	Transcript bool `json:"transcript,omitempty"`
	// Kind "git" makes the entry a git smart-HTTP binding, and "github-api" a
	// GitHub REST binding limited to pull request work and the reads and
	// writes its repositories grant (GitHubAPIMatch). Paths, methods and the
	// credential are derived from the kind; the
	// key is a GitHub App installation token minted per repository.
	// Kind "browser-session" lets an agent's own browser use a web app as a
	// test user; see BrowserSessionBinding.
	Kind     string           `json:"kind,omitempty"`
	Git      *GitBinding      `json:"git,omitempty"`
	Postgres *PostgresBinding `json:"postgres,omitempty"`
	// Kind "memgraph" is a graph database reached over Bolt; see
	// MemgraphBinding.
	Memgraph       *MemgraphBinding       `json:"memgraph,omitempty"`
	BrowserSession *BrowserSessionBinding `json:"browserSession,omitempty"`
	// Kind "gcp" mints a short-lived Google token per entry; see GCPBinding.
	GCP *GCPBinding `json:"gcp,omitempty"`
	// HTTP2 lets workers speak HTTP/2 to the entry's host, which gRPC needs:
	// the broker offers h2 on the tunnel and forwards over HTTP/2. Header and
	// gcp entries only, and every entry on one host and port agrees, since
	// the protocol is chosen before the first request names a path.
	HTTP2 bool `json:"http2,omitempty"`
	// Tier is T0 (data every worker allowed on the pool may read; the default),
	// T1 (a verified person in every Requires group) or T2 (T1 with
	// time-boxed groups granted through an access-request tool). Requires
	// lists Entra group object IDs and is mandatory for T1 and T2.
	Tier     string   `json:"tier,omitempty"`
	Requires []string `json:"requires,omitempty"`
}

// GitBinding names the GitHub App installation that mints tokens and the
// repositories a pool may reach, each read-only or read-write.
type GitBinding struct {
	AppID          int64     `json:"appID"`
	InstallationID int64     `json:"installationID"`
	Repos          []GitRepo `json:"repos"`
	// MaxPushCommandBytes, git entries only, bounds the command list the
	// broker reads from each push to check and audit its refs (default
	// DefaultMaxPushCommandBytes, at most the entry's maxRequestBytes); a push
	// with a longer list is refused.
	MaxPushCommandBytes int64 `json:"maxPushCommandBytes,omitempty"`
}

// DefaultMaxPushCommandBytes is the command list a push may send by default:
// 16 MiB, about 75,000 refs or more at once (a command is two object IDs and a
// ref name, under 220 bytes for most refs).
const DefaultMaxPushCommandBytes = 16 << 20

// GitRepo is one repository. RefPrefixes, when set, restrict which refs a
// push may create, update or delete (for example refs/heads/cursor/), for
// every pool of the entry. PoolRefPrefixes give each pool its own besides
// (see PushPrefixes): once a repository lists either, a pool may push only
// under the shared prefixes and its own, and a pool with none pushes nothing,
// so one entry serves many pools without any pushing to another's branches.
// A prefix ending in {requester}/ (RequesterToken) goes further: each person
// or Automation on the pool pushes only under their own branch segment there,
// so requesters sharing a pool never write to each other's branches or pull
// requests.
type GitRepo struct {
	Repo            string       `json:"repo"` // owner/name
	Access          string       `json:"access"`
	RefPrefixes     []string     `json:"refPrefixes,omitempty"`
	PoolRefPrefixes PoolPrefixes `json:"poolRefPrefixes,omitempty"`
	// The rest apply to github-api entries only.
	// Operations are what the pool may do in this repository, from the
	// vocabulary in githubOperations; unset means DefaultGitHubOperations.
	Operations []string `json:"operations,omitempty"`
	// PullRequestPrefixes are head branch names (refs/heads/ removed) of pull
	// requests in this repository that the pool may also comment on, label,
	// edit and mark ready, as its operations allow, besides its own (from its
	// push prefixes). It never opens a pull request from them.
	PullRequestPrefixes []string `json:"pullRequestPrefixes,omitempty"`
	// PoolPullRequestPrefixes are pull request prefixes for one pool of the
	// entry each, besides the shared PullRequestPrefixes.
	PoolPullRequestPrefixes PoolPrefixes `json:"poolPullRequestPrefixes,omitempty"`
	// Labels are the only labels pr.label may add.
	Labels []string `json:"labels,omitempty"`
	// DispatchEvents are the only repository_dispatch event types dispatch may
	// send. A dispatch runs workflows from the default branch, never the pool's.
	DispatchEvents []string `json:"dispatchEvents,omitempty"`
}

// PoolPrefixes maps each pool of an entry to prefixes of its own
// (poolRefPrefixes, poolPullRequestPrefixes).
type PoolPrefixes map[string][]string

// errNullPoolPrefixes refuses a per-pool field written as null, which would
// decode to no map, as if the field were absent. For poolRefPrefixes that
// fails open: a repository that lists no push prefix holds no pool to any
// branch, so an empty value rendered as null would let every pool of the
// entry push anywhere. poolPullRequestPrefixes refuses it alike.
var errNullPoolPrefixes = errors.New("poolRefPrefixes and poolPullRequestPrefixes may not be null; list each pool with its prefixes, or leave the field out")

// UnmarshalJSON decodes the map and refuses null (errNullPoolPrefixes).
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

// DefaultGitHubOperations are a github-api repository's operations when it
// lists none: open a pull request from the pool's own branch, read one, and
// comment on the pool's own.
var DefaultGitHubOperations = []string{"pr.open", "pr.read", "pr.comment"}

// githubOperations is the reviewed vocabulary a github-api repository's
// operations come from, and the token scope each needs (see GitGranted). The
// routes each one opens are in githubAPIRoutes.
var githubOperations = map[string]string{
	// graphql opts a repository into POST /graphql (graphql.go), where each
	// field still needs its own operation and pr.read also covers a pull
	// request's comments, reviews and review threads. Opt-in, so no existing
	// entry widens when the broker starts serving GraphQL. A broker without
	// it drops any entry listing it, REST routes included: deploy the broker
	// first.
	"graphql":          "pull-requests",
	"pr.open":          "pull-requests",  // POST /pulls, head under the pool's push prefixes
	"pr.read":          "pull-requests",  // GET /pulls/{n}
	"pr.list":          "pull-requests",  // GET /pulls, GET /issues/{n}/comments
	"pr.comment":       "pull-requests",  // POST comments and review replies on a pull request in reach
	"pr.edit":          "pull-requests",  // PATCH a body, or the App's own comment, in reach
	"pr.label":         "pull-requests",  // POST /issues/{n}/labels, listed labels only, in reach
	"pr.ready":         "update-branch",  // mark a draft in reach ready: one GraphQL mutation, which GitHub refuses without contents write
	"dispatch":         "contents-write", // POST /dispatches, listed event types only
	"actions.read":     "actions",        // workflow runs, jobs, logs and artifacts; a commit's check runs and statuses
	"deployments.read": "deployments",    // deployments and their statuses

	// CI restarts: each acts only on a branch of this repository the pool may
	// push to, under the push prefixes of the git entry a push would use, for
	// a requester that entry authorizes (see GitHubAPIMatch).
	"pr.update_branch":     "update-branch", // PUT /pulls/{n}/update-branch merges the base into the head
	"actions.rerun":        "actions-write", // POST /actions/runs/{id}/rerun, a push or pull_request run
	"actions.rerun_failed": "actions-write", // POST /actions/runs/{id}/rerun-failed-jobs, likewise
}

// githubRouteScopes are the scopes an operation's routes need besides its own
// (githubOperations): actions.read also reads a commit's check runs and
// statuses, the CI results GitHub keeps outside Actions, each with a token
// holding only that permission.
var githubRouteScopes = map[string][]string{
	"actions.read": {"checks", "statuses"},
}

// PushPrefixes returns the ref prefixes pool may push to in the repository:
// the shared RefPrefixes, then the pool's own. limited is false when the
// repository lists none for any pool, so only GitHub's branch protection
// holds a push; when it is true, a pool with no prefixes may push nothing.
func (r GitRepo) PushPrefixes(pool string) (prefixes []string, limited bool) {
	prefixes = append(append([]string(nil), r.RefPrefixes...), r.PoolRefPrefixes[pool]...)
	return prefixes, len(r.RefPrefixes) > 0 || len(r.PoolRefPrefixes) > 0
}

// pullRequestHeads returns the head prefixes of pull requests pool may act on
// besides its push prefixes: the shared PullRequestPrefixes, then its own.
func (r GitRepo) pullRequestHeads(pool string) []string {
	return append(append([]string(nil), r.PullRequestPrefixes...), r.PoolPullRequestPrefixes[pool]...)
}

// operations returns the repository's operations, the default when unset.
func (r GitRepo) operations() []string {
	if r.Operations == nil {
		return DefaultGitHubOperations
	}
	return r.Operations
}

// Allows reports whether a github-api repository grants an operation.
func (r GitRepo) Allows(op string) bool { return contains(r.operations(), op) }

// GrantsScope is grantsScope for callers outside the catalog (GraphQL tokens).
func (r GitRepo) GrantsScope(scope string) bool { return r.grantsScope(scope) }

// grantsScope reports whether any of the repository's operations needs a
// token scope.
func (r GitRepo) grantsScope(scope string) bool {
	for _, op := range r.operations() {
		if githubOperations[op] == scope || contains(githubRouteScopes[op], scope) {
			return true
		}
	}
	return false
}

// KeyRef locates a key in a KV version 2 secret. A new KV version rotates it.
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
}

// Pool names a set of workers by their Kubernetes identity. When a catalog
// defines pools, every entry may grant only defined pool names.
type Pool struct {
	Name           string `json:"name"`
	Namespace      string `json:"namespace"`
	ServiceAccount string `json:"serviceAccount"`
	// Identity says who can stand behind a request: "none" (the default),
	// "claude-session" (a runner session token naming the person),
	// "cursor-session" (a Cursor run's identity token naming the person),
	// "attested-person" (a shared proxy's attestation naming the person who
	// created the agent, from its Pod's requester annotation),
	// "cursor-automation" (a Cursor run's identity token naming the
	// Automation that started it, decided per listed Automation) or
	// "workload" (CI: Entitlements, never a person).
	Identity string `json:"identity,omitempty"`
	// Ceiling is the highest tier the pool may reach (default T0). "external"
	// is below T0: the pool's workers may reach nothing, and no entry may
	// grant it, until entries can be scoped to a tenant.
	Ceiling string `json:"ceiling,omitempty"`
	// CCPoolID is the runner pool a claude-session token must be issued for.
	CCPoolID string `json:"ccpoolID,omitempty"`
	// BaseGroup gates session start in the runner's spawn hook.
	BaseGroup string `json:"baseGroup,omitempty"`
	// Entitlements are a workload pool's fixed groups.
	Entitlements []string `json:"entitlements,omitempty"`
	// AutomationRunsAsPerson, cursor-session only, serves a run a Cursor
	// Automation started as the person its run token names, with this pool's
	// entries and that person's groups, as if they had started it. Off by
	// default: such a run is refused (automation_on_person_pool), so an
	// Automation gets a person's access only through what the catalog lists
	// for it, on a cursor-automation pool.
	AutomationRunsAsPerson bool `json:"automationRunsAsPerson,omitempty"`

	harness     *Harness              // the declared profile naming this pool, if any
	automations map[string]Automation // the catalog's Automations, on a cursor-automation pool
}

// Pool returns the defined pool with this name.
func (c Catalog) Pool(name string) (Pool, bool) {
	for _, p := range c.pools {
		if p.Name == name {
			return p, true
		}
	}
	return Pool{}, false
}

// PostgresBinding is a database the broker reaches with a Vault dynamic role.
type PostgresBinding struct {
	Database string `json:"database"`
	Mount    string `json:"mount"`
	Role     string `json:"role"`
	SSLMode  string `json:"sslmode,omitempty"`  // default verify-full
	MaxConns int    `json:"maxConns,omitempty"` // 0: the broker's default budget
	// Access is "read" (the default) or "write", and must be "write" exactly
	// when the role is a -readwrite role.
	Access string `json:"access,omitempty"`
	// CA, when set, is the only trust for this database's certificate: PEM
	// certificates, public, in place of the broker's bundled roots. Each is a
	// CA, or the server's own self-signed certificate (Citus makes one).
	CA string `json:"ca,omitempty"`
	// ServerName is the name the certificate must carry when it is not the
	// host, as when the host is our own DNS name for a provider's endpoint.
	ServerName string `json:"serverName,omitempty"`
}

// Current lets a fixed Catalog stand wherever a live, reloading one can.
func (c Catalog) Current() Catalog { return c }

// Pools returns the defined pools.
func (c Catalog) Pools() []Pool { return append([]Pool(nil), c.pools...) }

var (
	ErrUnlisted = errors.New("destination not in catalog")
	ErrMethod   = errors.New("method not allowed for destination")
	ErrPool     = errors.New("pool not granted destination")
	ErrReadOnly = errors.New("repository binding is read-only")
	repoPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,38}/[a-z0-9._-]{1,100}$`)
	refPattern  = regexp.MustCompile(`^refs/[A-Za-z0-9._/-]+$`)
	// branchPrefixPattern is a pull request head prefix: a branch name ending
	// in "/", so it names a directory of branches, never one branch's prefix.
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
	// The same shapes the catalog's Terraform module accepts, since these
	// strings end up in the broker's Vault policy.
	vendorKeyPath = regexp.MustCompile(`^vendors(/[a-z0-9][a-z0-9_-]*)+$`)
	vaultMount    = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*(/[a-z0-9][a-z0-9_-]*)*$`)
)

// ValidMount reports whether a Vault mount path has the policy-safe shape
// the catalog and broker settings share: lower-case segments, at most 127
// characters.
func ValidMount(mount string) bool { return len(mount) <= 127 && vaultMount.MatchString(mount) }

// Environment, when set (AGENT_VAULT_CATALOG_ENVIRONMENT, such as staging),
// requires every database role to be that environment's named role, by the
// role naming rule (SetRolePattern; by default
// <env>.<region>.<cluster>.<name>-readonly or -readwrite, or the
// Gatehouse-only role for the same connection, the same name prefixed with
// "gatehouse-").
var Environment atomic.Value // string

func environment() string {
	env, _ := Environment.Load().(string)
	return env
}

// rolesWithoutEnvironment keeps the plain role rule when no environment is
// set. Only the e2e build (whose Kind fixture role is "readonly") and this
// package's tests set it; anywhere else an unset environment refuses every
// database entry, so the role rule cannot be skipped by leaving it out.
var rolesWithoutEnvironment bool

func validRole(role string) bool {
	env := environment()
	if env == "" {
		return rolesWithoutEnvironment && vaultSegment.MatchString(role)
	}
	return vaultSegment.MatchString(role) && environmentRole(env).MatchString(role)
}

var allowedMethods = map[string]bool{"GET": true, "HEAD": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true}

// Headers a caller may never set, because they change routing, method,
// identity or framing. ForwardHeaders cannot name them either.
var reservedHeaders = map[string]bool{
	"Host": true, "Connection": true, "Proxy-Authorization": true, "Proxy-Connection": true, "Te": true, "Trailer": true,
	"Transfer-Encoding": true, "Upgrade": true, "Keep-Alive": true, "Content-Length": true, "Content-Encoding": true,
	"Cookie": true, "Forwarded": true, "X-Forwarded-For": true, "X-Forwarded-Host": true, "X-Forwarded-Proto": true,
	"X-Http-Method-Override": true, "X-Method-Override": true, "X-Original-Url": true, "X-Rewrite-Url": true,
	"Authorization": true, "X-Api-Key": true, "Accept-Encoding": true,
}

// maxCatalogFile bounds a catalog file only against a runaway read: a
// 100,000-Automation catalog is about 12 MiB.
const maxCatalogFile = 256 << 20

// Load reads a catalog file, rejecting unknown fields and trailing data.
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
		if h, ok := profiles[file.Pools[i].Name]; ok {
			file.Pools[i].harness = &h
		}
	}
	names := map[string]bool{}
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
			// A test user signs in for one entry only, so its session and
			// audit trail belong to that entry's pool.
			if other, ok := users[e.BrowserSession.User]; ok {
				return Catalog{}, fmt.Errorf("browser-session entries %q and %q share a test user", other, e.Name)
			}
			users[e.BrowserSession.User] = e.Name
			// The app host belongs to its entry alone.
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
	automations, err := indexAutomations(file.Automations, names)
	if err != nil {
		return Catalog{}, err
	}
	for i := range file.Pools {
		if file.Pools[i].Identity == IdentityCursorAutomation {
			file.Pools[i].automations = automations
		}
	}
	return Catalog{entries: file.Entries, pools: file.Pools, harnesses: file.Harnesses, automations: automations}, nil
}

func (e *Entry) normalize() error {
	if !idPattern.MatchString(e.Name) {
		return errors.New("name must be a short identifier")
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
		// A write body is small JSON. A response keeps the git default, since
		// a log or artifact download streams hundreds of MiB.
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
			if err := r.normalizeGitHubAPI(); err != nil {
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
		// Only a client certificate stands in for the header credential, and
		// then the credential's settings go with the header.
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
	sort.Strings(e.Methods)
	return nil
}

// HeaderCredential reports whether the entry injects a key into a header.
// Only a header entry with a client certificate may go without one.
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
	if prefix, path := keyPath(); !ValidMount(e.Key.Mount) || len(e.Key.Path) > 127 || !path.MatchString(e.Key.Path) || e.Key.Field == "" {
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
	// Modes that skip the certificate check let anyone on the network path
	// relay SCRAM and hold a session as the minted user.
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

// Database returns the postgres entry a pool asks for by name. An unknown
// name is ErrUnlisted; a pool without the grant is ErrPool.
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

// CheckHosts requires every host to end with one of suffixes (for example
// ".crunchybridge.com"), so CI can hold the catalog inside the ranges the
// broker's network policy allows.
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
		if e.Kind == "git" && (r.Operations != nil || len(r.PullRequestPrefixes) > 0 || len(r.PoolPullRequestPrefixes) > 0 || len(r.Labels) > 0 || len(r.DispatchEvents) > 0) {
			return fmt.Errorf("repository %s: operations, pull request prefixes, labels and dispatch events belong to a github-api entry", r.Repo)
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

// validRefPrefix is a push prefix: a ref prefix, or a branch prefix ending in
// {requester}/ (validRequesterTemplate).
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

// checkPoolPrefixes checks a repository's per-pool prefixes: a map that is
// present names at least one pool (an empty one would read as no limit), each
// pool is one the entry grants and lists distinct, valid prefixes, and no
// prefix overlaps another holder's (overlappingPrefixes).
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

// overlappingPrefixes refuses a prefix that starts, or is started by, one
// another holder holds (ignoring case): no pool's prefix may overlap another
// pool's or a shared one, so each pool's branches are its own. A {requester}
// prefix is compared by the part before the token and held apart from every
// other prefix, its own pool's and the shared ones included: each requester's
// branches are theirs alone, so no prefix anyone else holds may reach into
// them. Sorting puts every prefix right before the ones it starts, so each is
// compared only with those, never with every other prefix.
func overlappingPrefixes(repo, what string, shared []string, byPool map[string][]string) error {
	type owned struct{ holder, prefix, spelled string } // prefix lowercased; spelled as written
	var all []owned
	// own keys a prefix by what it reaches: a {requester} prefix by the part
	// before the token, under a holder of its own (see holder).
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

// requesterHolder separates a pool from the part before the token of one of
// its {requester} prefixes, in the holder overlappingPrefixes gives that
// prefix.
const requesterHolder = "\x00"

// holder names who holds a checked prefix: a pool, or "" for the shared list,
// followed for a {requester} prefix by requesterHolder.
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

// pullRequestCrossing is a github-api entry whose pull request prefixes reach
// a pool's own push prefixes in another entry, the git entry a clone of the
// repository would use (pairedGit).
type pullRequestCrossing struct {
	git string // the git entry's name
	err error
}

// pullRequestCrossings checks each repository of a github-api entry against
// every git entry listing it, on any host or port, since a pool's pull
// request reach draws on each of them (pushBranchPrefixes): no pull request
// prefix may start, or be started by, a push prefix there that a pool it
// reaches does not hold (compared as refs,
// ignoring case, as checkPoolPrefixes compares). Otherwise that pool's
// comment, edit, label and ready routes would act on pull requests from
// branches only other pools push to. A pool's own pull request prefixes reach
// that pool only, the shared ones every pool of the github-api entry. A pool's
// own push prefixes are held by that pool alone, the git entry's shared ones
// by each pool of the git entry, so a shared push prefix crosses only a pool
// outside it. A {requester} push prefix is held by each requester alone, so
// no pool holds it whole: any pull request prefix that starts, or is started
// by, the part before its token crosses, since it would let one requester act
// on another's pull requests. A write repository with no push prefixes counts
// as a shared push prefix of refs/heads/. It returns one crossing per
// repository and git entry, each naming that entry. As in overlappingPrefixes, sorting
// puts every prefix right before the ones it starts, so each is compared only
// with those.
func pullRequestCrossings(api Entry, entries []Entry) []pullRequestCrossing {
	if api.Kind != "github-api" || api.Git == nil {
		return nil
	}
	type owned struct {
		prefix, spelled string // prefix: the ref, lowercased; spelled: as written
		push            bool
		pool            string // "": shared by every pool of its entry; for a {requester} prefix, followed by requesterHolder
	}
	// pushed keys a push prefix by what it reaches, as overlappingPrefixes does.
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
			// A write repository that lists no push prefixes lets each pool of
			// the git entry push any branch: a shared push prefix of refs/heads/.
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

// gitListing is one git entry listing a repository, and its binding there.
type gitListing struct {
	entry *Entry
	repo  *GitRepo
}

// gitListings are the git entries listing repo, on any host or port: each one
// whose pools a pool's pull request reach draws on (pushBranchPrefixes).
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

// normalizeGitHubAPI checks a github-api repository's operations and their
// parameters: every operation is in the vocabulary, each list holds distinct,
// well-formed values, labels come exactly with pr.label, dispatch events
// exactly with dispatch, and pull request prefixes only with an operation
// that acts on an existing pull request.
func (r *GitRepo) normalizeGitHubAPI() error {
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
	return check("dispatch event", r.DispatchEvents, eventPattern)
}

// GitRequest is a matched git smart-HTTP request.
type GitRequest struct {
	Entry *Entry
	Repo  GitRepo
	Write bool // receive-pack: the push service; for github-api, a POST
	// RefPrefixes are, for a push, the refs it may create, update or delete:
	// the repository's shared prefixes and the pool's own (PushPrefixes);
	// none when the repository limits no ref. A {requester} prefix among them
	// matches nothing until ForRequester narrows it to one requester's.
	RefPrefixes []string
	// Limited marks a push to a repository that limits which refs a push may
	// change: only refs under RefPrefixes, and none when ForRequester left no
	// prefix (a requester with no branch segment of their own).
	Limited bool
	// OpensPullRequest marks a github-api request that opens a pull request;
	// its head must start with one of HeadPrefixes, the pool's own push
	// prefixes (none: no pull request may be opened).
	OpensPullRequest bool
	HeadPrefixes     []string
	// CommentsOn is the pull request number a comment request targets: the
	// broker comments only on a pull request whose head is one of HeadPrefixes.
	CommentsOn int64
	// CloneEntry is the git entry a code-returning route (a pull request's
	// files, a compare) or a CI restart relies on. The broker authorizes the
	// requester against it as well as Entry, so a code read never reaches
	// further than a clone, nor a CI restart further than a push.
	CloneEntry *Entry
	// The fields below describe every github-api request. Route names it
	// (see githubAPIRoutes), Operation is the repository operation that opened
	// it, and Method is the one method it was matched with.
	Route     string
	Operation string
	Method    string
	// Target is the pull request a write acts on (comment, label, body edit,
	// ready); the broker acts only when its head is under HeadPrefixes, which
	// then also holds the repository's pull request prefixes, shared and the
	// pool's own. CommentID is the comment an edit targets, which must be the
	// App's own.
	Target    int64
	CommentID int64
	// Query is the request's query string, rebuilt from its allowed keys.
	Query string
	// Permissions is the token scope the route needs: "pull-requests",
	// "contents-write" (a repository dispatch), "actions", "deployments",
	// "checks", "statuses", "update-branch" (pull requests and contents write,
	// for a branch update or marking a draft ready) or "actions-write".
	Permissions string
	// Download marks a route GitHub answers with a redirect to a signed
	// download URL, which the broker follows itself without the token.
	Download bool
	// RestartOf is the pull request (pr.update_branch) or workflow run
	// (actions.rerun, actions.rerun_failed) a CI restart acts on. The broker
	// acts only when its head is a branch of this repository under
	// HeadPrefixes, here the push prefixes of CloneEntry, the git entry a push
	// to the repository would use.
	RestartOf int64
}

// GitMatch routes a request to a git entry. ok is false when the host has no
// git entries, so the request belongs to header entries. Only the three
// smart-HTTP endpoints exist: info/refs with exactly one service parameter,
// and POST to git-upload-pack or git-receive-pack. A push needs write access.
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
					// The repository holds every pool to its own prefixes, and
					// this pool has none: it may clone and fetch only.
					return matched, true, ErrReadOnly
				}
			}
			return matched, true, nil
		}
	}
	return GitRequest{}, true, ErrUnlisted
}

// GitHubAPIMatch routes a request to a github-api entry. ok is false when the
// host has none. For a listed repository only the routes in githubAPIRoutes
// exist. Every repository gets the pull request routes: open a pull request
// from a branch under the pool's own push prefixes (HeadPrefixes), list and
// read pull requests, read and post comments, and, on a pull request whose
// head is under the pool's push prefixes or its pull request prefixes (see
// pullRequestHeads), comment, edit the body, edit the App's own comment and
// mark it ready. A pull request's files and a compare return code, so they
// exist only for a pool whose git entry can clone the repository, which the
// broker then authorizes too (CloneEntry). Labels, repository dispatch, Actions
// reads (with check runs and commit statuses), deployment reads and CI
// restarts exist only where the repository grants them; a CI restart also
// needs the git entry a push would use to grant the pool branch prefixes,
// which then hold its target's head (HeadPrefixes), and authorizes the
// requester against that entry too (CloneEntry). Reviews, merging a pull
// request, pushes through the API other than a CI restart's branch update
// (which merges the base into the head) and everything else are unlisted.
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
	if len(parts) < 5 || parts[0] != "" || parts[1] != "repos" {
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
				Query: query, Permissions: permissions, Download: route.download, CommentID: route.comment}
			if !contains(e.Pools, pool) {
				return matched, true, ErrPool
			}
			if route.code {
				// A file list or compare returns code: only for a pool whose git
				// entry lets it clone the repository, and only for a requester
				// that entry authorizes (its tier and groups).
				if matched.CloneEntry = c.cloneEntry(host, repo, pool); matched.CloneEntry == nil {
					return GitRequest{}, true, ErrUnlisted
				}
			}
			if route.restart > 0 {
				// A CI restart writes to, or runs again, a branch the pool could
				// push to itself: only where the git entry a push would use lets
				// the pool push to branch prefixes, only on those branches, and
				// only for a requester that entry authorizes too.
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
			case route.comment > 0:
				matched.HeadPrefixes = append(c.pushBranchPrefixes(repo, pool), r.pullRequestHeads(pool)...)
			}
			return matched, true, nil
		}
	}
	return GitRequest{}, true, ErrUnlisted
}

// GitHubAPIRepos returns, for a GraphQL request to a github-api host, every
// repository its entries list that the pool is granted, each with its head
// prefixes as for a REST write (its push prefixes, then pullRequestHeads). ok
// is false when the host has no github-api entry.
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
			out = append(out, GitRequest{Entry: e, Repo: r, Write: true, Route: "graphql", Method: http.MethodPost,
				Permissions: "pull-requests", HeadPrefixes: append(c.pushBranchPrefixes(r.Repo, pool), r.pullRequestHeads(pool)...)})
		}
	}
	return out, found
}

// GitHubAPIRepository is the GraphQL counterpart of GitHubAPIMatch: the
// github-api entry listing repo on the host, with the pool's head prefixes
// there. A repository no entry lists is ErrUnlisted; one listed only for
// other pools is ErrPool.
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

// pushBranchPrefixes are the branch names (refs/heads/ removed) a pool may
// push to in a repository, from its git entries' shared and per-pool ref
// prefixes (PushPrefixes). A pull request may come only from one of them; none
// means none may be opened.
func (c Catalog) pushBranchPrefixes(repo, pool string) []string {
	var out []string
	for i := range c.entries {
		if e := &c.entries[i]; e.Kind == "git" && contains(e.Pools, pool) {
			out = append(out, pushPrefixes(e, repo, pool)...)
		}
	}
	return out
}

// githubRoute is one GitHub REST route a github-api entry may serve, opened
// by one operation.
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
	workflowFile    = regexp.MustCompile(`^([1-9][0-9]{0,11}|[A-Za-z0-9][A-Za-z0-9_.-]{0,99}\.ya?ml)$`)
	queryValue      = regexp.MustCompile(`^[A-Za-z0-9 _.,:/+()-]{0,200}$`) // () for matrix job names such as `build (ubuntu-latest)`
	commitSHA       = regexp.MustCompile(`^[0-9a-f]{7,40}$`)
	// compareRef is one side of a compare: a branch name or a commit, with no
	// slash (a branch with one is not served) and never "..".
	compareRef = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}$`)
)

// compareRange reports whether s is "base...head" with two plain refs.
func compareRange(s string) bool {
	base, head, ok := strings.Cut(s, "...")
	return ok && compareRef.MatchString(base) && compareRef.MatchString(head) &&
		!strings.Contains(base, "..") && !strings.Contains(head, "..")
}

// githubAPIRoutes returns the routes for a path below /repos/{owner}/{repo}/,
// one per method, each naming the operation that opens it; none when the
// path is unlisted.
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
		// Not a GitHub REST route: GitHub marks a draft ready only through
		// GraphQL, so the broker makes that one mutation for this path.
		return []githubRoute{{name: "ready", method: http.MethodPost, op: "pr.ready", target: number(rest[1])}}
	case n == 3 && rest[0] == "issues" && number(rest[1]) > 0 && rest[2] == "comments":
		return []githubRoute{{name: "comment", method: http.MethodPost, op: "pr.comment", target: number(rest[1])},
			{name: "list-comments", method: http.MethodGet, op: "pr.list", query: commentQuery}}
	case n == 3 && rest[0] == "pulls" && number(rest[1]) > 0 && rest[2] == "comments":
		return []githubRoute{{name: "comment", method: http.MethodPost, op: "pr.comment", target: number(rest[1])}}
	case n == 5 && rest[0] == "pulls" && number(rest[1]) > 0 && rest[2] == "comments" && number(rest[3]) > 0 && rest[4] == "replies":
		return []githubRoute{{name: "comment", method: http.MethodPost, op: "pr.comment", target: number(rest[1])}}
	case n == 3 && rest[0] == "issues" && rest[1] == "comments" && number(rest[2]) > 0:
		return []githubRoute{{name: "edit-comment", method: http.MethodPatch, op: "pr.edit", comment: number(rest[2])}}
	case n == 3 && rest[0] == "issues" && number(rest[1]) > 0 && rest[2] == "labels":
		return []githubRoute{{name: "label", method: http.MethodPost, op: "pr.label", target: number(rest[1])}}
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

// githubQuery rebuilds a query string from its allowed keys, each at most
// once with a plain value; ok is false for any other key, a repeated key or
// a value outside queryValue.
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

// Match returns the entry for a request, choosing the longest path prefix
// that matches on a segment boundary. A host or path outside the catalog is
// ErrUnlisted; a listed route with another method is ErrMethod; a pool
// without the grant is ErrPool, reported only after the route matched.
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

// HasHost reports whether any entry names host and port, so a tunnel to an
// unlisted host can be refused before it opens.
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

// HasHostForPool reports whether an entry granted to pool names host and
// port. A tunnel is refused before it opens unless this holds, so a caller
// learns nothing about hosts other pools may reach.
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

// HTTP2Host reports whether the entries on host and port take HTTP/2, so a
// tunnel to it offers h2 and every other host keeps HTTP/1.1.
func (c Catalog) HTTP2Host(host string, port int) bool {
	host = strings.ToLower(host)
	for _, e := range c.entries {
		if e.HTTP2 && e.Host == host && e.Port == port {
			return true
		}
	}
	return false
}

// HasAuth0Domain reports whether host is the Auth0 domain of a
// browser-session entry: the only hosts the broker's own logins may reach.
func (c Catalog) HasAuth0Domain(host string) bool {
	host = strings.ToLower(host)
	for _, e := range c.entries {
		if e.BrowserSession != nil && e.BrowserSession.Auth0.Domain == host {
			return true
		}
	}
	return false
}

// HasAutomatedAuth reports whether addr (host:port) is the automated-auth
// service of a browser-session entry: the only other place the broker's own
// logins may reach.
func (c Catalog) HasAutomatedAuth(addr string) bool {
	addr = strings.ToLower(addr)
	for _, e := range c.entries {
		if e.BrowserSession != nil && e.BrowserSession.AutomatedAuth != nil && e.BrowserSession.AutomatedAuth.Addr() == addr {
			return true
		}
	}
	return false
}

// Entries returns a copy of the catalog, for wiring and diagnostics.
func (c Catalog) Entries() []Entry { return append([]Entry(nil), c.entries...) }

// GitGranted reports whether some entry still lets the installation's tokens
// reach repo at a scope: "contents-read" (a git entry), "contents-write" (a git
// entry with write access, or a github-api repository with dispatch),
// "pull-requests", "actions", "deployments", "checks", "statuses",
// "update-branch" or "actions-write" (a github-api repository with an
// operation that needs that scope).
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

// GitHubScope is what the catalog lets one installation's tokens reach: its
// repositories and whether any github-api entry on it needs each token scope.
type GitHubScope struct {
	Repos                                                []string
	PullRequests, Actions, Deployments, Checks, Statuses bool
	// ActionsWrite: a CI restart runs a workflow run again.
	ActionsWrite bool
}

// GitScope returns every repository the catalog lists for an installation,
// and whether any github-api entry on it opens pull requests (or updates a
// pull request's branch), reads Actions, reads deployments, reads check runs
// or commit statuses (which actions.read also does), or runs a workflow run
// again.
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

// cloneGitPort is the port a clone uses: git over HTTPS on 443. An entry for
// the same repository on another port is a different endpoint and never
// stands in for it.
const cloneGitPort = 443

// GitHubCloneEntry is cloneEntry for a GraphQL request that reads a pull
// request's files: the git entry the requester must also pass, or nil when
// the pool may not clone the repository.
func (c Catalog) GitHubCloneEntry(apiHost, repo, pool string) *Entry {
	return c.cloneEntry(strings.ToLower(apiHost), strings.ToLower(repo), pool)
}

// cloneEntry returns the git entry a clone of repo would use (pairedGit), or
// nil when there is none or it does not grant the pool (where a clone would
// get ErrPool).
func (c Catalog) cloneEntry(apiHost, repo, pool string) *Entry {
	e, _ := pairedGit(c.entries, apiHost, repo)
	if e == nil || !contains(e.Pools, pool) {
		return nil
	}
	return e
}

// pairedGit returns the git entry a clone of repo would use for a github-api
// entry on apiHost, and its listing of the repository, chosen the way
// GitMatch chooses it: the git entry on the git host and port that lists the
// repository (the catalog allows one per host and port), or nil when there is
// none. The git host is the API host without its "api." label, as github.com
// is for api.github.com, and the port is cloneGitPort.
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

// pushPrefixes are the branch names (refs/heads/ removed) git entry e lets
// pool push to in repo, the shared prefixes and the pool's own
// (PushPrefixes), never another pool's: none when e is nil, the repository is
// read-only there, or the pool has no branch prefixes.
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

// clusterLocal reports whether host is a Kubernetes Service name, the only
// kind of host a plaintext database entry may name.
func clusterLocal(host string) bool {
	return strings.HasSuffix(host, ".svc.cluster.local") || strings.HasSuffix(host, ".svc")
}

// plaintextDatabases lets a database entry for a Kubernetes Service host use
// sslmode disable, and an automated-auth service on one use plain http. Only a binary built with the e2e tag can set it (see
// plaintext_e2e.go), for the Kind fixture database, which serves no TLS.
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

// ForwardsHeader reports whether a caller header is passed upstream: a fixed
// set of content-negotiation headers plus the entry's ForwardHeaders.
func (e *Entry) ForwardsHeader(name string) bool {
	switch name = http.CanonicalHeaderKey(name); name {
	case "Accept", "Accept-Language", "Content-Type", "User-Agent":
		return true
	}
	return e.forwardsGRPCHeader(name) || contains(e.ForwardHeaders, name)
}

// grpcForwardHeaders are the gRPC protocol headers a client sets and its
// server reads: the call's deadline. The broker sets te and
// grpc-accept-encoding itself and refuses a compressed request, so every
// message it forwards or returns can be checked.
var grpcForwardHeaders = []string{"Grpc-Timeout"}

func (e *Entry) forwardsGRPCHeader(name string) bool {
	return e.HTTP2 && contains(grpcForwardHeaders, name)
}

var (
	groupID  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	ccpoolID = regexp.MustCompile(`^ccpool_[A-Za-z0-9]{1,120}$`)
	tierRank = map[string]int{"": 0, "T0": 0, "T1": 1, "T2": 2}
)

// CeilingExternal is the ceiling below T0, for workers serving people
// outside the company.
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
	// Only a cursor-session pool serves a Cursor run as its person; any
	// other pool names no person for one or decides it per Automation.
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
		// The broker's Cursor teams and audience bind the token; no session
		// start gate exists for Cursor, so a base group would promise nothing.
		if p.CCPoolID != "" || p.BaseGroup != "" || len(p.Entitlements) != 0 {
			return fmt.Errorf("a cursor-session pool takes no ccpool_ ID, base group or fixed entitlements")
		}
	case "attested-person":
		// The person comes from the proxy's attestation; there is no runner
		// pool, and a base group would gate nothing.
		if p.CCPoolID != "" || p.BaseGroup != "" || len(p.Entitlements) != 0 {
			return fmt.Errorf("an attested-person pool takes no ccpool_ ID, base group or fixed entitlements")
		}
	case IdentityCursorAutomation:
		// Each run is decided for its Automation, so the pool carries no
		// entitlements of its own.
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

// grantable is the CI rule: an entry above T0 is never granted to a pool that
// cannot carry it. Without defined pools only T0 entries may be granted. At
// any tier, a git entry's {requester} push prefix goes only to a pool that
// names who runs each request (requesterGrantable).
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

// Credential is the header value that carries v: v after Scheme, for a Basic
// user "Basic " and the base64 of v and an empty password, or for a Basic
// pair "Basic " and the base64 of v, which holds "user:password".
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

// CallerCredential is the value a worker sends in Header: the placeholder
// encoded as the key would be, and for a Basic pair, the placeholder as both
// user name and password. A Basic pair also takes the stored user name with
// the placeholder as password (CallerPairUser).
func (e *Entry) CallerCredential() string {
	if e.BasicPair {
		return e.Credential(e.Placeholder + ":" + e.Placeholder)
	}
	return e.Credential(e.Placeholder)
}

// CallerPairUser is the user name in value when value is Basic credentials
// with a user name of the worker's own and the placeholder as password, as a
// client given a pair's public key and, as its secret key, the placeholder
// sends them. Basic pair entries only. The user half of a pair is not
// secret; the broker serves the request only when it equals the stored one.
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

// SplitPair is the user and password halves of a Basic pair key, and false
// when v is not "user:password" with both halves set, so a malformed key is
// never sent.
func SplitPair(v string) (user, password string, ok bool) {
	user, password, ok = strings.Cut(v, ":")
	return user, password, ok && user != "" && password != ""
}
