package cmd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Infisical/agent-vault/internal/auditchain"
	"github.com/Infisical/agent-vault/internal/githubapp"
	"github.com/Infisical/agent-vault/internal/hashicorp"
	"github.com/Infisical/agent-vault/internal/httpcatalog"
	"github.com/Infisical/agent-vault/internal/mitm"
	"github.com/Infisical/agent-vault/internal/netguard"
	"github.com/Infisical/agent-vault/internal/server"
	"golang.org/x/oauth2/google"
)

var sharedCatalog struct {
	sync.Mutex
	source  *httpcatalog.Source
	started bool
}

// brokerCatalog loads the destination catalog once per process, for the HTTP
// adapter and the PostgreSQL broker alike. AGENT_VAULT_CATALOG_VAULT_PATH
// (mount/path of a KV version 2 secret whose "catalog" field Terraform
// writes) is reloaded every 30 seconds without a restart; a version that
// fails validation is logged and the last good catalog stays in force.
// AGENT_VAULT_CATALOG_VAULT_PREFIX reads the same catalog stored one secret
// per entry, with the same reload. AGENT_VAULT_HTTP_CATALOG_FILE is a fixed
// catalog read at start.
//
// A Vault catalog never stops the broker: an entry that fails validation is
// left out and named in the log, and each accepted version is kept in st. A
// broker that starts while Vault is unreachable starts from that stored copy,
// or, with none, from an empty catalog that refuses everything and reports
// not ready until the watch loads a version.
func brokerCatalog(ctx context.Context, client *hashicorp.Client, st any, ready func(string, func() bool), getenv func(string) string, logger *slog.Logger) (*httpcatalog.Source, error) {
	sharedCatalog.Lock()
	defer sharedCatalog.Unlock()
	if sharedCatalog.started {
		return sharedCatalog.source, nil
	}
	if err := catalogEnvironment(getenv); err != nil {
		return nil, err
	}
	testPlaintextDatabases(getenv, logger)
	var source *httpcatalog.Source
	single, perEntry := getenv("AGENT_VAULT_CATALOG_VAULT_PATH"), getenv("AGENT_VAULT_CATALOG_VAULT_PREFIX")
	if single != "" && perEntry != "" {
		return nil, fmt.Errorf("set AGENT_VAULT_CATALOG_VAULT_PATH or AGENT_VAULT_CATALOG_VAULT_PREFIX, not both")
	}
	if location := single + perEntry; location != "" {
		mount, path, ok := strings.Cut(location, "/")
		if !ok || client == nil {
			return nil, fmt.Errorf("the catalog's Vault location needs mount/path and a Vault client")
		}
		// One secret per entry (AGENT_VAULT_CATALOG_VAULT_PREFIX) has no size
		// limit; the single document (AGENT_VAULT_CATALOG_VAULT_PATH) is
		// bounded by Vault's size limit for one secret and stays for migration.
		load := httpcatalog.VaultLoader(client.Logical(), mount, path, "catalog")
		if perEntry != "" {
			load = httpcatalog.VaultPrefixLoader(client.Logical(), mount, path)
		}
		kept, _ := st.(catalogStore)
		var stored httpcatalog.Loader
		if kept != nil {
			stored = func(ctx context.Context) ([]byte, int, error) { return kept.LoadBrokerCatalog(ctx, location) }
		}
		accepted := func(version int, data []byte, dropped []httpcatalog.Dropped) {
			logDroppedCatalogParts(logger, version, dropped)
			if kept == nil {
				return
			}
			saveCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := kept.SaveBrokerCatalog(saveCtx, location, version, data); err != nil {
				logger.Warn("broker catalog accepted but not stored; a restart during a Vault outage starts from an older copy",
					slog.Int("version", version), slog.String("error", err.Error()))
			}
		}
		var err error
		source, err = httpcatalog.Start(ctx, load, stored, accepted)
		switch {
		case err == nil:
		case source.Loaded():
			logger.Warn("broker catalog unavailable at start; serving the stored copy until Vault answers", slog.String("error", err.Error()))
		default:
			logger.Error("broker catalog unavailable at start and none stored; refusing every destination until Vault answers", slog.String("error", err.Error()))
		}
		if ready != nil {
			ready("catalog", source.Loaded)
		}
		// ctx is the server's lifetime context, so the watch runs until exit.
		go source.Watch(ctx, 30*time.Second, load, func(version int, err error) {
			logger.Error("broker catalog version rejected; keeping the last good catalog",
				slog.Int("version", version), slog.Int("in_force", source.Version()), slog.String("error", err.Error()))
		})
	} else if path := getenv("AGENT_VAULT_HTTP_CATALOG_FILE"); path != "" {
		catalog, err := httpcatalog.Load(path)
		if err != nil {
			return nil, err
		}
		source = httpcatalog.NewSource(catalog, 0)
	}
	sharedCatalog.source, sharedCatalog.started = source, true
	return source, nil
}

// catalogStore keeps the last accepted catalog across restarts.
type catalogStore interface {
	SaveBrokerCatalog(ctx context.Context, location string, version int, document []byte) error
	LoadBrokerCatalog(ctx context.Context, location string) ([]byte, int, error)
}

// logDroppedCatalogParts names, without contents, each part a catalog version
// left out, so a bad entry is found from the log while the rest serve.
func logDroppedCatalogParts(logger *slog.Logger, version int, dropped []httpcatalog.Dropped) {
	for _, d := range dropped {
		logger.Error("broker catalog part left out; the rest of the catalog is in force",
			slog.Int("version", version), slog.String("kind", d.Kind), slog.String("name", d.Name), slog.String("reason", d.Reason))
	}
}

// httpHeaderAdapter builds the catalog-driven HTTP adapter when a broker
// catalog is configured. It requires the strict credential proxy, a Vault
// client and the signed audit chain, and refuses to start without any of
// them rather than serve unaudited or unlisted traffic.
func httpHeaderAdapter(ctx context.Context, srv *server.Server, getenv func(string) string) (*mitm.HeaderAdapter, error) {
	if getenv("AGENT_VAULT_CATALOG_VAULT_PATH") == "" && getenv("AGENT_VAULT_CATALOG_VAULT_PREFIX") == "" && getenv("AGENT_VAULT_HTTP_CATALOG_FILE") == "" {
		return nil, nil
	}
	if !srv.CredentialProxyEnabled() {
		return nil, fmt.Errorf("requires AGENT_VAULT_CREDENTIAL_PROXY=true")
	}
	client := srv.HashicorpClient()
	if client == nil {
		if getenv("AGENT_VAULT_HTTP_CATALOG_FILE") != "" {
			if _, err := httpcatalog.Load(getenv("AGENT_VAULT_HTTP_CATALOG_FILE")); err != nil {
				return nil, err
			}
		}
		return nil, fmt.Errorf("requires a HashiCorp Vault client")
	}
	source, err := brokerCatalog(ctx, client, srv.CleanupStore(), srv.AttachReadiness, getenv, srv.Logger())
	if err != nil {
		return nil, err
	}
	chain, err := sharedAuditChain(ctx, client, srv.CleanupStore(), getenv, srv.Logger())
	if err != nil {
		return nil, err
	}
	if chain == nil {
		return nil, fmt.Errorf("requires AGENT_VAULT_AUDIT_CHAIN")
	}
	keys := &httpcatalog.Keys{Vault: client.Logical()}
	adapter := &mitm.HeaderAdapter{Catalog: source, Keys: keys, Audit: chain}
	if err := attachAuthorization(adapter, getenv); err != nil {
		return nil, err
	}
	adapter.Sessions = sessionBinder(srv.CleanupStore())
	dial := netguard.SafeDialContext(netguard.AllowPrivateFromEnv())
	browserTokens := &httpcatalog.Auth0Tokens{Keys: keys, Client: auth0Client(source, dial), AutomatedAuth: automatedAuthClient(source, dial),
		Revoked: func(binding, outcome string, status int, took time.Duration) {
			_ = chain.Record(auditchain.Event{Event: auditchain.EventHTTPResponse, Binding: binding + "/revoke", Outcome: outcome, Method: http.MethodPost, Status: status,
				Duration: took.Milliseconds()})
		}}
	adapter.BrowserTokens = browserTokens
	source.OnChange(browserTokens.Prune)
	githubEntries, gcpEntries := false, false
	for _, e := range source.Current().Entries() {
		githubEntries = githubEntries || e.Kind == "git" || e.Kind == "github-api"
		gcpEntries = gcpEntries || e.Kind == "gcp"
	}
	if gcpEntries {
		// The broker's own Workload Identity is the root; per-entry tokens are
		// downscoped from it or minted for the entry's service account.
		root, err := google.DefaultTokenSource(ctx, "https://www.googleapis.com/auth/cloud-platform")
		if err != nil {
			return nil, fmt.Errorf("gcp catalog entries need the broker's Google identity: %w", err)
		}
		adapter.GCPTokens = &httpcatalog.GCPTokens{Root: root, Client: &http.Client{Timeout: 10 * time.Second,
			Transport: &http.Transport{DialContext: netguard.SafeDialContext(netguard.AllowPrivateFromEnv()), TLSHandshakeTimeout: 5 * time.Second}}}
	}
	signer, err := githubAppSigner(client, getenv)
	switch {
	case err == nil:
		api := getenv("AGENT_VAULT_GITHUB_API_URL")
		if api != "" && !strings.HasPrefix(api, "https://") {
			return nil, fmt.Errorf("AGENT_VAULT_GITHUB_API_URL must be https")
		}
		scopeMode, err := githubapp.ParseScopeMode(getenv("AGENT_VAULT_GITHUB_APP_SCOPE"))
		if err != nil {
			return nil, err
		}
		minter := &githubapp.Minter{Signer: signer, API: api, Log: srv.Logger(), ScopeMode: scopeMode, Scope: func(installation int64) githubapp.Scope {
			s := source.Current().GitScope(installation)
			return githubapp.Scope{Repos: s.Repos, PullRequests: s.PullRequests, Actions: s.Actions, Deployments: s.Deployments, Checks: s.Checks, Statuses: s.Statuses}
		}}
		adapter.GitTokens = minter
		// A catalog change that removes or narrows a repository revokes the
		// tokens it no longer grants instead of letting them run out, and
		// checks each installation against the new catalog before its next token.
		source.OnChange(func(c httpcatalog.Catalog) {
			minter.ForgetScope()
			minter.Prune(func(installation int64, repo string, p githubapp.Permissions) bool {
				return c.GitGranted(installation, repo, gitScope(p))
			})
		})
	case githubEntries:
		return nil, err
	}
	return adapter, nil
}

// auth0Client is how browser-session test users log in from the broker: over
// the same guarded dialer as every other upstream, to an Auth0 domain the
// current catalog names on port 443 and nowhere else, never following a
// redirect, since the login body holds the user's password and the client
// secret.
func auth0Client(catalog interface{ Current() httpcatalog.Catalog }, dial func(context.Context, string, string) (net.Conn, error)) *http.Client {
	pinned := func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil || port != "443" || !catalog.Current().HasAuth0Domain(host) {
			return nil, errors.New("auth0 login: host not in the catalog")
		}
		return dial(ctx, network, addr)
	}
	return &http.Client{Timeout: 10 * time.Second,
		Transport:     &http.Transport{DialContext: pinned, TLSHandshakeTimeout: 5 * time.Second},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// automatedAuthClient is how browser-session test users sign in through TRM's
// automated-auth service: over the guarded dialer, to a service address the
// current catalog names and nowhere else, never following a redirect. The
// service drives a real login page, so a sign-in takes tens of seconds.
func automatedAuthClient(catalog interface{ Current() httpcatalog.Catalog }, dial func(context.Context, string, string) (net.Conn, error)) *http.Client {
	pinned := func(ctx context.Context, network, addr string) (net.Conn, error) {
		if !catalog.Current().HasAutomatedAuth(addr) {
			return nil, errors.New("automated-auth login: service not in the catalog")
		}
		return dial(ctx, network, addr)
	}
	return &http.Client{Timeout: 60 * time.Second,
		Transport:     &http.Transport{DialContext: pinned, TLSHandshakeTimeout: 5 * time.Second},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// gitScope names a token's permissions as the catalog grants them.
func gitScope(p githubapp.Permissions) string {
	switch {
	case p.Actions == "read":
		return "actions"
	case p.Deployments == "read":
		return "deployments"
	case p.Checks == "read":
		return "checks"
	case p.Statuses == "read":
		return "statuses"
	case p.PullRequests == "write":
		return "pull-requests"
	case p.Contents == "write":
		return "contents-write"
	default:
		return "contents-read"
	}
}

var transitKeyName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,126}$`)

// catalogEnvironment applies AGENT_VAULT_CATALOG_ENVIRONMENT, the environment
// every catalog database role must be named for (such as staging).
func catalogEnvironment(getenv func(string) string) error {
	env := getenv("AGENT_VAULT_CATALOG_ENVIRONMENT")
	if env != "" && !regexp.MustCompile(`^[a-z]+$`).MatchString(env) {
		return fmt.Errorf("AGENT_VAULT_CATALOG_ENVIRONMENT must be lower-case letters")
	}
	httpcatalog.Environment.Store(env)
	return nil
}

// githubAppSigner signs App JWTs with the App key imported into Transit, so
// the key never leaves Vault. AGENT_VAULT_GITHUB_APP_KV_PATH selects the
// fallback, a PEM on the gatehouse KV mount read into the broker per signature.
func githubAppSigner(client *hashicorp.Client, getenv func(string) string) (githubapp.JWTSigner, error) {
	if key := getenv("AGENT_VAULT_GITHUB_APP_TRANSIT_KEY"); key != "" {
		mount := getenv("AGENT_VAULT_GITHUB_APP_TRANSIT_MOUNT")
		if mount == "" {
			mount = "transit"
		}
		// The same shapes the catalog's Terraform module accepts.
		if !transitKeyName.MatchString(key) || !httpcatalog.ValidMount(mount) {
			return nil, fmt.Errorf("AGENT_VAULT_GITHUB_APP_TRANSIT_KEY or _MOUNT has an invalid name")
		}
		return githubapp.TransitSigner{Vault: client.Logical(), Mount: mount, Key: key}, nil
	}
	if path := getenv("AGENT_VAULT_GITHUB_APP_KV_PATH"); path != "" {
		return githubapp.KVSigner{Vault: client.Logical(), Mount: "gatehouse", Path: path, Field: "private_key"}, nil
	}
	return nil, fmt.Errorf("git catalog entries require AGENT_VAULT_GITHUB_APP_TRANSIT_KEY or AGENT_VAULT_GITHUB_APP_KV_PATH")
}
