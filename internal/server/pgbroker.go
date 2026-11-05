package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/hashicorp"
	"github.com/Infisical/agent-vault/internal/pgproxy"
	"github.com/Infisical/agent-vault/internal/store"
)

type agentAuthAdapter struct{ resolver brokercore.SessionResolver }

func NewAgentAuthAdapter(resolver brokercore.SessionResolver) pgproxy.AgentAuthenticator {
	return agentAuthAdapter{resolver: resolver}
}

func (a agentAuthAdapter) Authenticate(ctx context.Context, token, vaultHint string) (*pgproxy.AgentScope, error) {
	scope, err := a.resolver.ResolveForProxy(ctx, token, vaultHint)
	if err != nil {
		return nil, err
	}
	return agentScope(scope), nil
}

// AuthenticatePeer: a loopback peer (no PROXY header) keeps the token-only check.
func (a agentAuthAdapter) AuthenticatePeer(ctx context.Context, token, vaultHint string, peer netip.Addr, renewal bool) (*pgproxy.AgentScope, error) {
	attestor, ok := a.resolver.(brokercore.Attestor)
	if !ok || !peer.IsValid() || peer.IsLoopback() {
		return a.Authenticate(ctx, token, vaultHint)
	}
	var scope *brokercore.ProxyScope
	var err error
	if again, ok := a.resolver.(brokercore.Reattestor); ok && renewal {
		scope, err = again.Reattest(ctx, token, peer)
	} else {
		scope, err = attestor.Attest(ctx, token, peer)
	}
	if err != nil {
		return nil, err
	}
	if vaultHint != "" && vaultHint != scope.VaultName {
		return nil, brokercore.ErrVaultHintMismatch
	}
	return agentScope(scope), nil
}

func agentScope(scope *brokercore.ProxyScope) *pgproxy.AgentScope {
	return &pgproxy.AgentScope{VaultID: scope.VaultID, VaultName: scope.VaultName, ActorID: scope.ActorID(), WorkloadID: scope.WorkloadID, NotAfter: scope.NotAfter, Pool: scope.Pool,
		IdentityKind: scope.IdentityKind, ClaimedRun: scope.ClaimedRun, AttestedRequester: scope.AttestedRequester}
}

type DatabaseServiceConfig struct {
	Name     string `json:"name"`                // service slug the agent selects by
	Upstream string `json:"upstream"`            // upstream host:port
	Database string `json:"database"`            // optional upstream database override
	Mount    string `json:"mount"`               // Vault database secrets-engine mount
	Role     string `json:"role"`                // Vault role granting scoped SQL privileges
	SSLMode  string `json:"sslmode,omitempty"`   // upstream TLS: disable|prefer(default)|require|verify-full
	MaxConns int    `json:"max_conns,omitempty"` // per-database connection budget (0 = broker default)
}

type staticDatabaseResolver struct {
	byVault map[string][]pgproxy.DatabaseService
}

// NewStaticDatabaseResolver: exact service names beat unique upstream database aliases; unknown names are rejected even when a vault has one service.
func NewStaticDatabaseResolver(byVault map[string][]pgproxy.DatabaseService) pgproxy.DatabaseResolver {
	return staticDatabaseResolver{byVault: byVault}
}

func (r staticDatabaseResolver) ResolveDatabase(_ context.Context, scope pgproxy.AgentScope, requestedDatabase string) (*pgproxy.DatabaseService, error) {
	svc, err := selectDatabaseService(r.byVault[scope.VaultName], scope.VaultName, requestedDatabase)
	if err != nil {
		return nil, err
	}
	for _, services := range r.byVault {
		for _, other := range services {
			if other.Addr == svc.Addr && other.MaxConns > 0 && (svc.MaxConns == 0 || other.MaxConns < svc.MaxConns) {
				svc.MaxConns = other.MaxConns
			}
		}
	}
	return svc, nil
}

type databaseServiceLister interface {
	ListDatabaseServices(ctx context.Context, vaultID string) ([]store.DatabaseService, error)
	DatabaseUpstreamLimit(ctx context.Context, upstream string) (int, error)
}

type storeDatabaseResolver struct{ store databaseServiceLister }

func NewStoreDatabaseResolver(lister databaseServiceLister) pgproxy.DatabaseResolver {
	return storeDatabaseResolver{store: lister}
}

func (r storeDatabaseResolver) ResolveDatabase(ctx context.Context, scope pgproxy.AgentScope, requestedDatabase string) (*pgproxy.DatabaseService, error) {
	rows, err := r.store.ListDatabaseServices(ctx, scope.VaultID)
	if err != nil {
		return nil, fmt.Errorf("listing database services for vault %q: %w", scope.VaultName, err)
	}
	services := make([]pgproxy.DatabaseService, len(rows))
	for i, row := range rows {
		services[i] = pgproxy.DatabaseService{
			Name:     row.Name,
			Addr:     row.Upstream,
			Database: row.Database,
			Mount:    row.Mount,
			Role:     row.Role,
			SSLMode:  row.SSLMode,
			MaxConns: row.MaxConns,
			ReadOnly: readOnlyRole(row.Role),
		}
	}
	svc, err := selectDatabaseService(services, scope.VaultName, requestedDatabase)
	if err != nil {
		return nil, err
	}
	// Aliases and vaults on one endpoint share its strictest explicit limit.
	svc.MaxConns, err = r.store.DatabaseUpstreamLimit(ctx, svc.Addr)
	if err != nil {
		return nil, fmt.Errorf("reading database budget: %w", err)
	}
	return svc, nil
}

// selectDatabaseService applies strict selection even to single-service vaults, so deleting a service cannot redirect reconnecting clients.
func selectDatabaseService(services []pgproxy.DatabaseService, vaultName, requestedDatabase string) (*pgproxy.DatabaseService, error) {
	for _, svc := range services {
		if svc.Name == requestedDatabase {
			return &svc, nil
		}
	}
	var match *pgproxy.DatabaseService
	for _, svc := range services {
		if svc.Database != "" && svc.Database == requestedDatabase {
			if match != nil {
				return nil, fmt.Errorf("ambiguous database alias %q; select a service name", requestedDatabase)
			}
			copy := svc
			match = &copy
		}
	}
	if match != nil {
		return match, nil
	}
	available := make([]string, len(services))
	for i := range services {
		available[i] = services[i].Name
	}
	return nil, fmt.Errorf("no database service named %q in vault %q (available: %s)", requestedDatabase, vaultName, strings.Join(available, ", "))
}

func (s *Server) DatabaseResolver() pgproxy.DatabaseResolver {
	return NewStoreDatabaseResolver(s.store)
}

// SeedDatabaseServices seeds the store from AGENT_VAULT_DB_SERVICES once per service, leaving services already in the store (even after deletion or API edits) untouched; unknown vaults are skipped with a warning.
func (s *Server) SeedDatabaseServices(ctx context.Context, byVault map[string][]pgproxy.DatabaseService) (int, error) {
	seeded := 0
	for vaultName, services := range byVault {
		vault, err := s.store.GetVault(ctx, vaultName)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return seeded, fmt.Errorf("resolving seed vault: %w", err)
		}
		if vault == nil || errors.Is(err, sql.ErrNoRows) {
			s.logger.Warn("pgproxy: skipping seed for unknown vault", slog.String("vault", vaultName))
			continue
		}
		added, err := func() (int, error) {
			unlock, err := s.lockVault(ctx, vault.ID)
			if err != nil {
				return 0, err
			}
			defer unlock()
			added := 0
			for _, svc := range services {
				if inserted, err := s.store.SeedDatabaseService(ctx, store.DatabaseService{
					VaultID:  vault.ID,
					Name:     svc.Name,
					Upstream: svc.Addr,
					Database: svc.Database,
					Mount:    svc.Mount,
					Role:     svc.Role,
					SSLMode:  svc.SSLMode,
					MaxConns: svc.MaxConns,
				}); err != nil {
					return added, fmt.Errorf("seeding database service %q in vault %q: %w", svc.Name, vaultName, err)
				} else if inserted {
					added++
				}
			}
			return added, nil
		}()
		seeded += added
		if err != nil {
			return seeded, err
		}

	}
	return seeded, nil
}

type vaultLeaseMinter struct{ client *hashicorp.Client }

func NewVaultLeaseMinter(client *hashicorp.Client) pgproxy.LeaseMinter {
	return vaultLeaseMinter{client: client}
}

func (m vaultLeaseMinter) Mint(ctx context.Context, _ pgproxy.AgentScope, svc *pgproxy.DatabaseService) (*pgproxy.Lease, error) {
	issuedAt := time.Now()
	cred, err := m.client.ReadDatabaseCredential(ctx, svc.Mount, svc.Role)
	if err != nil {
		return nil, err
	}
	return &pgproxy.Lease{
		ID:        cred.LeaseID,
		Username:  cred.Username,
		Password:  cred.Password,
		ExpiresAt: cred.ExpiresAt(issuedAt),
		Renewable: cred.Renewable,
	}, nil
}

func (m vaultLeaseMinter) Renew(ctx context.Context, leaseID string, minRemaining time.Duration) (time.Time, error) {
	started := time.Now()
	granted, err := m.client.RenewLease(ctx, leaseID, minRemaining)
	if err != nil {
		return time.Time{}, err
	}
	return started.Add(granted), nil
}

func (m vaultLeaseMinter) Revoke(ctx context.Context, leaseID string) error {
	return m.client.RevokeLease(ctx, leaseID)
}

// LoadDatabaseServices reads AGENT_VAULT_DB_SERVICES (inline JSON) or, when empty, the file named by AGENT_VAULT_DB_SERVICES_FILE.
// The wire form is {"<vault>": [{"name","upstream","database","mount","role"}, ...]}.
func LoadDatabaseServices(getenv func(string) string) (map[string][]pgproxy.DatabaseService, error) {
	raw := strings.TrimSpace(getenv("AGENT_VAULT_DB_SERVICES"))
	if raw == "" {
		if path := strings.TrimSpace(getenv("AGENT_VAULT_DB_SERVICES_FILE")); path != "" {
			data, err := os.ReadFile(path)
			if err != nil {
				return nil, fmt.Errorf("read AGENT_VAULT_DB_SERVICES_FILE: %w", err)
			}
			raw = strings.TrimSpace(string(data))
		}
	}
	if raw == "" {
		return map[string][]pgproxy.DatabaseService{}, nil
	}

	var cfg map[string][]DatabaseServiceConfig
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return nil, fmt.Errorf("parse database services JSON: %w", err)
	}
	out := make(map[string][]pgproxy.DatabaseService, len(cfg))
	for vault, entries := range cfg {
		for _, entry := range entries {
			if err := entry.Validate(vault); err != nil {
				return nil, err
			}
			for _, svc := range out[vault] {
				if svc.Name == entry.Name {
					return nil, fmt.Errorf("duplicate database service %q in vault %q", entry.Name, vault)
				}
			}
			out[vault] = append(out[vault], pgproxy.DatabaseService{
				Name:     entry.Name,
				Addr:     entry.Upstream,
				Database: entry.Database,
				Mount:    entry.Mount,
				Role:     entry.Role,
				SSLMode:  entry.SSLMode,
				MaxConns: entry.MaxConns,
				ReadOnly: readOnlyRole(entry.Role),
			})
		}
	}
	return out, nil
}

// readOnlyRole infers read-only from the catalog naming (<name>-readonly or -readwrite) for services outside the catalog.
func readOnlyRole(role string) bool { return strings.HasSuffix(role, "-readonly") }

var databaseServiceName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

func (e DatabaseServiceConfig) Validate(vault string) error {
	switch {
	case strings.TrimSpace(e.Name) == "":
		return fmt.Errorf("database service in vault %q is missing %q", vault, "name")
	case strings.TrimSpace(e.Upstream) == "":
		return fmt.Errorf("database service %q in vault %q is missing %q", e.Name, vault, "upstream")
	case strings.TrimSpace(e.Mount) == "":
		return fmt.Errorf("database service %q in vault %q is missing %q", e.Name, vault, "mount")
	case strings.TrimSpace(e.Role) == "":
		return fmt.Errorf("database service %q in vault %q is missing %q", e.Name, vault, "role")
	}
	if !databaseServiceName.MatchString(e.Name) {
		return fmt.Errorf("database name must be 1-64 lowercase letters, digits or hyphens")
	}
	host, port, err := net.SplitHostPort(e.Upstream)
	if err != nil || strings.TrimSpace(host) == "" {
		return fmt.Errorf("upstream must be a nonempty host:port")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("upstream port must be between 1 and 65535")
	}
	if err := hashicorp.ValidateDatabaseReference(e.Mount, e.Role); err != nil {
		return err
	}
	if e.MaxConns < 0 {
		return fmt.Errorf("database service %q in vault %q: max_conns %d must be >= 0 (0 = broker default)", e.Name, vault, e.MaxConns)
	}
	// Reject an unrecognized sslmode: a typo must not silently disable TLS.
	switch e.SSLMode {
	case "", "disable", "prefer", "require", "verify-full":
	default:
		return fmt.Errorf("database service %q in vault %q: invalid sslmode %q (want disable|prefer|require|verify-full)", e.Name, vault, e.SSLMode)
	}
	return nil
}
