package server

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"net"

	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/hashicorp"
	"github.com/Infisical/agent-vault/internal/infisical"
	"github.com/Infisical/agent-vault/internal/mitm"
	"github.com/Infisical/agent-vault/internal/netguard"
	"github.com/Infisical/agent-vault/internal/notify"
	"github.com/Infisical/agent-vault/internal/oauth"
	"github.com/Infisical/agent-vault/internal/pgproxy"
	"github.com/Infisical/agent-vault/internal/pidfile"
	"github.com/Infisical/agent-vault/internal/proxyactivity"
	"github.com/Infisical/agent-vault/internal/proxycert"
	"github.com/Infisical/agent-vault/internal/ratelimit"
	"github.com/Infisical/agent-vault/internal/requestlog"
	"github.com/Infisical/agent-vault/internal/store"
	"github.com/Infisical/agent-vault/internal/telemetry"
)

//go:embed all:webdist
var webDistFS embed.FS

//go:embed invite_email.html
var userInviteEmailHTML string

//go:embed proposal_notification_email.html
var proposalNotificationEmailHTML string

//go:embed verification_code_email.html
var verificationCodeEmailHTML string

//go:embed password_reset_email.html
var passwordResetEmailHTML string

//go:embed test_email.html
var testEmailHTML string

// agentVaultJSON is the JSON representation of an agent's vault grant (reused across handlers).
type agentVaultJSON struct {
	VaultName string `json:"vault_name"`
	VaultRole string `json:"vault_role"`
}

// Server is the Agent Vault HTTP server.
type Server struct {
	httpServer    *http.Server
	store         Store
	encKey        []byte // 32-byte encryption key, held in memory while running
	notifier      *notify.Notifier
	initialized   atomic.Bool         // true when at least one owner account exists; replicas share registration
	shuttingDown  atomic.Bool         // SIGTERM arrived: readiness is false from here on
	lastInitCheck atomic.Int64        // unix-millis of last DB check for initialization (throttle)
	baseURL       string              // externally-reachable base URL (e.g. "https://sb.example.com")
	skillCLI      []byte              // embedded CLI skill content (served at GET /v1/skills/cli)
	mitm          *mitm.Proxy         // transparent MITM proxy; nil only when --mitm-port 0
	logger        *slog.Logger        // structured logger for per-request observability
	rateLimit     *ratelimit.Registry // tiered rate limiter; shared with the MITM ingress
	logSink       requestlog.Sink     // per-request persistence sink; never nil (Nop default)
	// httpListener, when set, is served instead of binding httpServer.Addr; tests set it to avoid port races.
	httpListener net.Listener
	// touchCache throttles session-touch writes because each UPDATE takes the single WAL writer slot; pruned periodically.
	touchCache sync.Map // raw token (string) -> time.Time
	// infisicalClient is nil when INFISICAL_URL is unset; create handlers
	// reject kind="infisical" then.
	infisicalClient *infisical.Client
	// infisicalSyncer is built in Run; exposed for manual-refresh RefreshOnce.
	infisicalSyncer *infisical.Syncer
	// infisicalDynamic resolves Infisical dynamic-secret leases on demand; built
	// in Run alongside the syncer when a client is attached. Nil disables it.
	infisicalDynamic *infisical.DynamicResolver
	// hashicorpClient is nil when VAULT_ADDR is unset; create handlers then reject kind="hashicorp".
	hashicorpClient *hashicorp.Client
	hashicorpSyncer *hashicorp.Syncer
	credentialProxy bool
	oauthRefresher  *oauth.Refresher
	telemetry       *telemetry.Telemetry
	// pgBroker is nil when --postgres-port is 0 or no database services are configured.
	cleanupObserverServer *http.Server
	crossClusterAddr      string                 // loopback address of the cross-cluster listener, or ""
	crossClusterLimits    CrossClusterLimits     // zero fields take the defaults
	staticTokenAddr       string                 // loopback address of the static-token listener, or ""
	proxyCerts            *proxycert.Issuer      // signs shared proxies' serving certificates on that listener, or nil
	proxyActivity         *proxyactivity.Service // keeps shared proxies' Sandbox activity on that listener, or nil
	pgBroker              *pgproxy.Broker
	pgTLS                 *pgTLSFront // the broker's own TLS listener for pgBroker, or nil
	readiness             []readinessCheck
	liveness              []readinessCheck
	pgLeaseCloser         interface{ Close(context.Context) error }
	shutdownFuncs         []func()
	finalShutdownFuncs    []func()
	shutdownTimeout       time.Duration // 0: the default 5s
	storeOK               atomic.Int64  // Unix ms of the last good store ping; 0 before the first
}

// lockVault acquires the per-vault mutation lock via the store's
// LockVault. Callers MUST defer the returned unlock func.
func (s *Server) lockVault(ctx context.Context, vaultID string) (func(), error) {
	return s.store.LockVault(ctx, vaultID)
}

// RateLimit returns the server's rate-limit registry. Exported so the
// MITM ingress can share the same tier state (see cmd/server.go).
func (s *Server) RateLimit() *ratelimit.Registry { return s.rateLimit }

// AttachMITM registers an optional MITM proxy whose lifecycle is bound to this Server.
func (s *Server) AttachMITM(p *mitm.Proxy) { s.mitm = p }

// AttachInfisical registers the Infisical client. Must be called before Start.
func (s *Server) AttachInfisical(c *infisical.Client) { s.infisicalClient = c }

// AttachInfisicalSyncer pre-wires a syncer instead of letting Start build one; used by tests to inject a fake fetcher.
func (s *Server) AttachInfisicalSyncer(syncer *infisical.Syncer) { s.infisicalSyncer = syncer }

// AttachHashicorp must be called before Start.
func (s *Server) AttachHashicorp(c *hashicorp.Client) { s.hashicorpClient = c }

// HashicorpClient returns the attached client, or nil when VAULT_ADDR is unset.
func (s *Server) HashicorpClient() *hashicorp.Client { return s.hashicorpClient }

// AttachPostgresBroker binds the broker's lifecycle to this Server. Must be called before Start.
func (s *Server) AttachPostgresBroker(b *pgproxy.Broker) { s.pgBroker = b }

// EnableProxyCertificates requires the cross-cluster listener to be enabled.
func (s *Server) EnableProxyCertificates(i *proxycert.Issuer) error {
	if err := i.Validate(); err != nil {
		return err
	}
	s.proxyCerts = i
	return nil
}

// EnableProxyActivity requires the cross-cluster listener to be enabled.
func (s *Server) EnableProxyActivity(a *proxyactivity.Service) error {
	if err := a.Validate(); err != nil {
		return err
	}
	s.proxyActivity = a
	return nil
}

// SetShutdownTimeout sets the graceful-stop wait for in-flight work; zero keeps the default 5s.
func (s *Server) SetShutdownTimeout(d time.Duration) { s.shutdownTimeout = d }

func (s *Server) shutdownBudget() time.Duration {
	if s.shutdownTimeout > 0 {
		return s.shutdownTimeout
	}
	return 5 * time.Second
}

// AttachReadiness adds a named check to GET /readyz; names, never values, appear in the response.
func (s *Server) AttachReadiness(name string, check func() bool) {
	s.readiness = append(s.readiness, readinessCheck{name: name, check: check})
}

// AttachLiveness adds a named check to GET /health, which a liveness probe restarts on; attach only what a restart fixes.
func (s *Server) AttachLiveness(name string, check func() bool) {
	s.liveness = append(s.liveness, readinessCheck{name: name, check: check})
}

type readinessCheck struct {
	name  string
	check func() bool
}

// AttachHashicorpSyncer injects a syncer (tests use a fake fetcher); Start builds one when nil.
func (s *Server) AttachHashicorpSyncer(syncer *hashicorp.Syncer) { s.hashicorpSyncer = syncer }

// AttachLogSink swaps the per-request log sink; call once at startup, nil resets to a Nop sink.
func (s *Server) AttachLogSink(sink requestlog.Sink) {
	if sink == nil {
		sink = requestlog.Nop{}
	}
	s.logSink = sink
}

// LogSink returns the server's log sink. Shared with the MITM ingress so
// both paths feed the same pipeline.
func (s *Server) LogSink() requestlog.Sink { return s.logSink }

// AttachTelemetry sets the PostHog telemetry client. When nil (the
// default), captureEvent is a no-op.
func (s *Server) AttachTelemetry(t *telemetry.Telemetry) { s.telemetry = t }

// captureEvent sends a telemetry event if configured; actor may be nil for pre-auth endpoints.
func (s *Server) captureEvent(r *http.Request, event string, actor *Actor, extra map[string]string) {
	if s.telemetry == nil {
		return
	}
	props := make(map[string]string, len(extra)+3)
	for k, v := range extra {
		props[k] = v
	}

	if avClient := r.Header.Get("X-AV-Client"); avClient != "" {
		props["source"] = "cli"
		props["client_version"] = avClient
	} else if _, err := r.Cookie("av_session"); err == nil {
		props["source"] = "web"
	} else {
		props["source"] = "api"
	}

	distinctID := ""
	if actor != nil {
		props["actor_type"] = actor.Type
		if actor.User != nil {
			distinctID = actor.User.Email
		} else if actor.Agent != nil {
			distinctID = "agent:" + actor.Agent.Name
		}
	}
	if distinctID == "" {
		if email, ok := extra["email"]; ok && email != "" {
			distinctID = email
		} else {
			distinctID = "anonymous_server"
		}
	}

	s.telemetry.CaptureEvent(distinctID, event, props)
}

// SessionResolver returns a brokercore.SessionResolver backed by this
// server's store.
func (s *Server) SessionResolver() brokercore.SessionResolver {
	return brokercore.NewStoreSessionResolver(s.store)
}

// CredentialProvider returns a brokercore.CredentialProvider backed by
// this server's store and encryption key.
func (s *Server) CredentialProvider() brokercore.CredentialProvider {
	p := &brokercore.StoreCredentialProvider{
		Store:      credentialStoreAdapter{s.store},
		OAuthStore: credentialStoreAdapter{s.store},
		EncKey:     s.encKey,
		Refresher:  s.oauthRefresher,
	}
	// Late-bind via an adapter: the proxy captures this provider before Start() builds s.infisicalDynamic.
	p.Dynamic = lateDynamicResolver{s}
	p.RequestSecrets = requestSecrets{s}
	return p
}

// lateDynamicResolver reads s.infisicalDynamic per call because Start() builds it after the MITM proxy captured the provider.
type lateDynamicResolver struct{ s *Server }

func (l lateDynamicResolver) Resolve(ctx context.Context, vaultID, key string) (string, bool, error) {
	if l.s.infisicalDynamic == nil {
		return "", false, nil
	}
	return l.s.infisicalDynamic.Resolve(ctx, vaultID, key)
}

// revokeDynamicLeases evicts the lease cache synchronously and revokes upstream in the background so a slow Infisical cannot stall the response.
func (s *Server) revokeDynamicLeases(vaultID string) {
	if s.infisicalDynamic == nil {
		return
	}
	s.infisicalDynamic.RevokeVaultAsync(vaultID)
}

// credentialStoreAdapter adds the typed UnmatchedHostPolicy lookup to brokercore.CredentialStore over the generic store.
type credentialStoreAdapter struct {
	Store
}

func (a credentialStoreAdapter) UnmatchedHostPolicy(ctx context.Context, vaultID string) (brokercore.UnmatchedHostPolicy, error) {
	return readUnmatchedHostPolicy(ctx, a.Store, vaultID)
}

func (a credentialStoreAdapter) GetCredentialOAuth(ctx context.Context, vaultID, key string) (*store.CredentialOAuth, error) {
	return a.Store.GetCredentialOAuth(ctx, vaultID, key)
}

func (a credentialStoreAdapter) UpdateCredentialOAuthTokens(ctx context.Context, vaultID, key string, accessCT, accessNonce, refreshCT, refreshNonce []byte, expiresAt *time.Time) error {
	return a.Store.UpdateCredentialOAuthTokens(ctx, vaultID, key, accessCT, accessNonce, refreshCT, refreshNonce, expiresAt)
}

func (a credentialStoreAdapter) UpdateCredentialOAuthError(ctx context.Context, vaultID, key, errMsg string) error {
	return a.Store.UpdateCredentialOAuthError(ctx, vaultID, key, errMsg)
}

// Logger returns the server's structured logger. Callers (e.g. the MITM
// proxy constructed outside the server) use this to share a single logger.
func (s *Server) Logger() *slog.Logger { return s.logger }

// BaseURL returns the externally-reachable base URL of the server
// (e.g. "http://127.0.0.1:14321").
func (s *Server) BaseURL() string { return s.baseURL }

// Store is the persistence interface used by the server.
type Store interface {
	GetMasterKeyRecord(ctx context.Context) (*store.MasterKeyRecord, error)
	CreateUser(ctx context.Context, email string, passwordHash, passwordSalt []byte, role string, kdfTime uint32, kdfMemory uint32, kdfThreads uint8, kdfAlgorithm string) (*store.User, error)
	GetUserByEmail(ctx context.Context, email string) (*store.User, error)
	GetUserByID(ctx context.Context, id string) (*store.User, error)
	GetUserEmailByID(ctx context.Context, id string) (string, error)
	ListUsers(ctx context.Context) ([]store.User, error)
	UpdateUserRole(ctx context.Context, userID, role string) error
	UpdateUserPassword(ctx context.Context, userID string, passwordHash, passwordSalt []byte, kdfTime uint32, kdfMemory uint32, kdfThreads uint8, kdfAlgorithm string) error
	UpgradeUserPasswordHash(ctx context.Context, expected *store.User, passwordHash, passwordSalt []byte, kdfTime uint32, kdfMemory uint32, kdfThreads uint8, kdfAlgorithm string) (bool, error)
	DeleteUser(ctx context.Context, userID string) error
	CountUsers(ctx context.Context) (int, error)
	RegisterFirstUser(ctx context.Context, email string, passwordHash, passwordSalt []byte, defaultVaultID string, kdfTime uint32, kdfMemory uint32, kdfThreads uint8, kdfAlgorithm string) (*store.User, error)
	CreateUserSession(ctx context.Context, p store.CreateUserSessionParams) (*store.Session, error)
	CreateScopedSession(ctx context.Context, p store.CreateScopedSessionParams) (*store.Session, error)
	GetSession(ctx context.Context, id string) (*store.Session, error)
	DeleteSession(ctx context.Context, id string) error
	DeleteUserSessions(ctx context.Context, userID string) error
	TouchSession(ctx context.Context, rawToken, ip, userAgent string) error
	ListUserSessions(ctx context.Context, userID string) ([]store.Session, error)
	RevokeUserSession(ctx context.Context, userID, publicID string) error
	ListScopedSessionsByVault(ctx context.Context, vaultID string) ([]store.Session, error)
	RevokeScopedSession(ctx context.Context, vaultID, publicID string) error

	// Vaults
	CreateVault(ctx context.Context, name string) (*store.Vault, error)
	GetVault(ctx context.Context, name string) (*store.Vault, error)
	GetVaultByID(ctx context.Context, id string) (*store.Vault, error)
	ListVaults(ctx context.Context) ([]store.Vault, error)
	DeleteVault(ctx context.Context, name string) error
	RenameVault(ctx context.Context, oldName string, newName string) error

	// Vault grants (unified: actor_id + actor_type)
	GrantVaultRole(ctx context.Context, actorID, actorType, vaultID, role string) error
	RevokeVaultAccess(ctx context.Context, actorID, vaultID string) error
	ListActorGrants(ctx context.Context, actorID string) ([]store.VaultGrant, error)
	HasVaultAccess(ctx context.Context, actorID, vaultID string) (bool, error)
	GetVaultRole(ctx context.Context, actorID, vaultID string) (string, error)
	CountVaultAdmins(ctx context.Context, vaultID string) (int, error)
	ListVaultMembers(ctx context.Context, vaultID string) ([]store.VaultGrant, error)
	ListVaultMembersByType(ctx context.Context, vaultID, actorType string) ([]store.VaultGrant, error)

	// User activation
	ActivateUser(ctx context.Context, userID string) error

	// Credentials
	SetCredential(ctx context.Context, vaultID, key string, ciphertext, nonce []byte) (*store.Credential, error)
	GetCredential(ctx context.Context, vaultID, key string) (*store.Credential, error)
	ListCredentials(ctx context.Context, vaultID string) ([]store.Credential, error)
	DeleteCredential(ctx context.Context, vaultID, key string) error

	// OAuth credentials
	GetCredentialOAuth(ctx context.Context, vaultID, key string) (*store.CredentialOAuth, error)
	SetCredentialOAuth(ctx context.Context, oauth *store.CredentialOAuth) error
	UpdateCredentialOAuthTokens(ctx context.Context, vaultID, key string, accessCT, accessNonce, refreshCT, refreshNonce []byte, expiresAt *time.Time) error
	UpdateCredentialOAuthError(ctx context.Context, vaultID, key string, errMsg string) error

	// OAuth states (CSRF + PKCE for consent flow)
	CreateCredentialOAuthState(ctx context.Context, state *store.CredentialOAuthState) error
	GetCredentialOAuthStateByHash(ctx context.Context, stateHash string) (*store.CredentialOAuthState, error)
	DeleteCredentialOAuthState(ctx context.Context, id string) error
	ExpireCredentialOAuthStates(ctx context.Context, before time.Time) (int, error)

	// Broker configs
	GetBrokerConfig(ctx context.Context, vaultID string) (*store.BrokerConfig, error)
	SetBrokerConfig(ctx context.Context, vaultID, servicesJSON string) (*store.BrokerConfig, error)

	UpsertDatabaseService(ctx context.Context, svc store.DatabaseService) (*store.DatabaseService, error)
	SeedDatabaseService(ctx context.Context, svc store.DatabaseService) (bool, error)
	GetDatabaseService(ctx context.Context, vaultID, name string) (*store.DatabaseService, error)
	ListDatabaseServices(ctx context.Context, vaultID string) ([]store.DatabaseService, error)
	DatabaseUpstreamLimit(ctx context.Context, upstream string) (int, error)
	DeleteDatabaseService(ctx context.Context, vaultID, name string) (bool, error)

	// Proposals
	CreateProposal(ctx context.Context, vaultID, sessionID, servicesJSON, credentialsJSON, message, userMessage string, credentials map[string]store.EncryptedCredential) (*store.Proposal, error)
	GetProposal(ctx context.Context, vaultID string, id int) (*store.Proposal, error)
	GetProposalByApprovalToken(ctx context.Context, token string) (*store.Proposal, error)
	ListProposals(ctx context.Context, vaultID, status string) ([]store.Proposal, error)
	CountPendingProposals(ctx context.Context, vaultID string) (int, error)
	UpdateProposalStatus(ctx context.Context, vaultID string, id int, status, reviewNote string) error
	GetProposalCredentials(ctx context.Context, vaultID string, proposalID int) (map[string]store.EncryptedCredential, error)
	ApplyProposal(ctx context.Context, vaultID string, proposalID int, mergedServicesJSON string, credentials map[string]store.EncryptedCredential, deleteCredentialKeys []string, oauthConfigs []store.OAuthCredentialConfig) error
	ExpirePendingProposals(ctx context.Context, before time.Time) (int, error)

	// User invites (instance-level)
	CreateUserInvite(ctx context.Context, email, createdBy, role string, expiresAt time.Time, vaults []store.UserInviteVault) (*store.UserInvite, error)
	GetUserInviteByToken(ctx context.Context, token string) (*store.UserInvite, error)
	GetPendingUserInviteByEmail(ctx context.Context, email string) (*store.UserInvite, error)
	ListUserInvites(ctx context.Context, status string) ([]store.UserInvite, error)
	ListUserInvitesByVault(ctx context.Context, vaultID, status string) ([]store.UserInvite, error)
	AcceptUserInvite(ctx context.Context, token string) error
	RevokeUserInvite(ctx context.Context, token string) error
	UpdateUserInviteVaults(ctx context.Context, token string, vaults []store.UserInviteVault) error
	CountPendingUserInvites(ctx context.Context) (int, error)

	// Email verification
	CreateEmailVerification(ctx context.Context, email, code string, expiresAt time.Time) (*store.EmailVerification, error)
	GetPendingEmailVerification(ctx context.Context, email, code string) (*store.EmailVerification, error)
	MarkEmailVerificationUsed(ctx context.Context, id int) error
	CountPendingEmailVerifications(ctx context.Context, email string) (int, error)

	// Password resets
	CreatePasswordReset(ctx context.Context, email, code string, expiresAt time.Time) (*store.PasswordReset, error)
	GetPendingPasswordReset(ctx context.Context, email, code string) (*store.PasswordReset, error)
	MarkPasswordResetUsed(ctx context.Context, id int) error
	CountPendingPasswordResets(ctx context.Context, email string) (int, error)
	ExpirePendingPasswordResets(ctx context.Context, before time.Time) (int, error)

	// Instance settings
	GetSetting(ctx context.Context, key string) (string, error)
	SetSetting(ctx context.Context, key, value string) error
	GetAllSettings(ctx context.Context) (map[string]string, error)

	// Vault settings (per-vault key/value)
	GetVaultSetting(ctx context.Context, vaultID, key string) (string, error)
	SetVaultSetting(ctx context.Context, vaultID, key, value string) error
	DeleteVaultSetting(ctx context.Context, vaultID, key string) error

	// External credential stores
	CreateExternalVault(ctx context.Context, p store.CreateExternalVaultParams) (*store.Vault, error)
	GetVaultCredentialStore(ctx context.Context, vaultID string) (*store.VaultCredentialStore, error)
	ListVaultCredentialStores(ctx context.Context) ([]store.VaultCredentialStore, error)
	UpdateVaultCredentialStoreHealth(ctx context.Context, vaultID, status, errMsg string, syncedAt time.Time) error
	ReplaceVaultCredentialsForSync(ctx context.Context, vaultID, configJSON string, items []store.EncryptedKV) (applied bool, err error)
	SetVaultExternalStore(ctx context.Context, p store.SetVaultExternalStoreParams) (*store.VaultCredentialStore, error)
	DeleteVaultCredentialStore(ctx context.Context, vaultID string) error

	// Dynamic-secret lease tracking (Infisical)
	InsertDynamicSecretLease(ctx context.Context, lease store.DynamicSecretLease) error
	DeleteDynamicSecretLease(ctx context.Context, leaseID string) error
	ListDynamicSecretLeases(ctx context.Context) ([]store.DynamicSecretLease, error)

	// Agents
	CreateAgent(ctx context.Context, name, createdBy, role string) (*store.Agent, error)
	CreateAgentWithGrantsAndToken(ctx context.Context, name, createdBy, role string, vaultGrants []store.AgentVaultGrantSpec, tokenExpiresAt *time.Time) (*store.Agent, *store.Session, error)
	GetAgentByID(ctx context.Context, id string) (*store.Agent, error)
	GetAgentNameByID(ctx context.Context, id string) (string, error)
	GetAgentByName(ctx context.Context, name string) (*store.Agent, error)
	ListAgents(ctx context.Context, vaultID string) ([]store.Agent, error)
	ListAllAgents(ctx context.Context) ([]store.Agent, error)
	RevokeAgent(ctx context.Context, id string) error
	DeleteAgent(ctx context.Context, id string) error
	RenameAgent(ctx context.Context, id string, newName string) error
	UpdateAgentRole(ctx context.Context, agentID, role string) error
	CountAgentTokens(ctx context.Context, agentID string) (int, error)
	GetLatestAgentTokenExpiry(ctx context.Context, agentID string) (*time.Time, error)
	DeleteAgentTokens(ctx context.Context, agentID string) error
	RotateAgentToken(ctx context.Context, agentID string, tokenExpiresAt *time.Time) (*store.Session, error)
	CreateAgentToken(ctx context.Context, agentID string, expiresAt *time.Time) (*store.Session, error)
	CountAllOwners(ctx context.Context) (int, error)

	// Request logs
	InsertRequestLogs(ctx context.Context, rows []store.RequestLog) error
	ListRequestLogs(ctx context.Context, opts store.ListRequestLogsOpts) ([]store.RequestLog, error)
	ListUnmatchedHosts(ctx context.Context, vaultID string) ([]store.UnmatchedHost, error)
	DeleteOldRequestLogs(ctx context.Context, before time.Time) (int64, error)
	TrimRequestLogsToCap(ctx context.Context, vaultID string, cap int64) (int64, error)
	VaultIDsWithLogs(ctx context.Context) ([]string, error)

	// LockVault acquires an exclusive advisory lock for the given vault.
	LockVault(ctx context.Context, vaultID string) (unlock func(), err error)

	Close() error
	Ping(ctx context.Context) error
	DialectName() string
}

// contextKey is an unexported type for context keys in this package.
type contextKey int

const sessionContextKey contextKey = 0

// sessionFromContext retrieves the session from the request context.
func sessionFromContext(ctx context.Context) *store.Session {
	sess, _ := ctx.Value(sessionContextKey).(*store.Session)
	return sess
}

// Actor represents an authenticated entity (user or agent) with an instance-level role.
// All permission checks operate on Actor, making the system role-based rather than type-based.
type Actor struct {
	ID    string       // user.ID or agent.ID
	Type  string       // "user" or "agent"
	Role  string       // "owner", "member", or "no-access" (instance-level)
	User  *store.User  // non-nil for user actors
	Agent *store.Agent // non-nil for agent actors
}

// IsOwner returns true if the actor has the instance-level owner role.
func (a *Actor) IsOwner() bool { return a.Role == "owner" }

// Hierarchy: no-access(0) < member(1) < owner(2).
var instanceRoleRank = map[string]int{"no-access": 0, "member": 1, "owner": 2}

func validInstanceRole(s string) bool {
	_, ok := instanceRoleRank[s]
	return ok
}

func instanceRoleSatisfies(role, required string) bool {
	return satisfiesRank(instanceRoleRank, role, required)
}

// DisplayLabel returns a human-readable label for the actor (email for users, name for agents).
func (a *Actor) DisplayLabel() string {
	if a.User != nil {
		return a.User.Email
	}
	if a.Agent != nil {
		return a.Agent.Name
	}
	return a.ID
}

// actorByID hydrates an Actor from a stored (id, type) pair, e.g. a created_by column.
func (s *Server) actorByID(ctx context.Context, actorID, actorType string) (*Actor, error) {
	switch actorType {
	case "user":
		user, err := s.store.GetUserByID(ctx, actorID)
		if err != nil || user == nil {
			return nil, fmt.Errorf("user not found")
		}
		return &Actor{ID: user.ID, Type: "user", Role: user.Role, User: user}, nil
	case "agent":
		agent, err := s.store.GetAgentByID(ctx, actorID)
		if err != nil || agent == nil {
			return nil, fmt.Errorf("agent not found")
		}
		return &Actor{ID: agent.ID, Type: "agent", Role: agent.Role, Agent: agent}, nil
	}
	return nil, fmt.Errorf("unknown actor type: %s", actorType)
}

// actorFromSession resolves any session to an Actor.
func (s *Server) actorFromSession(ctx context.Context, sess *store.Session) (*Actor, error) {
	if sess == nil {
		return nil, fmt.Errorf("no session")
	}
	if sess.UserID != "" {
		user, err := s.store.GetUserByID(ctx, sess.UserID)
		if err != nil || user == nil {
			return nil, fmt.Errorf("user not found")
		}
		return &Actor{ID: user.ID, Type: "user", Role: user.Role, User: user}, nil
	}
	if sess.AgentID != "" {
		agent, err := s.store.GetAgentByID(ctx, sess.AgentID)
		if err != nil || agent == nil {
			return nil, fmt.Errorf("agent not found")
		}
		return &Actor{ID: agent.ID, Type: "agent", Role: agent.Role, Agent: agent}, nil
	}
	return nil, fmt.Errorf("session has no actor")
}

// requireActor checks that the request is from any authenticated actor (user or agent).
func (s *Server) requireActor(w http.ResponseWriter, r *http.Request) (*Actor, error) {
	sess := sessionFromContext(r.Context())
	actor, err := s.actorFromSession(r.Context(), sess)
	if err != nil {
		jsonError(w, http.StatusForbidden, "Authentication required")
		return nil, err
	}
	return actor, nil
}

// requireOwnerActor checks that the request is from an owner (user OR agent).
func (s *Server) requireOwnerActor(w http.ResponseWriter, r *http.Request) (*Actor, error) {
	actor, err := s.requireActor(w, r)
	if err != nil {
		return nil, err
	}
	if !actor.IsOwner() {
		jsonError(w, http.StatusForbidden, "Owner role required")
		return nil, fmt.Errorf("not owner")
	}
	return actor, nil
}

// requireInstanceMember rejects no-access actors on instance-scoped actions that do not already require owner.
func (s *Server) requireInstanceMember(w http.ResponseWriter, r *http.Request) (*Actor, error) {
	actor, err := s.requireActor(w, r)
	if err != nil {
		return nil, err
	}
	if !instanceRoleSatisfies(actor.Role, "member") {
		jsonError(w, http.StatusForbidden, "Instance member role required")
		return nil, fmt.Errorf("instance role too low: %s", actor.Role)
	}
	return actor, nil
}

// guardLastOwner checks that removing/demoting an owner would not leave zero owners.
// Returns true if the operation is blocked (error already written to w).
func (s *Server) guardLastOwner(ctx context.Context, w http.ResponseWriter, action string) bool {
	count, err := s.store.CountAllOwners(ctx)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to count owners")
		return true
	}
	if count <= 1 {
		jsonError(w, http.StatusConflict, "Cannot "+action+" the last owner")
		return true
	}
	return false
}

// requireVaultAccess checks that the session may access the vault; returns the actor (nil for scoped sessions) or writes an error.
func (s *Server) requireVaultAccess(w http.ResponseWriter, r *http.Request, vaultID string) (*Actor, error) {
	sess := sessionFromContext(r.Context())
	if sess == nil {
		jsonError(w, http.StatusForbidden, "Authentication required")
		return nil, fmt.Errorf("no session")
	}

	// Scoped session: vault is baked into the session.
	if sess.VaultID != "" {
		if sess.VaultID != vaultID {
			jsonError(w, http.StatusForbidden, "Session not authorized for this vault")
			return nil, fmt.Errorf("vault mismatch")
		}
		return nil, nil // scoped session, no actor resolved
	}

	// Instance-level session: resolve actor, check unified vault_grants.
	actor, err := s.actorFromSession(r.Context(), sess)
	if err != nil {
		jsonError(w, http.StatusForbidden, "Invalid session")
		return nil, err
	}

	has, err := s.store.HasVaultAccess(r.Context(), actor.ID, vaultID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to check vault access")
		return nil, err
	}
	if !has {
		jsonError(w, http.StatusForbidden, "No access to this vault")
		return nil, fmt.Errorf("no grant")
	}

	return actor, nil
}

// requireVaultAdmin checks that the actor has admin role in the given vault.
// For scoped sessions: checks sess.VaultRole. For instance-level sessions: checks vault_grants.
func (s *Server) requireVaultAdmin(w http.ResponseWriter, r *http.Request, vaultID string) (*Actor, error) {
	sess := sessionFromContext(r.Context())
	if sess == nil {
		jsonError(w, http.StatusForbidden, "Authentication required")
		return nil, fmt.Errorf("no session")
	}

	// Scoped session: check role from session.
	if sess.VaultID != "" {
		if sess.VaultID != vaultID {
			jsonError(w, http.StatusForbidden, "Session not authorized for this vault")
			return nil, fmt.Errorf("vault mismatch")
		}
		if !roleSatisfies(sess.VaultRole, "admin") {
			jsonError(w, http.StatusForbidden, "Vault admin role required")
			return nil, fmt.Errorf("insufficient role: %s", sess.VaultRole)
		}
		return nil, nil
	}

	// Instance-level session: single GetVaultRole call (covers both existence and role check).
	actor, err := s.actorFromSession(r.Context(), sess)
	if err != nil {
		jsonError(w, http.StatusForbidden, "Invalid session")
		return nil, err
	}
	role, err := s.store.GetVaultRole(r.Context(), actor.ID, vaultID)
	if err != nil {
		jsonError(w, http.StatusForbidden, "No access to this vault")
		return nil, fmt.Errorf("no vault grant")
	}
	if role != "admin" {
		jsonError(w, http.StatusForbidden, "Vault admin role required")
		return nil, fmt.Errorf("not vault admin")
	}
	return actor, nil
}

// Hierarchy: proxy(0) < member(1) < admin(2).
var roleRank = map[string]int{"proxy": 0, "member": 1, "admin": 2}

// satisfiesRank reports whether role meets or exceeds required in the given rank table.
// Unknown roles rank as 0; unknown required values are satisfied by anything in rank.
func satisfiesRank(rank map[string]int, role, required string) bool {
	return rank[role] >= rank[required]
}

func roleSatisfies(role, requiredRole string) bool {
	return satisfiesRank(roleRank, role, requiredRole)
}

// requireVaultMember checks that the session has member+ access to the vault.
func (s *Server) requireVaultMember(w http.ResponseWriter, r *http.Request, vaultID string) (*Actor, error) {
	sess := sessionFromContext(r.Context())
	if sess == nil {
		jsonError(w, http.StatusForbidden, "Authentication required")
		return nil, fmt.Errorf("no session")
	}

	// Scoped session: check vault_role from session.
	if sess.VaultID != "" {
		if sess.VaultID != vaultID {
			jsonError(w, http.StatusForbidden, "Session not authorized for this vault")
			return nil, fmt.Errorf("vault mismatch")
		}
		if !roleSatisfies(sess.VaultRole, "member") {
			jsonError(w, http.StatusForbidden, "Member role required")
			return nil, fmt.Errorf("insufficient role: %s", sess.VaultRole)
		}
		return nil, nil
	}

	// Instance-level session: check vault grant and role.
	actor, err := s.actorFromSession(r.Context(), sess)
	if err != nil {
		jsonError(w, http.StatusForbidden, "Invalid session")
		return nil, err
	}

	role, err := s.store.GetVaultRole(r.Context(), actor.ID, vaultID)
	if err != nil {
		jsonError(w, http.StatusForbidden, "No access to this vault")
		return nil, fmt.Errorf("no vault grant")
	}
	if !roleSatisfies(role, "member") {
		jsonError(w, http.StatusForbidden, "Member role required")
		return nil, fmt.Errorf("insufficient role: %s", role)
	}
	return actor, nil
}

// assertBuiltinCredentialStore writes 409 and returns false when the vault
// is external-backed. Fails closed (500) on transient lookup errors.
func (s *Server) assertBuiltinCredentialStore(w http.ResponseWriter, ctx context.Context, vaultID, vaultName string) bool {
	cs, err := s.store.GetVaultCredentialStore(ctx, vaultID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		jsonError(w, http.StatusInternalServerError, "Failed to verify credential store")
		return false
	}
	if cs != nil && cs.Kind != "" {
		jsonCodedError(w, http.StatusConflict, "external_credential_store",
			fmt.Sprintf("Vault %q uses an external credential store (%s). Manage credentials in the upstream system.", vaultName, cs.Kind))
		return false
	}
	return true
}

// requireProposalReview gates proposal approve/reject; proxy-role actors are forbidden so a proxy cannot approve its own proposal.
func (s *Server) requireProposalReview(w http.ResponseWriter, r *http.Request, vaultID string) (*Actor, error) {
	sess := sessionFromContext(r.Context())
	if sess == nil {
		jsonError(w, http.StatusForbidden, "Authentication required")
		return nil, fmt.Errorf("no session")
	}

	// Scoped session: require admin role.
	if sess.VaultID != "" {
		if sess.VaultID != vaultID {
			jsonError(w, http.StatusForbidden, "Session not authorized for this vault")
			return nil, fmt.Errorf("vault mismatch")
		}
		if !roleSatisfies(sess.VaultRole, "admin") {
			jsonError(w, http.StatusForbidden, "Admin role required")
			return nil, fmt.Errorf("insufficient role: %s", sess.VaultRole)
		}
		return nil, nil
	}

	// Instance-level session: require member+ (proxy-role actors cannot self-approve).
	return s.requireVaultMember(w, r, vaultID)
}

// securityHeaders wraps a handler to set security headers on every response.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

// maxRequestBodySize is the maximum allowed request body size (1 MB).
const maxRequestBodySize = 1 << 20

// limitBody wraps a handler to enforce a maximum request body size.
func limitBody(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
		next(w, r)
	}
}

// New creates a Server on the given address; while uninitialized, all endpoints except /health and POST /v1/init return 503.
func New(addr string, store Store, encKey []byte, notifier *notify.Notifier, initialized bool, baseURL string, logger *slog.Logger) *Server {
	mux := http.NewServeMux()

	rlCfg, _ := ratelimit.LoadFromEnv()
	rl := ratelimit.New(rlCfg)

	s := &Server{
		httpServer: &http.Server{
			Addr:              addr,
			Handler:           securityHeaders(rl.GlobalMiddleware(logger)(mux)),
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      60 * time.Second,
			IdleTimeout:       120 * time.Second,
		},
		store:          store,
		encKey:         encKey,
		notifier:       notifier,
		baseURL:        strings.TrimRight(baseURL, "/"),
		logger:         logger,
		rateLimit:      rl,
		logSink:        requestlog.Nop{},
		oauthRefresher: oauth.NewRefresher(),
	}

	// Apply SSRF protection to OAuth token endpoint requests.
	oauthTransport := http.DefaultTransport.(*http.Transport).Clone()
	oauthTransport.Proxy = nil
	oauthTransport.DialContext = netguard.SafeDialContext(netguard.AllowPrivateFromEnv())
	oauth.TokenClient = &http.Client{Timeout: 30 * time.Second, Transport: oauthTransport}

	ipAuth := s.tier(ratelimit.TierAuth, s.ipKeyer())

	// /health, /v1/status, and other public static routes rely on the
	// server-wide TierGlobal backstop; no per-route limit is useful.
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("GET /readyz", s.handleReady)
	mux.HandleFunc("GET /ready", s.handleReady)
	mux.HandleFunc("GET /v1/status", s.handleStatus)
	mux.HandleFunc("POST /v1/auth/register", ipAuth(limitBody(s.handleRegister)))
	mux.HandleFunc("POST /v1/auth/verify", ipAuth(limitBody(s.handleVerify)))
	mux.HandleFunc("POST /v1/auth/resend-verification", ipAuth(limitBody(s.handleResendVerification)))
	mux.HandleFunc("POST /v1/auth/forgot-password", ipAuth(limitBody(s.handleForgotPassword)))
	mux.HandleFunc("POST /v1/auth/reset-password", ipAuth(limitBody(s.handleResetPassword)))

	actorAuthed := s.tier(ratelimit.TierAuthed, s.actorKeyer())

	// Require initialization
	mux.HandleFunc("GET /v1/auth/me", s.requireInitialized(s.requireAuth(actorAuthed(s.handleAuthMe))))
	mux.HandleFunc("POST /v1/auth/login", s.requireInitialized(ipAuth(limitBody(s.handleLogin))))
	mux.HandleFunc("POST /v1/auth/change-password", s.requireInitialized(s.requireAuth(actorAuthed(limitBody(s.handleChangePassword)))))
	mux.HandleFunc("DELETE /v1/auth/account", s.requireInitialized(s.requireAuth(actorAuthed(s.handleDeleteAccount))))
	mux.HandleFunc("GET /v1/auth/sessions", s.requireInitialized(s.requireAuth(actorAuthed(s.handleListUserSessions))))
	mux.HandleFunc("DELETE /v1/auth/sessions/{id}", s.requireInitialized(s.requireAuth(actorAuthed(s.handleRevokeUserSession))))
	mux.HandleFunc("POST /v1/sessions", s.requireInitialized(s.requireAuth(actorAuthed(limitBody(s.handleScopedSession)))))
	mux.HandleFunc("GET /v1/sessions", s.requireInitialized(s.requireAuth(actorAuthed(s.handleListScopedSessions))))
	mux.HandleFunc("DELETE /v1/sessions/{id}", s.requireInitialized(s.requireAuth(actorAuthed(s.handleRevokeScopedSession))))
	mux.HandleFunc("GET /v1/credentials", s.requireInitialized(s.requireAuth(actorAuthed(s.handleCredentialsList))))
	mux.HandleFunc("POST /v1/credentials", s.requireInitialized(s.requireAuth(actorAuthed(limitBody(s.handleCredentialsSet)))))
	mux.HandleFunc("DELETE /v1/credentials", s.requireInitialized(s.requireAuth(actorAuthed(limitBody(s.handleCredentialsDelete)))))

	// OAuth credential flow
	mux.HandleFunc("POST /v1/credentials/oauth/connect", s.requireInitialized(s.requireAuth(actorAuthed(limitBody(s.handleOAuthConnect)))))
	mux.HandleFunc("GET /v1/oauth/callback", s.requireInitialized(s.handleOAuthCallback))
	mux.HandleFunc("GET /v1/credentials/oauth/status", s.requireInitialized(s.requireAuth(actorAuthed(s.handleOAuthStatus))))
	mux.HandleFunc("POST /v1/credentials/oauth/tokens", s.requireInitialized(s.requireAuth(actorAuthed(limitBody(s.handleOAuthTokenUpload)))))

	mux.HandleFunc("GET /discover", s.requireInitialized(s.requireAuth(actorAuthed(s.handleDiscover))))
	mux.HandleFunc("POST /v1/proposals", s.requireInitialized(s.requireAuth(actorAuthed(limitBody(s.handleProposalCreate)))))
	mux.HandleFunc("GET /v1/proposals/{id}", s.requireInitialized(s.requireAuth(actorAuthed(s.handleProposalGet))))
	mux.HandleFunc("GET /v1/proposals", s.requireInitialized(s.requireAuth(actorAuthed(s.handleProposalList))))
	mux.HandleFunc("POST /v1/admin/proposals/{id}/approve", s.requireInitialized(s.requireAuth(actorAuthed(limitBody(s.handleAdminProposalApprove)))))
	mux.HandleFunc("POST /v1/admin/proposals/{id}/reject", s.requireInitialized(s.requireAuth(actorAuthed(limitBody(s.handleAdminProposalReject)))))

	ipUserInviteToken := s.tier(ratelimit.TierAuth, ratelimit.IPTokenKey(clientIP, func(r *http.Request) string {
		return r.PathValue("token")
	}))
	ipApprovalToken := s.tier(ratelimit.TierAuth, ratelimit.IPTokenKey(clientIP, func(r *http.Request) string {
		return r.URL.Query().Get("token")
	}))

	// Agent management (instance-level)
	mux.HandleFunc("POST /v1/agents", s.requireInitialized(s.requireAuth(actorAuthed(limitBody(s.handleAgentCreate)))))
	mux.HandleFunc("GET /v1/agents", s.requireInitialized(s.requireAuth(actorAuthed(s.handleAgentList))))
	mux.HandleFunc("GET /v1/agents/{name}", s.requireInitialized(s.requireAuth(actorAuthed(s.handleAgentGet))))
	mux.HandleFunc("DELETE /v1/agents/{name}", s.requireInitialized(s.requireAuth(actorAuthed(s.handleAgentRevoke))))
	mux.HandleFunc("POST /v1/agents/{name}/delete", s.requireInitialized(s.requireAuth(actorAuthed(limitBody(s.handleAgentDelete)))))
	mux.HandleFunc("POST /v1/agents/{name}/rotate", s.requireInitialized(s.requireAuth(actorAuthed(limitBody(s.handleAgentRotate)))))
	mux.HandleFunc("POST /v1/agents/{name}/rename", s.requireInitialized(s.requireAuth(actorAuthed(limitBody(s.handleAgentRename)))))
	mux.HandleFunc("POST /v1/agents/{name}/role", s.requireInitialized(s.requireAuth(actorAuthed(limitBody(s.handleAgentSetRole)))))

	// Vault-level agent management
	mux.HandleFunc("GET /v1/vaults/{name}/agents", s.requireInitialized(s.requireAuth(actorAuthed(s.handleVaultAgentList))))
	mux.HandleFunc("POST /v1/vaults/{name}/agents", s.requireInitialized(s.requireAuth(actorAuthed(limitBody(s.handleVaultAgentAdd)))))
	mux.HandleFunc("DELETE /v1/vaults/{name}/agents/{agentName}", s.requireInitialized(s.requireAuth(actorAuthed(s.handleVaultAgentRemove))))
	mux.HandleFunc("POST /v1/vaults/{name}/agents/{agentName}/role", s.requireInitialized(s.requireAuth(actorAuthed(limitBody(s.handleVaultAgentSetRole)))))

	// Instance settings (owner-only)
	mux.HandleFunc("GET /v1/admin/settings", s.requireInitialized(s.requireAuth(actorAuthed(s.handleGetSettings))))
	mux.HandleFunc("PUT /v1/admin/settings", s.requireInitialized(s.requireAuth(actorAuthed(limitBody(s.handleUpdateSettings)))))
	mux.HandleFunc("POST /v1/admin/settings/rate-limit/preview", s.requireInitialized(s.requireAuth(actorAuthed(limitBody(s.handleRateLimitPreview)))))

	// Public user list (any authenticated user)
	mux.HandleFunc("GET /v1/users", s.requireInitialized(s.requireAuth(actorAuthed(s.handlePublicUserList))))

	// User management (owner-only, except GET self)
	mux.HandleFunc("GET /v1/admin/users/{email}", s.requireInitialized(s.requireAuth(actorAuthed(s.handleUserGet))))
	mux.HandleFunc("DELETE /v1/admin/users/{email}", s.requireInitialized(s.requireAuth(actorAuthed(s.handleUserDelete))))
	mux.HandleFunc("POST /v1/admin/users/{email}/role", s.requireInitialized(s.requireAuth(actorAuthed(limitBody(s.handleUserSetRole)))))

	// Vault management (any auth'd user)
	mux.HandleFunc("GET /v1/vaults/{name}/context", s.requireInitialized(s.requireAuth(actorAuthed(s.handleVaultContext))))
	mux.HandleFunc("POST /v1/vaults/{name}/sync", s.requireInitialized(s.requireAuth(actorAuthed(s.handleVaultSyncNow))))
	mux.HandleFunc("GET /v1/instance/credential-stores", s.requireInitialized(s.requireAuth(actorAuthed(s.handleInstanceCredentialStores))))
	mux.HandleFunc("POST /v1/vaults", s.requireInitialized(s.requireAuth(actorAuthed(limitBody(s.handleVaultCreate)))))
	mux.HandleFunc("GET /v1/vaults", s.requireInitialized(s.requireAuth(actorAuthed(s.handleVaultList))))
	mux.HandleFunc("DELETE /v1/vaults/{name}", s.requireInitialized(s.requireAuth(actorAuthed(s.handleVaultDelete))))
	mux.HandleFunc("POST /v1/vaults/{name}/rename", s.requireInitialized(s.requireAuth(actorAuthed(limitBody(s.handleVaultRename)))))
	mux.HandleFunc("POST /v1/vaults/{name}/join", s.requireInitialized(s.requireAuth(actorAuthed(limitBody(s.handleVaultJoin)))))
	mux.HandleFunc("POST /v1/vaults/{name}/leave", s.requireInitialized(s.requireAuth(actorAuthed(limitBody(s.handleVaultLeave)))))
	mux.HandleFunc("GET /v1/vaults/{name}/settings", s.requireInitialized(s.requireAuth(actorAuthed(s.handleVaultSettingsGet))))
	mux.HandleFunc("PATCH /v1/vaults/{name}/settings", s.requireInitialized(s.requireAuth(actorAuthed(limitBody(s.handleVaultSettingsPatch)))))
	mux.HandleFunc("PATCH /v1/vaults/{name}/credential-store", s.requireInitialized(s.requireAuth(actorAuthed(limitBody(s.handleVaultCredentialStorePatch)))))

	// Vault admin (owner-only)
	mux.HandleFunc("GET /v1/admin/vaults", s.requireInitialized(s.requireAuth(actorAuthed(s.handleAdminVaultList))))
	mux.HandleFunc("GET /v1/vaults/{name}/services", s.requireInitialized(s.requireAuth(actorAuthed(s.handleServicesGet))))
	mux.HandleFunc("POST /v1/vaults/{name}/services", s.requireInitialized(s.requireAuth(actorAuthed(limitBody(s.handleServicesUpsert)))))
	mux.HandleFunc("PUT /v1/vaults/{name}/services", s.requireInitialized(s.requireAuth(actorAuthed(limitBody(s.handleServicesSet)))))
	mux.HandleFunc("PATCH /v1/vaults/{name}/services/{host}", s.requireInitialized(s.requireAuth(actorAuthed(limitBody(s.handleServicePatch)))))
	mux.HandleFunc("DELETE /v1/vaults/{name}/services/{host}", s.requireInitialized(s.requireAuth(actorAuthed(s.handleServiceRemove))))
	mux.HandleFunc("DELETE /v1/vaults/{name}/services", s.requireInitialized(s.requireAuth(actorAuthed(s.handleServicesClear))))
	mux.HandleFunc("GET /v1/vaults/{name}/services/credential-usage", s.requireInitialized(s.requireAuth(actorAuthed(s.handleServicesCredentialUsage))))
	mux.HandleFunc("GET /v1/vaults/{name}/databases", s.requireInitialized(s.requireAuth(actorAuthed(s.handleDatabasesList))))
	mux.HandleFunc("POST /v1/vaults/{name}/databases", s.requireInitialized(s.requireAuth(actorAuthed(limitBody(s.handleDatabaseUpsert)))))
	mux.HandleFunc("GET /v1/vaults/{name}/databases/{db}", s.requireInitialized(s.requireAuth(actorAuthed(s.handleDatabaseGet))))
	mux.HandleFunc("DELETE /v1/vaults/{name}/databases/{db}", s.requireInitialized(s.requireAuth(actorAuthed(s.handleDatabaseRemove))))
	mux.HandleFunc("GET /v1/vaults/{name}/logs", s.requireInitialized(s.requireAuth(actorAuthed(s.handleVaultLogsList))))
	mux.HandleFunc("GET /v1/vaults/{name}/discovered-hosts", s.requireInitialized(s.requireAuth(actorAuthed(s.handleDiscoveredHosts))))
	// Public static reads carry no credentials, so only TierGlobal applies; TierAuth would punish `vault run` CA fetches.
	mux.HandleFunc("GET /v1/service-catalog", s.requireInitialized(s.handleServiceCatalog))
	mux.HandleFunc("GET /v1/skills/cli", s.requireInitialized(s.handleSkillCLI))
	// CA PEM is not wrapped in requireInitialized — the CA lifecycle is
	// tied to --mitm-port, not owner registration.
	mux.HandleFunc("GET /v1/mitm/ca.pem", s.handleMITMCA)

	// Instance-level user invites
	mux.HandleFunc("POST /v1/users/invites", s.requireInitialized(s.requireAuth(actorAuthed(limitBody(s.handleUserInviteCreate)))))
	mux.HandleFunc("GET /v1/users/invites", s.requireInitialized(s.requireAuth(actorAuthed(s.handleUserInviteList))))
	mux.HandleFunc("DELETE /v1/users/invites/{token}", s.requireInitialized(s.requireAuth(actorAuthed(s.handleUserInviteRevoke))))
	mux.HandleFunc("POST /v1/users/invites/{token}/reinvite", s.requireInitialized(s.requireAuth(actorAuthed(limitBody(s.handleUserInviteReinvite)))))
	mux.HandleFunc("GET /v1/users/invites/{token}/details", s.requireInitialized(ipUserInviteToken(s.handleUserInviteDetails)))
	mux.HandleFunc("POST /v1/users/invites/{token}/accept", s.requireInitialized(ipUserInviteToken(limitBody(s.handleUserInviteAccept))))

	// Vault user management (vault admin)
	mux.HandleFunc("GET /v1/vaults/{name}/users", s.requireInitialized(s.requireAuth(actorAuthed(s.handleVaultUserList))))
	mux.HandleFunc("POST /v1/vaults/{name}/users", s.requireInitialized(s.requireAuth(actorAuthed(limitBody(s.handleVaultUserAdd)))))
	mux.HandleFunc("DELETE /v1/vaults/{name}/users/{email}", s.requireInitialized(s.requireAuth(actorAuthed(s.handleVaultUserRemove))))
	mux.HandleFunc("POST /v1/vaults/{name}/users/{email}/role", s.requireInitialized(s.requireAuth(actorAuthed(limitBody(s.handleVaultUserSetRole)))))

	// Proposal approval details (token-based, no auth required)
	mux.HandleFunc("GET /v1/proposals/approve-details", s.requireInitialized(ipApprovalToken(s.handleProposalApproveDetails)))

	// Admin proposal management
	mux.HandleFunc("GET /v1/database-cleanup", s.requireInitialized(s.requireAuth(actorAuthed(s.handleDatabaseCleanupList))))
	mux.HandleFunc("POST /v1/database-cleanup/{accessor}/confirm", s.requireInitialized(s.requireAuth(actorAuthed(limitBody(s.handleDatabaseCleanupConfirm)))))
	mux.HandleFunc("GET /v1/admin/proposals", s.requireInitialized(s.requireAuth(actorAuthed(s.handleAdminProposalList))))
	mux.HandleFunc("GET /v1/admin/proposals/{id}", s.requireInitialized(s.requireAuth(actorAuthed(s.handleAdminProposalGet))))

	// Email
	mux.HandleFunc("POST /v1/admin/email/test", s.requireInitialized(s.requireAuth(actorAuthed(limitBody(s.handleEmailTest)))))

	mux.HandleFunc("POST /v1/auth/logout", s.requireInitialized(ipAuth(s.handleLogout)))

	// React app static assets (Vite outputs to /assets/ with base "/")
	webFS, _ := fs.Sub(webDistFS, "webdist")
	static := http.FileServer(http.FS(webFS))
	mux.Handle("GET /assets/", cacheStatic(cacheImmutable, static))
	// Files Vite copies verbatim from web/public/ (favicons, fonts) need routes or they 404; names are unhashed so cache lifetime is modest.
	mux.Handle("GET /fonts/", cacheStatic(cacheDay, static))
	mux.Handle("GET /favicon.svg", cacheStatic(cacheDay, static))
	mux.Handle("GET /favicon.png", cacheStatic(cacheDay, static))

	// SPA catch-all: serve index.html for all frontend routes
	mux.HandleFunc("GET /login", s.handleSPA)
	mux.HandleFunc("GET /register", s.handleSPA)
	mux.HandleFunc("GET /forgot-password", s.handleSPA)
	mux.HandleFunc("GET /users", s.handleSPA)
	mux.HandleFunc("GET /agents", s.handleSPA)
	mux.HandleFunc("GET /vaults/{$}", s.handleSPA)
	mux.HandleFunc("GET /vaults/{name...}", s.handleSPA)
	mux.HandleFunc("GET /invite/{token...}", s.handleSPA)
	mux.HandleFunc("GET /approve/{id...}", s.handleSPA)
	mux.HandleFunc("GET /oauth/complete", s.handleSPA)
	mux.HandleFunc("GET /manage/{path...}", s.handleSPA)
	mux.HandleFunc("GET /change-password", s.handleSPA)
	mux.HandleFunc("GET /account/{path...}", s.handleSPA)
	mux.HandleFunc("GET /{$}", s.handleSPA)

	s.initialized.Store(initialized)
	return s
}

// Cache lifetimes: /assets/ names carry a content hash so are immutable; files copied from web/public/ keep stable names so get a modest lifetime.
const (
	cacheImmutable = "public, max-age=31536000, immutable"
	cacheDay       = "public, max-age=86400"
)

// cacheStatic sets Cache-Control on embedded build output, which has no ModTime or ETag to revalidate against.
// Only successful responses are marked: during a rolling upgrade a cached 404 chunk would wedge the UI for a year.
func cacheStatic(cacheControl string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(&staticCacheWriter{ResponseWriter: w, cacheControl: cacheControl}, r)
	})
}

// staticCacheWriter sets the Cache-Control header on 200 and 206 responses,
// just before the status line is written.
type staticCacheWriter struct {
	http.ResponseWriter
	cacheControl string
	wroteHeader  bool
}

func (w *staticCacheWriter) WriteHeader(code int) {
	if !w.wroteHeader {
		w.wroteHeader = true
		if code == http.StatusOK || code == http.StatusPartialContent {
			w.Header().Set("Cache-Control", w.cacheControl)
		}
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *staticCacheWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

// requireInitialized returns 503 when no owner exists, re-checking the DB at most every 2 seconds for multi-instance deployments.
func (s *Server) requireInitialized(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.initialized.Load() {
			now := time.Now().UnixMilli()
			if now-s.lastInitCheck.Load() < 2000 {
				jsonStatus(w, http.StatusServiceUnavailable, map[string]string{
					"error":   "not_initialized",
					"message": "No owner account exists. Run 'agent-vault auth register' to create the first account.",
				})
				return
			}
			s.lastInitCheck.Store(now)
			if count, err := s.store.CountUsers(r.Context()); err == nil && count > 0 {
				s.initialized.Store(true)
			} else {
				jsonStatus(w, http.StatusServiceUnavailable, map[string]string{
					"error":   "not_initialized",
					"message": "No owner account exists. Run 'agent-vault auth register' to create the first account.",
				})
				return
			}
		}
		next(w, r)
	}
}

// Start starts the server and blocks until shutdown.
// It listens for SIGINT/SIGTERM to shut down gracefully.
func (s *Server) Start() error {
	// Registered first so it runs last, after the Vault logins are revoked.
	defer func() {
		for _, fn := range s.finalShutdownFuncs {
			fn()
		}
	}()
	// Vault logins are revoked last, after the database cleanup that needs them.
	if s.hashicorpClient != nil {
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), vaultCloseTimeout)
			defer cancel()
			s.hashicorpClient.CloseContext(ctx)
		}()
	}
	if s.pgLeaseCloser != nil {
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := s.pgLeaseCloser.Close(ctx); err != nil {
				s.logger.Warn("database cleanup shutdown incomplete")
			}
		}()
	}
	defer func() {
		for _, fn := range s.shutdownFuncs {
			fn()
		}
	}()
	if err := s.prepareCredentialProxy(context.Background()); err != nil {
		return err
	}
	var strictMITMLn net.Listener
	if s.credentialProxy {
		if s.mitm == nil {
			return fmt.Errorf("credential proxy requires its HTTP proxy listener")
		}
		var err error
		strictMITMLn, err = net.Listen("tcp", s.mitm.Addr())
		if err != nil {
			return fmt.Errorf("listen credential proxy: %w", err)
		}
		defer func() { _ = strictMITMLn.Close() }()
	}
	// Non-fatal: registry already holds env-based config from New().
	if s.initialized.Load() {
		if _, err := s.applyRateLimitSettingToRegistry(context.Background()); err != nil {
			s.logger.Warn("ratelimit setting load failed", "err", err.Error())
		}
	}

	// Bind synchronously so EADDRINUSE returns before pidfile work and cannot clobber a running daemon's PID file.
	httpLn := s.httpListener
	var err error
	if httpLn == nil {
		if httpLn, err = net.Listen("tcp", s.httpServer.Addr); err != nil {
			return fmt.Errorf("listen %s: %w", s.httpServer.Addr, err)
		}
	}

	defer func() { _ = httpLn.Close() }()
	var pgLn net.Listener
	if s.pgBroker != nil {
		pgLn, err = net.Listen("tcp", s.pgBroker.Addr())
		if err != nil {
			return fmt.Errorf("listen postgres broker: %w", err)
		}
		defer func() { _ = pgLn.Close() }()
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = s.pgBroker.Shutdown(ctx)
		}()
		if s.pgTLS != nil {
			tlsLn, err := net.Listen("tcp", s.pgTLS.addr)
			if err != nil {
				return fmt.Errorf("listen postgres broker TLS: %w", err)
			}
			defer func() { _ = tlsLn.Close() }()
			merged := newMergedListener(pgLn)
			pgLn = merged
			fmt.Printf("Agent Vault PostgreSQL TLS listener on %s\n", tlsLn.Addr())
			go func() { _ = servePostgresTLS(tlsLn, merged, s.pgTLS.config(), s.logger) }()
		}
	} else if s.pgTLS != nil {
		return fmt.Errorf("the PostgreSQL TLS listener requires the PostgreSQL broker")
	}
	// An unrecoverable accept loop sends here so the Pod restarts instead of refusing clients silently.
	errCh := make(chan error, 8)
	if s.crossClusterAddr != "" {
		if s.pgTLS != nil {
			return fmt.Errorf("the PostgreSQL TLS listener cannot be combined with the cross-cluster listener")
		}
		if !s.credentialProxy || strictMITMLn == nil {
			return fmt.Errorf("the cross-cluster listener requires the credential proxy")
		}
		crossLn, err := net.Listen("tcp", s.crossClusterAddr)
		if err != nil {
			return fmt.Errorf("listen cross-cluster: %w", err)
		}
		defer func() { _ = crossLn.Close() }()
		httpMerged := newMergedListener(strictMITMLn)
		strictMITMLn = httpMerged
		var pgMerged *mergedListener
		if pgLn != nil {
			pgMerged = newMergedListener(pgLn)
			pgLn = pgMerged
		}
		var certLn *injectedListener
		if s.proxyCerts != nil || s.proxyActivity != nil {
			mux := http.NewServeMux()
			if s.proxyCerts != nil {
				s.proxyCerts.Register(mux)
			}
			if s.proxyActivity != nil {
				s.proxyActivity.Register(mux)
			}
			certLn = newInjectedListener(crossLn.Addr())
			certServer := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
				WriteTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
			defer func() { _ = certServer.Close() }()
			go func() { _ = certServer.Serve(certLn) }()
		}
		fmt.Printf("Agent Vault cross-cluster listener on %s (proxy-attested only)\n", crossLn.Addr())
		go func() {
			if err := serveCrossCluster(crossLn, httpMerged, pgMerged, certLn, s.crossClusterLimits.withDefaults(), s.logger); !errors.Is(err, net.ErrClosed) {
				errCh <- err
			}
		}()
	}
	if s.staticTokenAddr != "" {
		if !s.credentialProxy || strictMITMLn == nil {
			return fmt.Errorf("the static-token listener requires the credential proxy")
		}
		staticLn, err := net.Listen("tcp", s.staticTokenAddr)
		if err != nil {
			return fmt.Errorf("listen static-token: %w", err)
		}
		defer func() { _ = staticLn.Close() }()
		httpMerged := newMergedListener(strictMITMLn)
		strictMITMLn = httpMerged
		fmt.Printf("Agent Vault static-token listener on %s (static-token only)\n", staticLn.Addr())
		go func() {
			if err := serveStaticToken(staticLn, httpMerged, s.logger); !errors.Is(err, net.ErrClosed) {
				errCh <- err
			}
		}()
	}
	observerLn, err := s.listenCleanupObserver()
	if err != nil {
		return err
	}
	if observerLn != nil {
		defer func() { _ = observerLn.Close(); _ = s.cleanupObserverServer.Close() }()
	}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(stop)

	pruneCtx, stopWorkers := context.WithCancel(context.Background())
	defer stopWorkers()
	go s.runTouchCachePruner(pruneCtx)
	if s.store.DialectName() == "postgres" {
		go s.watchStore(pruneCtx)
	}

	// Block on every syncer's in-flight refreshes before WipeBytes: a refresh mid-AES-GCM must never read a zeroed encKey.
	var syncerDones []chan struct{}
	runSyncer := func(run func(context.Context)) {
		done := make(chan struct{})
		syncerDones = append(syncerDones, done)
		go func() {
			defer close(done)
			run(pruneCtx)
		}()
	}
	if s.infisicalSyncer == nil && s.infisicalClient != nil {
		s.infisicalSyncer = infisical.NewSyncer(s.store, s.infisicalClient, s.encKey, s.logger)
	}
	if s.infisicalSyncer != nil {
		runSyncer(s.infisicalSyncer.Run)
	}
	if !s.credentialProxy && s.hashicorpSyncer == nil && s.hashicorpClient != nil {
		s.hashicorpSyncer = hashicorp.NewSyncer(s.store, s.hashicorpClient, s.encKey, s.logger)
	}
	if !s.credentialProxy && s.hashicorpSyncer != nil {
		runSyncer(s.hashicorpSyncer.Run)
	}

	// Dynamic-secret resolver: leases minted on demand from the proxy path.
	// Sweep orphaned leases (rows surviving a prior process) in the background.
	if s.infisicalDynamic == nil && s.infisicalClient != nil {
		s.infisicalDynamic = infisical.NewDynamicResolver(s.store, s.infisicalClient, s.logger)
	}
	if s.infisicalDynamic != nil {
		go s.infisicalDynamic.SweepOrphans(pruneCtx)
	}

	if observerLn != nil {
		go func() {
			if err := s.cleanupObserverServer.Serve(observerLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- fmt.Errorf("cleanup observer stopped: %w", err)
			}
		}()
	}
	go func() {
		fmt.Printf("Agent Vault server listening on %s\n", s.baseURL)
		if !s.initialized.Load() {
			fmt.Printf("Run `agent-vault auth register` or visit %s to create the owner account\n", s.baseURL)
		}
		if err := s.httpServer.Serve(httpLn); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	if s.mitm != nil {
		go func() {
			l := strictMITMLn
			var err error
			if l == nil {
				l, err = net.Listen("tcp", s.mitm.Addr())
			}
			if err != nil {
				// MITM is best-effort (e.g. default-on port conflict shouldn't
				// kill the core HTTP server). Log and let the goroutine exit.
				fmt.Fprintf(os.Stderr, "warning: transparent proxy unavailable: %v\n", err)
				return
			}
			fmt.Printf("Agent Vault transparent proxy listening on %s\n", s.mitm.Addr())
			if err := s.mitm.Serve(l); err != nil && err != http.ErrServerClosed {
				if s.credentialProxy {
					errCh <- fmt.Errorf("credential proxy stopped: %w", err)
					return
				}
				fmt.Fprintf(os.Stderr, "warning: transparent proxy stopped: %v\n", err)
			}
		}()
	}

	if s.pgBroker != nil {
		go func() {
			fmt.Printf("Agent Vault postgres broker listening on %s\n", pgLn.Addr())
			if err := s.pgBroker.Serve(pgLn); err != nil && !errors.Is(err, net.ErrClosed) {
				errCh <- fmt.Errorf("postgres broker stopped: %w", err)
			}
		}()
	}

	if err := pidfile.WriteIfFree(os.Getpid()); err != nil {
		if errors.Is(err, pidfile.ErrAlreadyRunning) {
			s.logger.Warn("pidfile owned by another process; not claiming or removing it")
		} else {
			fmt.Fprintf(os.Stderr, "warning: could not write PID file: %v\n", err)
		}
	} else {
		defer func() { _ = pidfile.Remove() }()
	}

	select {
	case err := <-errCh:
		_ = s.httpServer.Close()
		if s.mitm != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = s.mitm.Shutdown(ctx)
			cancel()
		}
		return err
	case <-stop:
	}
	s.beginShutdown()

	ctx, cancel := context.WithTimeout(context.Background(), s.shutdownBudget())
	defer cancel()

	fmt.Println("shutting down server...")
	// Start every shutdown together so one slow subsystem cannot consume the database broker's revoke budget.
	var shutdownWG sync.WaitGroup
	shutdown := func(name string, fn func(context.Context) error) {
		shutdownWG.Add(1)
		go func() {
			defer shutdownWG.Done()
			if err := fn(ctx); err != nil {
				s.logger.Warn("shutdown incomplete", "component", name, "error", err)
			}
		}()
	}
	if s.pgBroker != nil {
		shutdown("postgres broker", s.pgBroker.Shutdown)
	}
	if s.mitm != nil {
		shutdown("HTTP proxy", s.mitm.Shutdown)
	}
	if s.cleanupObserverServer != nil {
		shutdown("cleanup observer", s.cleanupObserverServer.Shutdown)
	}
	httpErr := s.httpServer.Shutdown(ctx)
	shutdownWG.Wait()
	if httpErr != nil {
		return fmt.Errorf("server shutdown: %w", httpErr)
	}

	stopWorkers()
	deadline := time.After(5 * time.Second)
	for _, done := range syncerDones {
		select {
		case <-done:
		case <-deadline:
			fmt.Fprintln(os.Stderr, "warning: external-store syncer did not stop within 5s; skipping key wipe to avoid racing in-flight encrypts")
			return nil
		}
	}

	// Revoke outstanding dynamic-secret leases (best-effort, self-bounded).
	// Independent of s.encKey: revocation needs only lease IDs + the client.
	if s.infisicalDynamic != nil {
		s.infisicalDynamic.Close(context.Background())
	}

	fmt.Println("server shut down gracefully")
	crypto.WipeBytes(s.encKey)
	return nil
}

func (s *Server) beginShutdown() {
	s.shuttingDown.Store(true)
	if drain, ok := s.pgLeaseCloser.(interface{ BeginDrain() }); ok {
		drain.BeginDrain()
	}
}

var errTooManyPendingCodes = errors.New("too many pending verification codes")

// vaultCloseTimeout: the shutdown drain, the 5s database cleanup, this and the 5s audit flush must fit in the Pod's termination grace.
const vaultCloseTimeout = 5 * time.Second

const passwordResetTTL = 15 * time.Minute

const maxPendingPasswordResets = 3

type loginRequest struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	DeviceLabel string `json:"device_label,omitempty"` // optional, e.g. CLI hostname
}

// maxDeviceLabelRunes caps device_label in runes so a multi-byte character is never cut into invalid UTF-8.
const maxDeviceLabelRunes = 64

// truncateDeviceLabel strips control characters and caps length in runes; empty input returns "".
func truncateDeviceLabel(label string) string {
	label = strings.TrimSpace(label)
	if label == "" {
		return ""
	}
	cleaned := make([]rune, 0, len(label))
	for _, r := range label {
		if r < 0x20 || r == 0x7f {
			continue
		}
		cleaned = append(cleaned, r)
	}
	if len(cleaned) > maxDeviceLabelRunes {
		cleaned = cleaned[:maxDeviceLabelRunes]
	}
	return string(cleaned)
}

type loginResponse struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
}

// registerResponse is the JSON returned by POST /v1/auth/register; Token and ExpiresAt are set only on the auto-login path.
type registerResponse struct {
	Email                string `json:"email"`
	Role                 string `json:"role,omitempty"`
	RequiresVerification bool   `json:"requires_verification"`
	EmailSent            bool   `json:"email_sent"`
	Authenticated        bool   `json:"authenticated"`
	Message              string `json:"message"`
	Token                string `json:"token,omitempty"`
	ExpiresAt            string `json:"expires_at,omitempty"`
}

// userSessionAbsoluteTTL caps a user session's lifetime; userSessionIdleTTL rejects sessions unused that long, limiting a stolen session.json.
const (
	userSessionAbsoluteTTL = 365 * 24 * time.Hour
	userSessionIdleTTL     = 30 * 24 * time.Hour
)

// trustedProxyCIDRs holds parsed CIDR ranges from AGENT_VAULT_TRUSTED_PROXIES.
// When non-empty, X-Forwarded-For is only trusted if RemoteAddr matches one of these.
var trustedProxyCIDRs []net.IPNet

func init() {
	trustedProxyCIDRs = netguard.ParseCIDRList(os.Getenv("AGENT_VAULT_TRUSTED_PROXIES"), "AGENT_VAULT_TRUSTED_PROXIES")
}

// ipKeyer returns a ratelimit.Keyer that keys on the request's client IP
// (honoring AGENT_VAULT_TRUSTED_PROXIES via clientIP).
func (s *Server) ipKeyer() ratelimit.Keyer {
	return ratelimit.IPKey(clientIP)
}

// actorKeyer keys the rate limiter on the authenticated actor; "" without a session is safe since actor tiers wrap requireAuth.
func (s *Server) actorKeyer() ratelimit.Keyer {
	return ratelimit.ActorKey(func(r *http.Request) string {
		sess := sessionFromContext(r.Context())
		if sess == nil {
			return ""
		}
		if sess.UserID != "" {
			return "u:" + sess.UserID
		}
		return "a:" + sess.AgentID
	})
}

// tier wraps handler with a rate-limit check for tier keyed by keyer, writing 429 on denial.
func (s *Server) tier(t ratelimit.Tier, keyer ratelimit.Keyer) func(http.HandlerFunc) http.HandlerFunc {
	return s.rateLimit.HandlerFunc(t, keyer, s.logger)
}

// requireAuth wraps a handler and validates the Bearer token or av_session cookie.
// The authenticated session is stored in the request context.
func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var token string
		header := r.Header.Get("Authorization")
		if strings.HasPrefix(header, "Bearer ") {
			token = strings.TrimPrefix(header, "Bearer ")
		} else if c, err := r.Cookie("av_session"); err == nil && c.Value != "" {
			token = c.Value
		} else {
			jsonError(w, http.StatusUnauthorized, "Authorization required")
			return
		}

		sess, err := s.store.GetSession(r.Context(), token)
		if err != nil || sess == nil {
			jsonError(w, http.StatusUnauthorized, "Invalid or expired session")
			return
		}
		if sess.IsExpired(time.Now()) {
			jsonError(w, http.StatusUnauthorized, "Session expired")
			return
		}

		s.maybeTouchSession(r.Context(), sess, token, clientIP(r), r.UserAgent())

		ctx := context.WithValue(r.Context(), sessionContextKey, sess)
		next(w, r.WithContext(ctx))
	}
}

// maybeTouchSession bumps last_used_at, last_ip and last_user_agent behind an in-memory cache; the store-side throttle remains as defense in depth.
func (s *Server) maybeTouchSession(ctx context.Context, sess *store.Session, rawToken, ip, userAgent string) {
	if sess == nil || sess.UserID == "" {
		return
	}
	now := time.Now()
	if last, ok := s.touchCache.Load(rawToken); ok {
		if t, _ := last.(time.Time); now.Sub(t) < store.TouchInterval {
			return
		}
	}
	s.touchCache.Store(rawToken, now)
	_ = s.store.TouchSession(ctx, rawToken, ip, userAgent)
}

// pruneTouchCache drops entries past 2x TouchInterval so active sessions are not evicted and re-stored.
func (s *Server) pruneTouchCache() {
	cutoff := time.Now().Add(-2 * store.TouchInterval)
	s.touchCache.Range(func(key, val any) bool {
		if t, ok := val.(time.Time); ok && t.Before(cutoff) {
			s.touchCache.Delete(key)
		}
		return true
	})
}

// runTouchCachePruner runs pruneTouchCache on a ticker until ctx is cancelled.
func (s *Server) runTouchCachePruner(ctx context.Context) {
	ticker := time.NewTicker(store.TouchInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.pruneTouchCache()
		}
	}
}

const (
	scopedSessionMinTTL     = 5 * time.Minute
	scopedSessionMaxTTL     = 7 * 24 * time.Hour
	scopedSessionDefaultTTL = 24 * time.Hour // when ttl_seconds is unset
)

// isSecureRequest reports whether the request arrived over TLS, using the trusted baseURL so X-Forwarded-Proto cannot spoof it.
func isSecureRequest(r *http.Request, baseURL string) bool {
	if r.TLS != nil {
		return true
	}
	return strings.HasPrefix(baseURL, "https://")
}

// sessionCookie builds an av_session cookie with all hardening flags set.
// Secure is set based on TLS state or the server's configured baseURL.
func sessionCookie(r *http.Request, baseURL, value string, maxAge int) *http.Cookie {
	return &http.Cookie{ //nolint:gosec // G124: HttpOnly and SameSite are fixed; Secure follows TLS, as a plain-HTTP local server cannot set it
		Name:     "av_session",
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   isSecureRequest(r, baseURL),
		SameSite: http.SameSiteStrictMode,
		MaxAge:   maxAge,
	}
}

// timePtr returns a pointer to the given time value.
func timePtr(t time.Time) *time.Time { return &t }

// formatExpiresAt returns an RFC3339 UTC string for an optional time, or "" if nil.
func formatExpiresAt(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

const settingAllowedDomains = "allowed_email_domains"

const settingInviteOnly = "invite_only"

const settingRateLimitConfig = "ratelimit_config"

// settingUnmatchedHostPolicy is the per-vault key in vault_settings that
// controls whether requests to unmatched hosts passthrough or are denied.
const settingUnmatchedHostPolicy = "unmatched_host_policy"
