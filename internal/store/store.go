package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"
)

// ErrNotFirstUser is returned by RegisterFirstUser when users already exist.
var ErrNotFirstUser = errors.New("users already exist; not first user")

// DefaultVault is the name of the automatically-seeded vault.
const DefaultVault = "default"

// Vault represents a logical grouping of credentials.
type Vault struct {
	ID        string
	Name      string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// VaultGrant represents an actor's (user or agent) access to a vault with a specific role.
type VaultGrant struct {
	ActorID   string
	ActorType string // "user" or "agent"
	VaultID   string
	VaultName string // populated via JOIN on reads (optional)
	Role      string // "proxy", "member", or "admin"
	CreatedAt time.Time
}

// Credential is an encrypted credential within a vault; encryption is the caller's job.
type Credential struct {
	ID         string
	VaultID    string
	Key        string
	Type       string // "static" (default) or "oauth"
	Ciphertext []byte
	Nonce      []byte
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// CredentialOAuth stores OAuth config and refresh state; the access token lives in credentials.ciphertext.
type CredentialOAuth struct {
	VaultID            string
	CredentialKey      string
	AuthorizationURL   string // empty = token upload mode
	TokenURL           string
	ClientID           string
	ClientSecretCT     []byte // nil for public clients
	ClientSecretNonce  []byte
	Scopes             string
	ScopeSeparator     string
	DisablePKCE        bool
	TokenAuthMethod    string // "client_secret_post" or "client_secret_basic"
	RefreshTokenCT     []byte
	RefreshTokenNonce  []byte
	TokenExpiresAt     *time.Time
	ConnectedAt        *time.Time
	LastRefreshedAt    *time.Time
	LastRefreshError   string
	LastRefreshErrorAt *time.Time
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

// CredentialOAuthState holds a CSRF state + PKCE verifier for an
// in-flight OAuth consent redirect.
type CredentialOAuthState struct {
	ID            string
	StateHash     string
	CodeVerifier  string
	VaultID       string
	CredentialKey string
	RedirectURL   string
	CreatedAt     time.Time
	ExpiresAt     time.Time
}

// OAuthCredentialConfig carries the OAuth provider config for a credential slot in ApplyProposal.
type OAuthCredentialConfig struct {
	Key               string
	AuthorizationURL  string
	TokenURL          string
	ClientID          string
	ClientSecretCT    []byte
	ClientSecretNonce []byte
	Scopes            string
	ScopeSeparator    string
	DisablePKCE       bool
	TokenAuthMethod   string
}

// MasterKeyRecord holds the KEK/DEK key-wrapping artifacts; DEKPlaintext is set only in passwordless mode.
type MasterKeyRecord struct {
	Sentinel      []byte // sentinel ciphertext (encrypted with DEK)
	SentinelNonce []byte // sentinel GCM nonce
	DEKCiphertext []byte // wrapped DEK (nil in passwordless mode)
	DEKNonce      []byte // DEK wrapping nonce (nil in passwordless mode)
	DEKPlaintext  []byte // unwrapped DEK (nil when password-protected)
	Salt          []byte // KDF salt (nil in passwordless mode)
	KDFTime       *uint32
	KDFMemory     *uint32
	KDFThreads    *uint8
	KDFAlgorithm  string // "pbkdf2-sha256" or legacy "argon2id"
	// KMSWrappedDEK is the DEK wrapped by the cloud key named in KMSKeyName (nil when unused).
	KMSWrappedDEK []byte
	KMSKeyName    string // "gcpkms://..." or "awskms://..." as configured; empty when unused
	WrapKind      string // WrapKindPassword (also passwordless), WrapKindKMS, or WrapKindKMSFallback
	CreatedAt     time.Time
}

// Wrap kinds: which wrap unlocks the DEK first at startup.
const (
	WrapKindPassword = "password"
	WrapKindKMS      = "kms"
	// WrapKindKMSFallback marks a KMS vault whose last unlock went through the break-glass password.
	WrapKindKMSFallback = "kms-password-fallback"
)

// Session represents an authenticated session.
// User sessions may be scoped to a VaultID or global; agent tokens have none and resolve the vault per request via X-Vault.
type Session struct {
	ID        string
	UserID    string     // non-empty for user login sessions, empty for agent tokens
	VaultID   string     // empty for global/agent tokens, non-empty for user scoped sessions
	AgentID   string     // non-empty for agent tokens
	VaultRole string     // set for user scoped sessions; empty for agent tokens (resolved per-request)
	ExpiresAt *time.Time // nil = never expires
	CreatedAt time.Time

	// User-session sliding-expiry fields. Populated by CreateUserSession;
	// left zero for scoped sessions and agent tokens.
	PublicID      string        // short opaque handle for revoke endpoint; empty for scoped/agent
	LastUsedAt    *time.Time    // last time the token was successfully resolved
	IdleTTL       time.Duration // 0 = no idle expiry (agent tokens, legacy rows)
	DeviceLabel   string        // user-visible label, e.g. hostname
	LastIP        string
	LastUserAgent string

	// Scoped-session metadata, set only for vault-scoped tokens.
	Label              string
	CreatedByActorID   string
	CreatedByActorType string
}

// IsExpired reports whether the session is past its absolute expiry or idle window.
func (s *Session) IsExpired(now time.Time) bool {
	if s.ExpiresAt != nil && now.After(*s.ExpiresAt) {
		return true
	}
	if s.IdleTTL > 0 && s.LastUsedAt != nil && now.Sub(*s.LastUsedAt) > s.IdleTTL {
		return true
	}
	return false
}

// CreateUserSessionParams carries the fields persisted on a user-login session.
type CreateUserSessionParams struct {
	UserID        string
	ExpiresAt     time.Time
	IdleTTL       time.Duration
	DeviceLabel   string
	LastIP        string
	LastUserAgent string
}

// CreateScopedSessionParams carries the fields persisted on a vault-scoped token; nil ExpiresAt never expires.
type CreateScopedSessionParams struct {
	VaultID            string
	VaultRole          string
	ExpiresAt          *time.Time
	Label              string
	CreatedByActorID   string
	CreatedByActorType string // "user" or "agent"
}

// User represents a human user account.
type User struct {
	ID           string
	Email        string
	PasswordHash []byte
	PasswordSalt []byte
	KDFTime      uint32 // iterations (PBKDF2) or passes (Argon2id) used when password was hashed
	KDFMemory    uint32 // Argon2id memory (KiB); 0 for PBKDF2
	KDFThreads   uint8  // Argon2id threads; 0 for PBKDF2
	KDFAlgorithm string // "pbkdf2-sha256" or legacy "argon2id"
	Role         string // "owner", "member", or "no-access"
	IsActive     bool   // false until email is verified (first user is auto-active)
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// BrokerConfig holds the brokering services for a vault.
type BrokerConfig struct {
	ID           string
	VaultID      string
	ServicesJSON string // JSON-encoded []broker.Service
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// DatabaseService is a managed upstream database; Vault mints its short-lived credentials, the broker never stores a password.
type DatabaseService struct {
	ID        string
	VaultID   string
	Name      string
	Upstream  string // host:port
	Database  string // upstream database override; empty honors the client's requested database
	Mount     string // Vault database secrets-engine mount (e.g. "database")
	Role      string // Vault role granting scoped SQL privileges
	SSLMode   string // upstream TLS: disable|prefer|require|verify-full
	MaxConns  int    // per-database connection budget (0 = broker default)
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Proposal represents a proposed set of changes (services + credential slots)
// created by an agent, pending human approval.
type Proposal struct {
	ID                     int // sequential per vault (1, 2, 3, ...)
	VaultID                string
	SessionID              string
	Status                 string
	ServicesJSON           string
	CredentialsJSON        string
	Message                string
	UserMessage            string // human-facing explanation shown on the browser approval page
	ReviewNote             string
	ReviewedAt             *string
	ApprovalToken          string     // random token for browser-based approval URL
	ApprovalTokenExpiresAt *time.Time // expiry for the approval token (default 24h)
	CreatedAt              time.Time
	UpdatedAt              time.Time
}

// EncryptedCredential holds an encrypted credential value (ciphertext + nonce).
type EncryptedCredential struct {
	Ciphertext []byte
	Nonce      []byte
}

// EncryptedKV pairs a credential key with its AES-256-GCM ciphertext+nonce.
type EncryptedKV struct {
	Key        string
	Ciphertext []byte
	Nonce      []byte
}

// Wire-protocol values for VaultCredentialStore.Kind. KindBuiltin is the
// API sentinel for "no external store" and is never persisted.
const (
	CredentialStoreBuiltin   = "builtin"
	CredentialStoreInfisical = "infisical"
	CredentialStoreHashicorp = "hashicorp"
)

// Wire-protocol values for VaultCredentialStore.LastSyncStatus.
const (
	SyncStatusOK    = "ok"
	SyncStatusError = "error"
)

// VaultCredentialStore is the per-vault external-source row; absence means built-in.
type VaultCredentialStore struct {
	VaultID             string
	Kind                string // CredentialStoreInfisical | CredentialStoreHashicorp
	ConfigJSON          string // per-kind config blob
	PollIntervalSeconds int
	LastSyncedAt        *time.Time
	LastSyncStatus      string // SyncStatus*
	LastSyncError       string
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

// DynamicSecretLease tracks an Infisical lease for revoke and restart sweep; holds no secret material.
type DynamicSecretLease struct {
	LeaseID           string
	VaultID           string
	DynamicSecretName string
	ProjectID         string
	Environment       string
	SecretPath        string
	ExpireAt          *time.Time
	CreatedAt         time.Time
}

// CreateExternalVaultParams carries inputs to CreateExternalVault. The
// creator is persisted as an admin vault_grants row in the same transaction.
type CreateExternalVaultParams struct {
	Name                string
	Kind                string
	ConfigJSON          string
	PollIntervalSeconds int
	Credentials         []EncryptedKV
	CreatorActorID      string
	CreatorActorType    string // "user" or "agent"
}

// SetVaultExternalStoreParams carries inputs to SetVaultExternalStore, used to
// connect an existing vault to an external store (built-in → external switch).
type SetVaultExternalStoreParams struct {
	VaultID             string
	Kind                string
	ConfigJSON          string
	PollIntervalSeconds int
	Credentials         []EncryptedKV
}

// RequestLog is a persisted record of one proxied request, secret-free by construction.
type RequestLog struct {
	ID             int64
	VaultID        string
	ActorType      string // brokercore.ActorType{User,Agent} or ""
	ActorID        string
	Ingress        string // brokercore.Ingress{Explicit,MITM}
	Method         string
	Host           string
	Path           string
	MatchedService string
	CredentialKeys []string
	Status         int
	LatencyMs      int64
	ErrorCode      string
	AuthScheme     string
	AuthHeader     string
	CreatedAt      time.Time
}

// ListRequestLogsOpts controls ListRequestLogs; set at most one of Before or After.
type ListRequestLogsOpts struct {
	VaultID        *string
	Ingress        string // "", "explicit", "mitm"
	StatusBucket   string // "", "2xx", "3xx", "4xx", "5xx", "err"
	MatchedService string
	Before         int64 // rows with id < Before (pagination going back)
	After          int64 // rows with id > After (polling for new rows)
	Limit          int   // capped at 200 by handler; store trusts caller
}

// UnmatchedHost is a host seen in proxy traffic that matched no service and was denied.
type UnmatchedHost struct {
	Host         string
	RequestCount int
	LastSeen     time.Time
	AuthScheme   string
	AuthHeader   string
}

// Agent represents a named, instance-level agent entity.
// Agents have multi-vault access via VaultGrant records and an instance-level role.
type Agent struct {
	ID        string
	Name      string
	Role      string // "owner", "member", or "no-access" (instance-level role, like users)
	Status    string // "active" or "revoked"
	CreatedBy string // user ID of the creator
	Vaults    []VaultGrant
	CreatedAt time.Time
	UpdatedAt time.Time
	RevokedAt *time.Time
}

// AgentVaultGrantSpec is a vault ID + vault role pair used when creating an agent.
type AgentVaultGrantSpec struct {
	VaultID string
	Role    string
}

// UserInvite represents an instance-level invitation for a new user.
// Invites bring users into the instance, with optional vault pre-assignment.
type UserInvite struct {
	ID         int
	Token      string // only populated on creation (not stored in DB)
	Email      string
	Role       string // "owner", "member", or "no-access" — instance role for the invited user
	Status     string // pending, accepted, expired, revoked
	CreatedBy  string // user ID of the inviter
	CreatedAt  time.Time
	ExpiresAt  time.Time
	AcceptedAt *time.Time
	Vaults     []UserInviteVault // pre-assigned vault access
}

// UserInviteVault represents a pre-assigned vault grant on a user invite.
type UserInviteVault struct {
	VaultID   string
	VaultName string // populated via JOIN on reads
	VaultRole string // "admin" or "member"
}

// EmailVerification holds a verification code for self-signup email confirmation.
type EmailVerification struct {
	ID        int
	Email     string
	Code      string
	Status    string // "pending", "verified", "expired"
	CreatedAt time.Time
	ExpiresAt time.Time
}

// PasswordReset holds a reset code for the forgot-password flow.
type PasswordReset struct {
	ID        int
	Email     string
	Code      string
	Status    string // "pending", "used", "expired"
	CreatedAt time.Time
	ExpiresAt time.Time
}

// CAState holds the persisted CA root certificate and encrypted private key.
type CAState struct {
	RootCert     []byte
	RootKeyCT    []byte
	RootKeyNonce []byte
	Source       string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// Store is the persistence interface for Agent Vault.
// All methods are safe for concurrent use.
type Store interface {
	// Vaults
	CreateVault(ctx context.Context, name string) (*Vault, error)
	// CreateVaultWithSetting is one transaction, so no reader sees the vault without the setting.
	CreateVaultWithSetting(ctx context.Context, name, key, value string) (*Vault, error)
	GetVault(ctx context.Context, name string) (*Vault, error)
	GetVaultByID(ctx context.Context, id string) (*Vault, error)
	ListVaults(ctx context.Context) ([]Vault, error)
	DeleteVault(ctx context.Context, name string) error
	RenameVault(ctx context.Context, oldName string, newName string) error

	// Credentials
	SetCredential(ctx context.Context, vaultID, key string, ciphertext, nonce []byte) (*Credential, error)
	GetCredential(ctx context.Context, vaultID, key string) (*Credential, error)
	ListCredentials(ctx context.Context, vaultID string) ([]Credential, error)
	DeleteCredential(ctx context.Context, vaultID, key string) error

	// OAuth credentials
	GetCredentialOAuth(ctx context.Context, vaultID, key string) (*CredentialOAuth, error)
	SetCredentialOAuth(ctx context.Context, oauth *CredentialOAuth) error
	UpdateCredentialOAuthTokens(ctx context.Context, vaultID, key string, accessCT, accessNonce, refreshCT, refreshNonce []byte, expiresAt *time.Time) error
	UpdateCredentialOAuthError(ctx context.Context, vaultID, key string, errMsg string) error

	// OAuth states (CSRF + PKCE for consent flow)
	CreateCredentialOAuthState(ctx context.Context, state *CredentialOAuthState) error
	GetCredentialOAuthStateByHash(ctx context.Context, stateHash string) (*CredentialOAuthState, error)
	DeleteCredentialOAuthState(ctx context.Context, id string) error
	ExpireCredentialOAuthStates(ctx context.Context, before time.Time) (int, error)

	// Users
	CreateUser(ctx context.Context, email string, passwordHash, passwordSalt []byte, role string, kdfTime uint32, kdfMemory uint32, kdfThreads uint8, kdfAlgorithm string) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	GetUserByID(ctx context.Context, id string) (*User, error)
	GetUserEmailByID(ctx context.Context, id string) (string, error)
	ListUsers(ctx context.Context) ([]User, error)
	UpdateUserRole(ctx context.Context, userID, role string) error
	UpdateUserPassword(ctx context.Context, userID string, passwordHash, passwordSalt []byte, kdfTime uint32, kdfMemory uint32, kdfThreads uint8, kdfAlgorithm string) error
	// UpgradeUserPasswordHash rewrites the row only while it still holds the hash and KDF params of expected as read; false means another writer won.
	UpgradeUserPasswordHash(ctx context.Context, expected *User, passwordHash, passwordSalt []byte, kdfTime uint32, kdfMemory uint32, kdfThreads uint8, kdfAlgorithm string) (bool, error)
	DeleteUser(ctx context.Context, userID string) error
	CountUsers(ctx context.Context) (int, error)
	CountOwners(ctx context.Context) (int, error)
	RegisterFirstUser(ctx context.Context, email string, passwordHash, passwordSalt []byte, defaultVaultID string, kdfTime uint32, kdfMemory uint32, kdfThreads uint8, kdfAlgorithm string) (*User, error)

	// Vault grants (unified: actor_id + actor_type)
	GrantVaultRole(ctx context.Context, actorID, actorType, vaultID, role string) error
	// GrantVaultRoleIfAbsent never changes an existing role and reports whether it granted.
	GrantVaultRoleIfAbsent(ctx context.Context, actorID, actorType, vaultID, role string) (bool, error)
	RevokeVaultAccess(ctx context.Context, actorID, vaultID string) error
	ListActorGrants(ctx context.Context, actorID string) ([]VaultGrant, error)
	HasVaultAccess(ctx context.Context, actorID, vaultID string) (bool, error)
	GetVaultRole(ctx context.Context, actorID, vaultID string) (string, error)
	CountVaultAdmins(ctx context.Context, vaultID string) (int, error)
	ListVaultMembers(ctx context.Context, vaultID string) ([]VaultGrant, error)
	ListVaultMembersByType(ctx context.Context, vaultID, actorType string) ([]VaultGrant, error)

	// User activation
	ActivateUser(ctx context.Context, userID string) error

	// Session cleanup
	DeleteUserSessions(ctx context.Context, userID string) error

	// Sessions
	CreateUserSession(ctx context.Context, p CreateUserSessionParams) (*Session, error)
	CreateScopedSession(ctx context.Context, p CreateScopedSessionParams) (*Session, error)
	GetSession(ctx context.Context, id string) (*Session, error)
	DeleteSession(ctx context.Context, id string) error
	// ListScopedSessionsByVault returns active vault-scoped tokens for the
	// vault, most recent first. Used by the Tokens tab.
	ListScopedSessionsByVault(ctx context.Context, vaultID string) ([]Session, error)
	// RevokeScopedSession deletes one scoped session by (vaultID, publicID).
	// Vault scoping prevents cross-vault revocation.
	RevokeScopedSession(ctx context.Context, vaultID, publicID string) error
	// TouchSession bumps last_used_at and last_ip/last_user_agent (empty leaves them), throttled to one write per minute; best-effort.
	TouchSession(ctx context.Context, rawToken, ip, userAgent string) error
	// ListUserSessions returns every non-expired user session for userID
	// (ordered most-recent activity first). Used by the auth-sessions UI.
	ListUserSessions(ctx context.Context, userID string) ([]Session, error)
	// RevokeUserSession deletes a session matching both userID
	// and publicID. Scoping by userID prevents cross-account revocation.
	RevokeUserSession(ctx context.Context, userID, publicID string) error

	// Broker configs
	SetBrokerConfig(ctx context.Context, vaultID string, servicesJSON string) (*BrokerConfig, error)
	GetBrokerConfig(ctx context.Context, vaultID string) (*BrokerConfig, error)

	// Database services
	UpsertDatabaseService(ctx context.Context, svc DatabaseService) (*DatabaseService, error)
	SeedDatabaseService(ctx context.Context, svc DatabaseService) (bool, error)
	GetDatabaseService(ctx context.Context, vaultID, name string) (*DatabaseService, error)
	ListDatabaseServices(ctx context.Context, vaultID string) ([]DatabaseService, error)
	DatabaseUpstreamLimit(ctx context.Context, upstream string) (int, error)
	DeleteDatabaseService(ctx context.Context, vaultID, name string) (bool, error)

	// Master key
	GetMasterKeyRecord(ctx context.Context) (*MasterKeyRecord, error)
	SetMasterKeyRecord(ctx context.Context, record *MasterKeyRecord) error
	UpdateMasterKeyRecord(ctx context.Context, record *MasterKeyRecord) error
	// UpgradeMasterKeyRecord rewrites the record only while it still has the salt and KDF params of expected as read; false means another writer won.
	UpgradeMasterKeyRecord(ctx context.Context, expected, record *MasterKeyRecord) (bool, error)
	// SetMasterKeyWrapKind records how a KMS vault last unlocked (WrapKindKMS or WrapKindKMSFallback); it never touches a password-kind record.
	SetMasterKeyWrapKind(ctx context.Context, kind string) error
	// ClearMasterKeyPlaintext removes the plaintext key from a KMS-wrapped record, only while the record still holds the KMS wrap and plaintext of expected as read; false means another writer won.
	ClearMasterKeyPlaintext(ctx context.Context, expected *MasterKeyRecord) (bool, error)
	// SetMasterKeyKMSWrap adds a KMS wrap beside an unchanged password wrap, only while the record still has the salt, wrapped key and KDF params of expected as read and no KMS wrap yet; false means another writer won.
	SetMasterKeyKMSWrap(ctx context.Context, expected *MasterKeyRecord, wrapped []byte, keyName string) (bool, error)
	// RemoveMasterKeyPasswordWrap drops the password wrap and any plaintext key, only while the record still has the KMS wrap and wrap kind of expected as read; false means another writer won.
	RemoveMasterKeyPasswordWrap(ctx context.Context, expected *MasterKeyRecord) (bool, error)

	// Proposals
	CreateProposal(ctx context.Context, vaultID, sessionID, servicesJSON, credentialsJSON, message, userMessage string, credentials map[string]EncryptedCredential) (*Proposal, error)
	GetProposal(ctx context.Context, vaultID string, id int) (*Proposal, error)
	GetProposalByApprovalToken(ctx context.Context, token string) (*Proposal, error)
	ListProposals(ctx context.Context, vaultID, status string) ([]Proposal, error)
	UpdateProposalStatus(ctx context.Context, vaultID string, id int, status, reviewNote string) error
	CountPendingProposals(ctx context.Context, vaultID string) (int, error)
	ExpirePendingProposals(ctx context.Context, before time.Time) (int, error)
	GetProposalCredentials(ctx context.Context, vaultID string, proposalID int) (map[string]EncryptedCredential, error)
	ApplyProposal(ctx context.Context, vaultID string, proposalID int, mergedServicesJSON string, credentials map[string]EncryptedCredential, deleteCredentialKeys []string, oauthConfigs []OAuthCredentialConfig) error

	// User invites (instance-level)
	CreateUserInvite(ctx context.Context, email, createdBy, role string, expiresAt time.Time, vaults []UserInviteVault) (*UserInvite, error)
	GetUserInviteByToken(ctx context.Context, token string) (*UserInvite, error)
	GetPendingUserInviteByEmail(ctx context.Context, email string) (*UserInvite, error)
	ListUserInvites(ctx context.Context, status string) ([]UserInvite, error)
	ListUserInvitesByVault(ctx context.Context, vaultID, status string) ([]UserInvite, error)
	AcceptUserInvite(ctx context.Context, token string) error
	RevokeUserInvite(ctx context.Context, token string) error
	UpdateUserInviteVaults(ctx context.Context, token string, vaults []UserInviteVault) error
	CountPendingUserInvites(ctx context.Context) (int, error)

	// Email verification
	CreateEmailVerification(ctx context.Context, email, code string, expiresAt time.Time) (*EmailVerification, error)
	GetPendingEmailVerification(ctx context.Context, email, code string) (*EmailVerification, error)
	MarkEmailVerificationUsed(ctx context.Context, id int) error
	CountPendingEmailVerifications(ctx context.Context, email string) (int, error)

	// Password resets
	CreatePasswordReset(ctx context.Context, email, code string, expiresAt time.Time) (*PasswordReset, error)
	GetPendingPasswordReset(ctx context.Context, email, code string) (*PasswordReset, error)
	MarkPasswordResetUsed(ctx context.Context, id int) error
	CountPendingPasswordResets(ctx context.Context, email string) (int, error)
	ExpirePendingPasswordResets(ctx context.Context, before time.Time) (int, error)

	// Agents
	CreateAgent(ctx context.Context, name, createdBy, role string) (*Agent, error)
	// CreateAgentWithGrantsAndToken creates an agent, grants and first token in one transaction.
	CreateAgentWithGrantsAndToken(ctx context.Context, name, createdBy, role string, vaultGrants []AgentVaultGrantSpec, tokenExpiresAt *time.Time) (*Agent, *Session, error)
	GetAgentByID(ctx context.Context, id string) (*Agent, error)
	GetAgentNameByID(ctx context.Context, id string) (string, error)
	GetAgentByName(ctx context.Context, name string) (*Agent, error)
	ListAgents(ctx context.Context, vaultID string) ([]Agent, error)
	ListAllAgents(ctx context.Context) ([]Agent, error)
	RevokeAgent(ctx context.Context, id string) error
	DeleteAgent(ctx context.Context, id string) error
	RenameAgent(ctx context.Context, id string, newName string) error
	UpdateAgentRole(ctx context.Context, agentID, role string) error
	CountAgentTokens(ctx context.Context, agentID string) (int, error)
	GetLatestAgentTokenExpiry(ctx context.Context, agentID string) (*time.Time, error)
	DeleteAgentTokens(ctx context.Context, agentID string) error
	// RotateAgentToken deletes the agent's existing tokens and mints a new one
	// in a single transaction so the agent is never stranded without a token.
	RotateAgentToken(ctx context.Context, agentID string, tokenExpiresAt *time.Time) (*Session, error)
	CreateAgentToken(ctx context.Context, agentID string, expiresAt *time.Time) (*Session, error)
	CountAllOwners(ctx context.Context) (int, error)

	// Instance settings
	GetSetting(ctx context.Context, key string) (string, error)
	SetSetting(ctx context.Context, key, value string) error
	GetAllSettings(ctx context.Context) (map[string]string, error)

	// Vault settings (per-vault key/value)
	GetVaultSetting(ctx context.Context, vaultID, key string) (string, error)
	SetVaultSetting(ctx context.Context, vaultID, key, value string) error
	DeleteVaultSetting(ctx context.Context, vaultID, key string) error

	// External credential stores (per vault)
	CreateExternalVault(ctx context.Context, p CreateExternalVaultParams) (*Vault, error)
	GetVaultCredentialStore(ctx context.Context, vaultID string) (*VaultCredentialStore, error)
	ListVaultCredentialStores(ctx context.Context) ([]VaultCredentialStore, error)
	UpdateVaultCredentialStoreHealth(ctx context.Context, vaultID, status, errMsg string, syncedAt time.Time) error
	// ReplaceVaultCredentialsForSync rewrites credentials only if the store row still matches configJSON (applied=false otherwise).
	ReplaceVaultCredentialsForSync(ctx context.Context, vaultID, configJSON string, items []EncryptedKV) (applied bool, err error)
	// SetVaultExternalStore upserts the credential-store row and replaces the vault's credentials in one transaction.
	SetVaultExternalStore(ctx context.Context, p SetVaultExternalStoreParams) (*VaultCredentialStore, error)
	// DeleteVaultCredentialStore removes the store row; synced credentials stay as built-in.
	DeleteVaultCredentialStore(ctx context.Context, vaultID string) error

	// Dynamic-secret lease tracking (Infisical). Lease metadata only — never
	// the leased credential values.
	InsertDynamicSecretLease(ctx context.Context, lease DynamicSecretLease) error
	DeleteDynamicSecretLease(ctx context.Context, leaseID string) error
	ListDynamicSecretLeases(ctx context.Context) ([]DynamicSecretLease, error)

	// Request logs
	InsertRequestLogs(ctx context.Context, rows []RequestLog) error
	ListRequestLogs(ctx context.Context, opts ListRequestLogsOpts) ([]RequestLog, error)
	ListUnmatchedHosts(ctx context.Context, vaultID string) ([]UnmatchedHost, error)
	DeleteOldRequestLogs(ctx context.Context, before time.Time) (int64, error)
	TrimRequestLogsToCap(ctx context.Context, vaultID string, cap int64) (int64, error)
	VaultIDsWithLogs(ctx context.Context) ([]string, error)

	// CA state (persistent CA root for Postgres HA deployments)
	GetCAState(ctx context.Context) (*CAState, error)
	SetCAState(ctx context.Context, state *CAState) error

	// LockVault acquires an exclusive advisory lock for the vault; callers MUST defer the returned release.
	LockVault(ctx context.Context, vaultID string) (unlock func(), err error)

	// Lifecycle
	Close() error
	Ping(ctx context.Context) error
	DialectName() string
}

// DefaultDBPath returns the default path for the SQLite database file (~/.agent-vault/agent-vault.db).
// It creates the ~/.agent-vault/ directory with 0700 permissions if it does not exist.
func DefaultDBPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".agent-vault")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	return filepath.Join(dir, "agent-vault.db"), nil
}
