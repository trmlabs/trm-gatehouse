package hashicorp

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
)

// DatabaseSession keeps its child token only in memory; persist Accessor before ReadCredential.
// Revocation touches no other session; an unknown issuance still needs database evidence before access reopens.
type DatabaseSession struct {
	Accessor    string
	ExpiresAt   time.Time
	client      *Client // holds the child token
	parent      *Client
	mount, role string
}

// DatabaseCredentialPolicyName names the pre-provisioned read-only policy on mount/creds/role; the broker never writes Vault policies.
func DatabaseCredentialPolicyName(mount, role string) string {
	path := strings.Trim(strings.TrimSpace(mount), "/") + "/creds/" + strings.TrimSpace(role)
	return fmt.Sprintf("agent-vault-db-%x", sha256.Sum256([]byte(path)))
}

func (c *Client) NewDatabaseSession(ctx context.Context, mount, role string, ttl time.Duration) (*DatabaseSession, error) {
	if err := ValidateDatabaseReference(mount, role); err != nil {
		return nil, err
	}
	if ttl < time.Second || ttl > 24*time.Hour {
		return nil, fmt.Errorf("database child token TTL must be between one second and 24 hours")
	}
	session, denied, err := c.newDatabaseSession(ctx, mount, role, ttl)
	if denied == "" || c.logins == nil {
		return session, err
	}
	// A new login may hold a child policy added after the old login was issued: log in again and retry once.
	// A policy a new login also lacked waits for the next scheduled login, so logins don't each live out their maximum lifetime.
	policy := DatabaseCredentialPolicyName(mount, role)
	if c.policyMissing(policy) {
		return nil, errSessionPolicy
	}
	if err := c.reloginAfterDenial(ctx, denied); err != nil {
		c.logger.Warn("database session refused: the broker's vault login lacks its policy", slog.String("reason", err.Error()))
		return nil, errSessionPolicy
	}
	if session, denied, err = c.newDatabaseSession(ctx, mount, role, ttl); denied != "" {
		c.markPolicyMissing(policy)
		c.logger.Warn("database session refused: a new vault login also lacks its policy; no more logins for it until the next scheduled one")
		return nil, errSessionPolicy
	}
	return session, err
}

var errSessionPolicy = errors.New("create database session failed: vault login lacks this database's policy")

// newDatabaseSession mints one child token; denied is the parent login's token when Vault answered 403.
func (c *Client) newDatabaseSession(ctx context.Context, mount, role string, ttl time.Duration) (session *DatabaseSession, denied string, err error) {
	api, err := c.api.CloneWithHeaders()
	if err != nil {
		return nil, "", fmt.Errorf("prepare database session failed")
	}
	parent, ceiling, done := c.api.Token(), time.Time{}, func(string, time.Time) {}
	if c.logins != nil {
		// Only a young login may parent a new session; see reauth.go.
		if parent, ceiling, done, err = c.logins.acquire(c.clock()); err != nil {
			return nil, "", err
		}
	}
	accessor, expiry := "", time.Time{}
	defer func() { done(accessor, expiry) }()
	api.SetToken(parent)
	api.SetMaxRetries(0)
	renewable := false
	started := c.clock()
	secret, err := api.Auth().Token().CreateWithContext(ctx, &vaultapi.TokenCreateRequest{
		Policies:        []string{DatabaseCredentialPolicyName(mount, role)},
		NoDefaultPolicy: true, Renewable: &renewable, Type: "service",
		TTL: ttl.String(), ExplicitMaxTTL: ttl.String(), DisplayName: "agent-vault-database-session",
	})
	var refused *vaultapi.ResponseError
	if errors.As(err, &refused) && refused.StatusCode == http.StatusForbidden {
		return nil, parent, fmt.Errorf("create database session failed")
	}
	if err != nil {
		return nil, "", fmt.Errorf("create database session failed")
	}
	if secret == nil || secret.Auth == nil || secret.Auth.ClientToken == "" || secret.Auth.Accessor == "" || secret.Auth.LeaseDuration <= 0 {
		return nil, "", fmt.Errorf("database session response missing token, accessor or positive TTL")
	}
	if len(secret.Auth.Policies) != 1 || secret.Auth.Policies[0] != DatabaseCredentialPolicyName(mount, role) || len(secret.Auth.IdentityPolicies) != 0 || secret.Auth.Renewable {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		api.SetToken(secret.Auth.ClientToken)
		_ = api.Auth().Token().RevokeSelfWithContext(cleanupCtx, "")
		if c.logins != nil {
			c.logins.forget(secret.Auth.Accessor)
		}
		return nil, "", fmt.Errorf("database child token has unexpected policy or renewal authority")
	}
	api.SetToken(secret.Auth.ClientToken)
	c.noteSession(secret.Auth.Accessor)
	granted := ttl
	if int64(secret.Auth.LeaseDuration) < int64(ttl/time.Second) {
		granted = time.Duration(secret.Auth.LeaseDuration) * time.Second
	}
	accessor, expiry = secret.Auth.Accessor, started.Add(granted)
	if !ceiling.IsZero() && ceiling.Before(expiry) {
		expiry = ceiling
	}
	child := &Client{api: api, method: c.method, logger: c.logger, now: c.now}
	child.minted.Store(c.mintedSet()) // its leases are this broker's too
	child.refusal.Store(c.refusal.Load())
	return &DatabaseSession{Accessor: accessor, ExpiresAt: expiry, client: child, parent: c, mount: mount, role: role}, "", nil
}

// Revoke ends the session with its own child token, revoking its leases. If it fails the token stays harmless:
// it lives only in this process, its leases are revoked by path, and it expires within its TTL.
func (s *DatabaseSession) Revoke(ctx context.Context) error {
	err := s.client.api.Auth().Token().RevokeSelfWithContext(ctx, "")
	if s.parent != nil && s.parent.logins != nil {
		s.parent.logins.forget(s.Accessor)
		s.parent.revokeIdle(ctx)
	}
	if err != nil {
		return fmt.Errorf("revoke database session failed")
	}
	return nil
}

func (s *DatabaseSession) ReadCredential(ctx context.Context) (*DatabaseCredential, error) {
	if !s.client.clock().Before(s.ExpiresAt) {
		return nil, fmt.Errorf("database session expired")
	}
	credential, err := s.client.ReadDatabaseCredential(ctx, s.mount, s.role)
	if err != nil {
		// The reason reaches only the broker's log, never the client.
		return nil, fmt.Errorf("database credential issuance failed: %w", err)
	}
	return credential, nil
}

// RevokeDatabaseSession revokes a child token by accessor, for operators with revoke-accessor; a 403 from a policy lacking it counts as done.
func (c *Client) RevokeDatabaseSession(ctx context.Context, accessor string) error {
	if accessor == "" {
		return fmt.Errorf("database session accessor is required")
	}
	if err := c.allowSessionRevoke(accessor); err != nil {
		return err
	}
	err := c.api.Auth().Token().RevokeAccessorWithContext(ctx, accessor)
	// Retrying after a successful revoke and failed journal deletion is safe.
	var response *vaultapi.ResponseError
	if errors.As(err, &response) && response.StatusCode == 400 && len(response.Errors) == 1 && response.Errors[0] == "invalid accessor" {
		err = nil
	}
	if errors.As(err, &response) && response.StatusCode == 403 {
		if c.logger != nil {
			c.logger.Info("vault refused accessor revoke; the database session token expires at its TTL")
		}
		err = nil
	}
	if err != nil {
		return fmt.Errorf("revoke database session failed")
	}
	c.forgetSession(accessor)
	if c.logins != nil {
		c.logins.forget(accessor)
		c.revokeIdle(ctx)
	}
	return nil
}

// RevokeDatabaseLeaseConfirmed refuses to treat a queued revoke as cleanup; the path form lets policy scope revocation to the lease prefix.
func (c *Client) RevokeDatabaseLeaseConfirmed(ctx context.Context, leaseID string) error {
	if leaseID == "" {
		return fmt.Errorf("database lease ID is required")
	}
	for _, part := range strings.Split(leaseID, "/") {
		if !databasePathSegment.MatchString(part) {
			return fmt.Errorf("invalid database lease ID")
		}
	}
	if err := c.allowLeaseRevoke(leaseID); err != nil {
		return err
	}
	if _, err := c.api.Logical().WriteWithContext(ctx, "sys/leases/revoke/"+leaseID, map[string]interface{}{"sync": true}); err != nil {
		return revokeFailure("synchronous database revoke failed", err)
	}
	secret, err := c.api.Logical().WriteWithContext(ctx, "sys/leases/lookup", map[string]interface{}{"lease_id": leaseID})
	var response *vaultapi.ResponseError
	if errors.As(err, &response) && response.StatusCode == 400 && len(response.Errors) == 1 && response.Errors[0] == "invalid lease" {
		c.forgetLease(leaseID)
		return nil
	}
	if err != nil {
		return revokeFailure("confirm database lease removal failed", err)
	}
	if secret == nil {
		return fmt.Errorf("database lease lookup returned no confirmation")
	}
	return fmt.Errorf("database lease still present after revoke: %w", ErrLeaseRevokeRefused)
}

// ErrLeaseRevokeRefused marks a revocation Vault refused or still lists, which a retry will meet again; timeouts, transport errors and 429/502/503/504 do not carry it.
var ErrLeaseRevokeRefused = errors.New("vault refused the database lease revocation")

func revokeFailure(message string, err error) error {
	var response *vaultapi.ResponseError
	if !errors.As(err, &response) {
		return errors.New(message)
	}
	switch response.StatusCode {
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return errors.New(message)
	}
	return fmt.Errorf("%s: %w", message, ErrLeaseRevokeRefused)
}

// DatabaseLeasePrefix is the lease ID prefix of every credential read from <mount>/creds/<role>.
func DatabaseLeasePrefix(mount, role string) (string, error) {
	mount = strings.Trim(strings.TrimSpace(mount), "/")
	role = strings.TrimSpace(role)
	if err := ValidateDatabaseReference(mount, role); err != nil {
		return "", err
	}
	return mount + "/creds/" + role + "/", nil
}

// ListDatabaseLeases returns every lease ID under a credential path, including pending, failing and irrevocable ones; a missing ID was revoked or never registered.
// Only Vault's empty-list answer (a 404 with {"errors":[]}) counts as none.
func (c *Client) ListDatabaseLeases(ctx context.Context, mount, role string) ([]string, error) {
	prefix, err := DatabaseLeasePrefix(mount, role)
	if err != nil {
		return nil, err
	}
	api, err := c.api.CloneWithHeaders()
	if err != nil {
		return nil, fmt.Errorf("prepare lease list failed")
	}
	api.SetToken(c.api.Token())
	api.SetMaxRetries(0)
	// Logical().List would read every 404 as an empty list.
	resp, err := api.Logical().ReadRawWithDataWithContext(ctx, "sys/leases/lookup/"+prefix, map[string][]string{"list": {"true"}})
	if resp != nil {
		defer func() { _ = resp.Body.Close() }()
	}
	if resp != nil && resp.StatusCode == http.StatusNotFound {
		var body struct {
			Errors *[]string `json:"errors"`
		}
		if json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&body) != nil || body.Errors == nil || len(*body.Errors) != 0 {
			return nil, fmt.Errorf("database lease list returned an unrecognized 404")
		}
		return []string{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("database lease list failed")
	}
	secret, err := vaultapi.ParseSecret(resp.Body)
	if err != nil || secret == nil {
		return nil, fmt.Errorf("database lease list returned no data")
	}
	raw, ok := secret.Data["keys"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("database lease list returned no keys")
	}
	leases := make([]string, 0, len(raw))
	for _, key := range raw {
		suffix, ok := key.(string)
		// A database lease is <prefix><id>; a nested key is not one.
		if !ok || suffix == "" || strings.Contains(suffix, "/") {
			return nil, fmt.Errorf("database lease list returned an unexpected key")
		}
		leases = append(leases, prefix+suffix)
	}
	return leases, nil
}

// DatabaseLeaseIssued returns when Vault registered a lease, by Vault's clock; a lease it no longer holds returns ErrLeaseGone.
func (c *Client) DatabaseLeaseIssued(ctx context.Context, leaseID string) (time.Time, error) {
	for _, part := range strings.Split(leaseID, "/") {
		if !databasePathSegment.MatchString(part) {
			return time.Time{}, fmt.Errorf("invalid database lease ID")
		}
	}
	secret, err := c.api.Logical().WriteWithContext(ctx, "sys/leases/lookup", map[string]interface{}{"lease_id": leaseID})
	var response *vaultapi.ResponseError
	if errors.As(err, &response) && response.StatusCode == 400 && len(response.Errors) == 1 && response.Errors[0] == "invalid lease" {
		return time.Time{}, ErrLeaseGone
	}
	if err != nil || secret == nil {
		return time.Time{}, fmt.Errorf("database lease lookup failed")
	}
	raw, _ := secret.Data["issue_time"].(string)
	issued, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return time.Time{}, fmt.Errorf("database lease lookup returned no issue time")
	}
	return issued, nil
}

var ErrLeaseGone = errors.New("database lease no longer held by Vault")
