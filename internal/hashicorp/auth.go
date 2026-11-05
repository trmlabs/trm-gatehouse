// Package hashicorp wraps the HashiCorp Vault API: auth detection, client construction and the per-vault sync worker.
// sync.go deliberately duplicates internal/infisical/sync.go; extract a shared engine before adding a third store.
package hashicorp

import (
	"errors"
	"fmt"
	"log/slog"
)

// AuthMethod identifies which Vault auth flow the client uses.
type AuthMethod string

const (
	AuthToken   AuthMethod = "token"
	AuthAppRole AuthMethod = "approle"
	// AuthJWT re-logs in on a schedule, so a fixed maximum login lifetime needs no restart.
	AuthJWT AuthMethod = "jwt"
)

type authProbe struct {
	method   AuthMethod
	required []string // all required to consider this method "configured"
}

// authProbes is priority-ordered and the first complete row wins, so AppRole beats a bare token.
var authProbes = []authProbe{
	{AuthAppRole, []string{"VAULT_ROLE_ID", "VAULT_SECRET_ID"}},
	{AuthJWT, []string{"VAULT_JWT_ROLE", "VAULT_JWT_TOKEN_FILE"}},
	{AuthToken, []string{"VAULT_TOKEN"}},
}

// DetectAuthMethod returns the first complete method, or "" when none is configured.
func DetectAuthMethod(getenv func(string) string, logger *slog.Logger) (AuthMethod, error) {
	var matches []AuthMethod
	for _, probe := range authProbes {
		complete := true
		for _, key := range probe.required {
			if getenv(key) == "" {
				complete = false
				break
			}
		}
		if complete {
			matches = append(matches, probe.method)
		}
	}
	if len(matches) == 0 {
		return "", nil
	}
	if len(matches) > 1 && logger != nil {
		logger.Warn("multiple HashiCorp Vault auth methods configured; using highest-priority",
			slog.String("using", string(matches[0])),
			slog.Any("ignoring", matches[1:]))
	}
	return matches[0], nil
}

// ErrNotConfigured means VAULT_ADDR is unset; the server runs without a HashiCorp store.
var ErrNotConfigured = fmt.Errorf("hashicorp: VAULT_ADDR not set")

var ErrNoAuthMethod = fmt.Errorf("hashicorp: VAULT_ADDR is set but no auth-method env vars are configured (set VAULT_TOKEN, VAULT_ROLE_ID + VAULT_SECRET_ID, or VAULT_JWT_ROLE + VAULT_JWT_TOKEN_FILE)")

// ErrInvalidAuthConfig wraps a present but unusable auth setting; retrying never fixes it.
var ErrInvalidAuthConfig = errors.New("hashicorp: invalid auth configuration")
