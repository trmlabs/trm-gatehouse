package pgproxy

import (
	"errors"

	"github.com/Infisical/agent-vault/internal/decoy"
)

var (
	// errCancelRequest is returned when the agent opens a Postgres CancelRequest
	// rather than a normal startup. The broker routes it using its session capability.
	errCancelRequest = errors.New("pgproxy: cancel request")
	// errMissingToken is returned when the agent presents an empty password. The
	// Agent Vault token is required to establish the vault scope.
	errMissingToken = errors.New("pgproxy: missing agent token")
)

const outcomeDecoy = "decoy_credential"

// It carries the decoy's label and surface, never the password.
type decoyError struct{ match decoy.Match }

func (e *decoyError) Error() string { return "pgproxy: decoy credential presented" }
