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

// outcomeDecoy is the audit outcome for a session refused because its password
// was a decoy credential.
const outcomeDecoy = "decoy_credential"

// decoyError is a password that was a decoy credential. It carries the decoy's
// label and surface, never the password.
type decoyError struct{ match decoy.Match }

func (e *decoyError) Error() string { return "pgproxy: decoy credential presented" }
