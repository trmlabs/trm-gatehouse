package brokercore

import "errors"

var (
	// ErrInvalidSession means the supplied session token is missing, unknown,
	// or expired. The MITM ingress maps this to a 407 challenge.
	ErrInvalidSession = errors.New("brokercore: invalid or expired session")

	// ErrNoVaultContext means the session carries no vault scope and no hint
	// was provided (e.g. an agent token with zero vault grants).
	ErrNoVaultContext = errors.New("brokercore: session has no vault context")

	// ErrAgentVaultAmbiguous means an instance-level agent token with several vaults named none.
	ErrAgentVaultAmbiguous = errors.New("brokercore: agent has multiple vault grants; vault hint required")

	// ErrVaultHintMismatch means the vault hint differs from the scoped session's vault; never retarget.
	ErrVaultHintMismatch = errors.New("brokercore: vault hint does not match scoped session")

	// ErrVaultNotFound means the requested vault name does not exist.
	ErrVaultNotFound = errors.New("brokercore: vault not found")

	// ErrVaultAccessDenied means the actor exists but has no grant on the
	// requested vault.
	ErrVaultAccessDenied = errors.New("brokercore: actor has no access to vault")

	// ErrServiceNotFound means no configured broker service in the resolved
	// vault matches the target host. Callers surface 403 with a proposal hint.
	ErrServiceNotFound = errors.New("brokercore: no broker service matches target host")

	// ErrCredentialMissing means a referenced credential is unset or undecryptable; callers surface 502.
	ErrCredentialMissing = errors.New("brokercore: referenced credential missing or undecryptable")

	// ErrServiceDisabled means a matching service is toggled off; callers surface 403 service_disabled.
	ErrServiceDisabled = errors.New("brokercore: broker service is disabled")

	// ErrOAuthNotConnected means the credential is an OAuth type but
	// the consent flow hasn't completed yet (no access token stored).
	ErrOAuthNotConnected = errors.New("brokercore: oauth credential not yet connected")

	// ErrOAuthRefreshFailed means the credential's access token expired
	// and the automatic refresh attempt failed.
	ErrOAuthRefreshFailed = errors.New("brokercore: oauth token refresh failed")
)
