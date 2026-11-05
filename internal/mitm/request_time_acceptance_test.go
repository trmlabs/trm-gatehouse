//go:build realvault && credentialproxyacceptance

package mitm

import "testing"

// Verifies fresh request-time Vault resolution with no synchronized local credential copy, on both proxy ingress forms.
func TestRealVault_RequestTimeResolution(t *testing.T) {
	runVaultFreshnessFixture(t, true)
}
