package brokercore

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"regexp"
)

// AttestationHeader carries a shared proxy's attestation of the agent Pod; any identity but a proxy-attested one presenting it is refused.
const AttestationHeader = "Gatehouse-Attestation"

type attestationKey struct{}

// WithAttestation carries the connection's attestation, as the proxy sent it, to the Attestor.
func WithAttestation(ctx context.Context, attestation string) context.Context {
	return context.WithValue(ctx, attestationKey{}, attestation)
}

// maxAttestationHeader bounds what AttestedSandbox decodes; the verifier uses the same bound.
const maxAttestationHeader = 4096

var sandboxUID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,127}$`)

// AttestedSandbox returns the Sandbox UID an attestation names, unverified, or "".
// It only keys pre-authentication rate limits, since every sandbox behind a shared proxy shares its address.
func AttestedSandbox(attestation string) string {
	if attestation == "" || len(attestation) > maxAttestationHeader {
		return ""
	}
	b, err := base64.RawURLEncoding.DecodeString(attestation)
	if err != nil {
		return ""
	}
	var a struct {
		OwnerUID string `json:"ownerUID"`
	}
	if json.Unmarshal(b, &a) != nil || !sandboxUID.MatchString(a.OwnerUID) {
		return ""
	}
	return a.OwnerUID
}

// AttestationFrom returns the connection's attestation, or "".
func AttestationFrom(ctx context.Context) string {
	a, _ := ctx.Value(attestationKey{}).(string)
	return a
}
