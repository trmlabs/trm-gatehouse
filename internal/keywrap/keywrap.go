// Package keywrap wraps the master data key with a cloud key service so no master password has to be held.
package keywrap

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

const (
	// EnvKMS selects the key service and key, for example gcpkms://projects/p/locations/l/keyRings/r/cryptoKeys/k.
	EnvKMS = "AGENT_VAULT_MASTER_KEY_KMS"
	// EnvKMSFIPS forces the AWS FIPS endpoint outside us-gov regions; us-gov regions always use it.
	EnvKMSFIPS = "AGENT_VAULT_KMS_FIPS"

	schemeGCP = "gcpkms://"
	schemeAWS = "awskms://"

	// contextLabel binds every wrap to this use; the per-vault binding is added to it.
	contextLabel = "agent-vault-master-key"
)

// Wrapper wraps and unwraps small secrets, the master data key, under one cloud key.
type Wrapper interface {
	// binding is a stable per-vault id; a wrap only unwraps under the binding it was made with.
	Wrap(ctx context.Context, plaintext []byte, binding string) ([]byte, error)
	Unwrap(ctx context.Context, ciphertext []byte, binding string) ([]byte, error)
	// KeyName is the configured value, scheme included; it is stored beside the wrapped key.
	KeyName() string
}

// New builds the wrapper for a gcpkms:// or awskms:// value; forceFIPS only affects AWS.
func New(ctx context.Context, value string, forceFIPS bool) (Wrapper, error) {
	switch {
	case strings.HasPrefix(value, schemeGCP):
		if err := validateGCPKey(strings.TrimPrefix(value, schemeGCP)); err != nil {
			return nil, err
		}
		return newGCP(ctx, value)
	case strings.HasPrefix(value, schemeAWS):
		region, err := awsKeyRegion(strings.TrimPrefix(value, schemeAWS))
		if err != nil {
			return nil, err
		}
		return newAWS(ctx, value, region, forceFIPS)
	}
	return nil, fmt.Errorf("%s must start with %s or %s", EnvKMS, schemeGCP, schemeAWS)
}

var (
	gcpKeyRE     = regexp.MustCompile(`^projects/([a-z][a-z0-9-]{4,28}[a-z0-9]|[0-9]+)/locations/[a-z0-9-]+/keyRings/[A-Za-z0-9_-]{1,63}/cryptoKeys/[A-Za-z0-9_-]{1,63}$`)
	awsRegionRE  = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-\d+$`)
	awsAccountRE = regexp.MustCompile(`^\d{12}$`)
	awsKeyRE     = regexp.MustCompile(`^key/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|mrk-[0-9a-f]{32})$`)
)

// validateGCPKey accepts a crypto key, not a key version: encryption always uses the primary version.
func validateGCPKey(name string) error {
	if !gcpKeyRE.MatchString(name) {
		return fmt.Errorf("%s must be gcpkms://projects/PROJECT/locations/LOCATION/keyRings/RING/cryptoKeys/KEY with no other characters", EnvKMS)
	}
	return nil
}

// awsKeyRegion checks an ARN of the form arn:PARTITION:kms:REGION:ACCOUNT:key/KEY-ID and returns its region; an alias is refused because whoever can repoint it would choose the key for the next wrap.
func awsKeyRegion(arn string) (string, error) {
	bad := fmt.Errorf("%s must be awskms://arn:PARTITION:kms:REGION:ACCOUNT:key/KEY-ID (a full key ARN, partition aws or aws-us-gov)", EnvKMS)
	p := strings.Split(arn, ":")
	if len(p) != 6 || p[0] != "arn" || p[2] != "kms" {
		return "", bad
	}
	partition, region, account, resource := p[1], p[3], p[4], p[5]
	if partition != "aws" && partition != "aws-us-gov" {
		return "", bad
	}
	if !awsRegionRE.MatchString(region) || strings.HasPrefix(region, "us-gov-") != (partition == "aws-us-gov") {
		return "", bad
	}
	if strings.HasPrefix(resource, "alias/") {
		return "", fmt.Errorf("%s must name the key ARN (key/KEY-ID), not an alias: whoever can repoint an alias would choose the key for the next wrap", EnvKMS)
	}
	if !awsAccountRE.MatchString(account) || !awsKeyRE.MatchString(resource) {
		return "", bad
	}
	return region, nil
}
