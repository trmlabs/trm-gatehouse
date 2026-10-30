package crypto

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"os"
	"strconv"

	"golang.org/x/crypto/argon2" // goes once the upgrade default is on everywhere and Argon2 records are gone
)

// KDF algorithm names as stored next to the params.
const (
	AlgoPBKDF2SHA256 = "pbkdf2-sha256"
	AlgoArgon2id     = "argon2id"
)

const (
	// DefaultPBKDF2Iterations is the OWASP 2023 recommendation for PBKDF2-HMAC-SHA256.
	DefaultPBKDF2Iterations = 600_000
	// MinPBKDF2Iterations and MaxPBKDF2Iterations bound the configured iteration count.
	MinPBKDF2Iterations = 600_000
	MaxPBKDF2Iterations = 10_000_000
	// MaxArgon2idMemoryKiB and MaxArgon2idPasses bound Argon2id params read from the database.
	MaxArgon2idMemoryKiB = 1024 * 1024
	MaxArgon2idPasses    = 10
	// IterationsEnv sets the PBKDF2 iteration count for new records; existing ones move to it on their next login or unlock.
	IterationsEnv = "AGENT_VAULT_PBKDF2_ITERATIONS"
	// KDFUpgradeEnv turns on writing PBKDF2 and upgrading Argon2id records; off by default so an older image can still read every record.
	KDFUpgradeEnv = "AGENT_VAULT_KDF_UPGRADE"
)

// KDFParams: Time is PBKDF2 iterations or Argon2id passes; Memory (KiB) and Threads are Argon2id only.
type KDFParams struct {
	Algorithm string
	Time      uint32
	Memory    uint32
	Threads   uint8
	KeyLen    uint32
	SaltLen   uint32
}

// KDFConfig reads the KDF settings from the environment and rejects invalid values.
func KDFConfig() (upgrade bool, iterations uint32, err error) {
	iterations = DefaultPBKDF2Iterations
	if v := os.Getenv(KDFUpgradeEnv); v != "" {
		if upgrade, err = strconv.ParseBool(v); err != nil {
			return false, 0, fmt.Errorf("%s must be true or false, got %q", KDFUpgradeEnv, v)
		}
	}
	if v := os.Getenv(IterationsEnv); v != "" {
		n, perr := strconv.ParseUint(v, 10, 32)
		if perr != nil || n < MinPBKDF2Iterations || n > MaxPBKDF2Iterations {
			return false, 0, fmt.Errorf("%s must be a whole number from %d to %d, got %q", IterationsEnv, MinPBKDF2Iterations, MaxPBKDF2Iterations, v)
		}
		iterations = uint32(n)
	}
	return upgrade, iterations, nil
}

// UpgradeEnabled reports whether new records use PBKDF2 and Argon2id records are upgraded.
func UpgradeEnabled() bool {
	upgrade, _, err := KDFConfig()
	return err == nil && upgrade
}

// DefaultKDFParams returns the params for newly written records: PBKDF2 when the upgrade is on, Argon2id when off.
func DefaultKDFParams() (KDFParams, error) {
	upgrade, iterations, err := KDFConfig()
	if err != nil {
		return KDFParams{}, err
	}
	if !upgrade {
		return KDFParams{Algorithm: AlgoArgon2id, Time: 3, Memory: 64 * 1024, Threads: 4, KeyLen: 32, SaltLen: 16}, nil
	}
	return KDFParams{Algorithm: AlgoPBKDF2SHA256, Time: iterations, KeyLen: 32, SaltLen: 16}, nil
}

// IsLegacy reports whether the record is really Argon2id, whatever its label says.
func (p KDFParams) IsLegacy() bool { return p.EffectiveAlgorithm() == AlgoArgon2id }

// NeedsUpgrade reports whether the upgrade is on and the record is Argon2id or PBKDF2 at a count other than the configured one.
func (p KDFParams) NeedsUpgrade() bool {
	upgrade, iterations, err := KDFConfig()
	if err != nil || !upgrade {
		return false
	}
	switch p.EffectiveAlgorithm() {
	case AlgoArgon2id:
		return true
	case AlgoPBKDF2SHA256:
		return p.Time != iterations
	}
	return false
}

// EffectiveAlgorithm is the algorithm a record was really derived with: a pbkdf2-sha256 label with Argon2id-shaped params is an old image's password change that left the label alone.
func (p KDFParams) EffectiveAlgorithm() string {
	switch p.Algorithm {
	case AlgoPBKDF2SHA256:
		if p.Memory > 0 || p.Threads > 0 {
			return AlgoArgon2id
		}
		return AlgoPBKDF2SHA256
	case "":
		return AlgoArgon2id
	default:
		return p.Algorithm
	}
}

// DeriveKey derives a key from a password and salt with the algorithm named in params.
func DeriveKey(password, salt []byte, params KDFParams) ([]byte, error) {
	switch params.EffectiveAlgorithm() {
	case AlgoPBKDF2SHA256:
		if params.Time < 1 || params.Time > MaxPBKDF2Iterations {
			return nil, fmt.Errorf("PBKDF2 iterations %d out of range", params.Time)
		}
		return pbkdf2.Key(sha256.New, string(password), salt, int(params.Time), int(params.KeyLen))
	case AlgoArgon2id:
		if params.Time < 1 || params.Time > MaxArgon2idPasses || params.Threads < 1 || params.Memory < 1 || params.Memory > MaxArgon2idMemoryKiB {
			return nil, fmt.Errorf("invalid Argon2id params")
		}
		return argon2.IDKey(password, salt, params.Time, params.Memory, params.Threads, params.KeyLen), nil
	default:
		return nil, fmt.Errorf("unknown KDF algorithm %q", params.Algorithm)
	}
}

// GenerateSalt generates a cryptographically random salt of the given length.
func GenerateSalt(n int) ([]byte, error) {
	salt := make([]byte, n)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	return salt, nil
}

// WipeBytes zeros out a byte slice. This is best-effort — Go's garbage
// collector may have copied the underlying data before this call.
// Avoid converting sensitive []byte to string, as strings are immutable
// and cannot be wiped.
func WipeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
