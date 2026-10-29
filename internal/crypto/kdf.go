package crypto

import (
	"crypto/rand"

	"golang.org/x/crypto/argon2"
)

// KDFParams holds the parameters for Argon2id key derivation.
type KDFParams struct {
	Time    uint32
	Memory  uint32 // in KiB
	Threads uint8
	KeyLen  uint32
	SaltLen uint32
}

// DefaultKDFParams returns recommended Argon2id parameters.
func DefaultKDFParams() KDFParams {
	return KDFParams{
		Time:    3,
		Memory:  64 * 1024, // 64 MiB
		Threads: 4,
		KeyLen:  32,
		SaltLen: 16,
	}
}

// DeriveKey derives a key from a password and salt using Argon2id.
func DeriveKey(password, salt []byte, params KDFParams) []byte {
	return argon2.IDKey(password, salt, params.Time, params.Memory, params.Threads, params.KeyLen)
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
