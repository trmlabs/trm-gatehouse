package auth

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"net/mail"

	"github.com/Infisical/agent-vault/internal/crypto"
)

// sentinel is the known plaintext encrypted with the DEK during setup and
// verified during unlock.
const sentinel = "agent-vault-master-key-check"

// ErrWrongPassword is returned when the master password does not match.
var ErrWrongPassword = errors.New("wrong master password")

// MasterKey holds the DEK (Data Encryption Key) in memory.
type MasterKey struct {
	key []byte
}

// Key returns the raw 32-byte DEK.
func (mk *MasterKey) Key() []byte {
	return mk.key
}

// Wipe zeros the key material. Call this when the server shuts down.
func (mk *MasterKey) Wipe() {
	crypto.WipeBytes(mk.key)
}

// VerificationRecord holds the artifacts needed to unlock the DEK
// on subsequent startups.
type VerificationRecord struct {
	Sentinel      []byte // sentinel ciphertext (encrypted with DEK)
	SentinelNonce []byte // sentinel GCM nonce
	DEKCiphertext []byte // KEK-wrapped DEK (nil in passwordless mode)
	DEKNonce      []byte // DEK wrapping nonce (nil in passwordless mode)
	DEKPlaintext  []byte // unwrapped DEK (nil when password-protected)
	Salt          []byte // KDF salt for KEK derivation (nil in passwordless mode)
	Params        crypto.KDFParams
}

// SetupWithPassword creates a new random DEK, encrypts the sentinel with it,
// then wraps the DEK under a KEK derived from the password (PBKDF2-HMAC-SHA256, or Argon2id until the KDF upgrade is on).
func SetupWithPassword(password []byte) (*MasterKey, *VerificationRecord, error) {
	dek, sentinelCT, sentinelNonce, err := generateDEK()
	if err != nil {
		return nil, nil, err
	}

	salt, dekCT, dekNonce, params, err := WrapDEK(dek, password)
	if err != nil {
		crypto.WipeBytes(dek)
		return nil, nil, fmt.Errorf("wrapping DEK: %w", err)
	}

	return &MasterKey{key: dek}, &VerificationRecord{
		Sentinel:      sentinelCT,
		SentinelNonce: sentinelNonce,
		DEKCiphertext: dekCT,
		DEKNonce:      dekNonce,
		Salt:          salt,
		Params:        params,
	}, nil
}

// SetupPasswordless creates a new random DEK and encrypts the sentinel with it.
// The DEK is stored in plaintext — security depends on filesystem access controls.
func SetupPasswordless() (*MasterKey, *VerificationRecord, error) {
	dek, sentinelCT, sentinelNonce, err := generateDEK()
	if err != nil {
		return nil, nil, err
	}

	// Copy the DEK for storage — the MasterKey holds the original.
	dekCopy := make([]byte, len(dek))
	copy(dekCopy, dek)

	return &MasterKey{key: dek}, &VerificationRecord{
		Sentinel:      sentinelCT,
		SentinelNonce: sentinelNonce,
		DEKPlaintext:  dekCopy,
	}, nil
}

// generateDEK creates a random 32-byte DEK and encrypts the sentinel with it.
func generateDEK() (dek, sentinelCT, sentinelNonce []byte, err error) {
	dek, err = crypto.GenerateSalt(32)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("generating DEK: %w", err)
	}

	sentinelCT, sentinelNonce, err = crypto.Encrypt([]byte(sentinel), dek)
	if err != nil {
		crypto.WipeBytes(dek)
		return nil, nil, nil, fmt.Errorf("encrypting sentinel: %w", err)
	}

	return dek, sentinelCT, sentinelNonce, nil
}

// Unlock derives the KEK from the password, unwraps the DEK, and verifies
// the sentinel. Returns ErrWrongPassword if the password is incorrect.
func Unlock(password []byte, record *VerificationRecord) (*MasterKey, error) {
	kek, err := crypto.DeriveKey(password, record.Salt, record.Params)
	if err != nil {
		return nil, fmt.Errorf("deriving key: %w", err)
	}

	dek, err := crypto.Decrypt(record.DEKCiphertext, record.DEKNonce, kek)
	crypto.WipeBytes(kek)
	if err != nil {
		return nil, ErrWrongPassword
	}

	if err := verifySentinel(dek, record.Sentinel, record.SentinelNonce); err != nil {
		crypto.WipeBytes(dek)
		return nil, err
	}

	return &MasterKey{key: dek}, nil
}

// UnlockPasswordless loads the DEK from plaintext storage and verifies the sentinel.
func UnlockPasswordless(record *VerificationRecord) (*MasterKey, error) {
	// Make a copy so the caller's record isn't shared with the MasterKey.
	dek := make([]byte, len(record.DEKPlaintext))
	copy(dek, record.DEKPlaintext)

	if err := verifySentinel(dek, record.Sentinel, record.SentinelNonce); err != nil {
		crypto.WipeBytes(dek)
		return nil, err
	}

	return &MasterKey{key: dek}, nil
}

// WrapDEK wraps a DEK under a new KEK derived from the password.
// Returns the salt, wrapped DEK ciphertext, nonce, and KDF params.
func WrapDEK(dek, password []byte) (salt, dekCT, dekNonce []byte, params crypto.KDFParams, err error) {
	params, err = crypto.DefaultKDFParams()
	if err != nil {
		return nil, nil, nil, params, err
	}

	salt, err = crypto.GenerateSalt(int(params.SaltLen))
	if err != nil {
		return nil, nil, nil, params, fmt.Errorf("generating KEK salt: %w", err)
	}

	kek, err := crypto.DeriveKey(password, salt, params)
	if err != nil {
		return nil, nil, nil, params, fmt.Errorf("deriving KEK: %w", err)
	}
	dekCT, dekNonce, err = crypto.Encrypt(dek, kek)
	crypto.WipeBytes(kek)
	if err != nil {
		return nil, nil, nil, params, fmt.Errorf("wrapping DEK: %w", err)
	}

	return salt, dekCT, dekNonce, params, nil
}

// verifySentinel decrypts the stored sentinel with the DEK and checks it
// matches the expected value.
func verifySentinel(dek, sentinelCT, sentinelNonce []byte) error {
	plaintext, err := crypto.Decrypt(sentinelCT, sentinelNonce, dek)
	if err != nil {
		return ErrWrongPassword
	}
	if subtle.ConstantTimeCompare(plaintext, []byte(sentinel)) != 1 {
		return ErrWrongPassword
	}
	return nil
}

// HashUserPassword hashes a user password with a random salt (PBKDF2-HMAC-SHA256, or Argon2id until the KDF upgrade is on).
// Returns the hash, salt, and the KDF parameters used (for storage alongside the hash).
func HashUserPassword(password []byte) (hash, salt []byte, params crypto.KDFParams, err error) {
	params, err = crypto.DefaultKDFParams()
	if err != nil {
		return nil, nil, params, err
	}
	salt, err = crypto.GenerateSalt(int(params.SaltLen))
	if err != nil {
		return nil, nil, params, fmt.Errorf("generating salt: %w", err)
	}
	hash, err = crypto.DeriveKey(password, salt, params)
	if err != nil {
		return nil, nil, params, fmt.Errorf("hashing password: %w", err)
	}
	return hash, salt, params, nil
}

// VerifyUserPassword checks a password against a stored hash, salt, and KDF params.
func VerifyUserPassword(password, hash, salt []byte, params crypto.KDFParams) bool {
	derived, err := crypto.DeriveKey(password, salt, params)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(derived, hash) == 1
}

// ValidateEmail performs basic email format validation.
func ValidateEmail(email string) error {
	if email == "" {
		return errors.New("email is required")
	}
	_, err := mail.ParseAddress(email)
	if err != nil {
		return fmt.Errorf("invalid email format: %w", err)
	}
	return nil
}
