package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/keywrap"
)

// ErrWrongKMSKey is returned when the KMS key unwraps a key that does not belong to this vault.
var ErrWrongKMSKey = errors.New("the KMS key unwrapped a key that does not match this vault")

// KMSBinding is the per-vault id mixed into every KMS wrap, derived from the vault's sentinel, so one key serving two vaults cannot unwrap across them.
func KMSBinding(sentinel []byte) string {
	sum := sha256.Sum256(append([]byte("agent-vault-kms-binding:"), sentinel...))
	return hex.EncodeToString(sum[:])
}

// WrapWithKMS wraps the DEK and unwraps it again, so a wrap that cannot be read back is never returned.
func WrapWithKMS(ctx context.Context, w keywrap.Wrapper, dek, sentinel []byte) ([]byte, error) {
	binding := KMSBinding(sentinel)
	wrapped, err := w.Wrap(ctx, dek, binding)
	if err != nil {
		return nil, fmt.Errorf("wrapping with KMS key %s: %w", w.KeyName(), err)
	}
	back, err := w.Unwrap(ctx, wrapped, binding)
	if err != nil {
		return nil, fmt.Errorf("verifying the KMS wrap: %w", err)
	}
	defer crypto.WipeBytes(back)
	if subtle.ConstantTimeCompare(back, dek) != 1 {
		return nil, errors.New("verifying the KMS wrap: the key read back differs from the key wrapped")
	}
	return wrapped, nil
}

// SetupWithKMS creates a new random DEK wrapped only by KMS; the record carries the sentinel and no password wrap.
func SetupWithKMS(ctx context.Context, w keywrap.Wrapper) (*MasterKey, *VerificationRecord, []byte, error) {
	dek, sentinelCT, sentinelNonce, err := generateDEK()
	if err != nil {
		return nil, nil, nil, err
	}
	wrapped, err := WrapWithKMS(ctx, w, dek, sentinelCT)
	if err != nil {
		crypto.WipeBytes(dek)
		return nil, nil, nil, err
	}
	return &MasterKey{key: dek}, &VerificationRecord{Sentinel: sentinelCT, SentinelNonce: sentinelNonce}, wrapped, nil
}

// UnlockWithKMS unwraps the DEK with KMS and verifies the sentinel.
func UnlockWithKMS(ctx context.Context, w keywrap.Wrapper, wrapped []byte, record *VerificationRecord) (*MasterKey, error) {
	dek, err := w.Unwrap(ctx, wrapped, KMSBinding(record.Sentinel))
	if err != nil {
		return nil, fmt.Errorf("unwrapping with KMS key %s: %w", w.KeyName(), err)
	}
	if err := verifySentinel(dek, record.Sentinel, record.SentinelNonce); err != nil {
		crypto.WipeBytes(dek)
		return nil, ErrWrongKMSKey
	}
	return &MasterKey{key: dek}, nil
}
