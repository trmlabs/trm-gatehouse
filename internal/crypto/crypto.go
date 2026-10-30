package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"slices"
)

// gcmNonceSize is the GCM nonce length; the random-nonce AEAD prepends it to the ciphertext.
const gcmNonceSize = 12

// Encrypt encrypts plaintext using AES-256-GCM with the given 32-byte key.
// It returns the ciphertext and a randomly generated nonce.
func Encrypt(plaintext, key []byte) (ciphertext, nonce []byte, err error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, nil, err
	}

	// The FIPS-approved constructor generates the nonce itself and returns nonce || ciphertext.
	sealed := gcm.Seal(nil, nil, plaintext, nil) //nolint:gosec // G407: random-nonce GCM generates the nonce
	return sealed[gcmNonceSize:], slices.Clip(slices.Clone(sealed[:gcmNonceSize])), nil
}

// Decrypt decrypts ciphertext using AES-256-GCM with the given 32-byte key and nonce.
func Decrypt(ciphertext, nonce, key []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcmNonceSize {
		return nil, errors.New("decrypting: invalid nonce length")
	}

	sealed := make([]byte, 0, len(nonce)+len(ciphertext))
	sealed = append(append(sealed, nonce...), ciphertext...)
	plaintext, err := gcm.Open(nil, nil, sealed, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypting: %w", err)
	}

	return plaintext, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}
	gcm, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}
	return gcm, nil
}
