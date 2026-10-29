package crypto

import (
	"bytes"
	"testing"
)

func TestDeriveKeySameSaltSameKey(t *testing.T) {
	params := KDFParams{Time: 1, Memory: 64 * 1024, Threads: 4, KeyLen: 32, SaltLen: 16}
	salt := []byte("0123456789abcdef")
	password := []byte("my-secret-password")

	key1 := DeriveKey(password, salt, params)
	key2 := DeriveKey(password, salt, params)

	if !bytes.Equal(key1, key2) {
		t.Fatal("same password and salt should produce the same key")
	}
}

func TestDeriveKeyDifferentSaltsDifferentKeys(t *testing.T) {
	params := KDFParams{Time: 1, Memory: 64 * 1024, Threads: 4, KeyLen: 32, SaltLen: 16}
	password := []byte("my-secret-password")

	key1 := DeriveKey(password, []byte("salt-aaaaaaaaaaaa"), params)
	key2 := DeriveKey(password, []byte("salt-bbbbbbbbbbbb"), params)

	if bytes.Equal(key1, key2) {
		t.Fatal("different salts should produce different keys")
	}
}

func TestDeriveKeyOutputLength(t *testing.T) {
	params := KDFParams{Time: 1, Memory: 64 * 1024, Threads: 4, KeyLen: 32, SaltLen: 16}
	key := DeriveKey([]byte("pw"), []byte("0123456789abcdef"), params)
	if len(key) != 32 {
		t.Fatalf("expected 32-byte key, got %d", len(key))
	}
}

func TestGenerateSaltLength(t *testing.T) {
	salt, err := GenerateSalt(16)
	if err != nil {
		t.Fatalf("GenerateSalt: %v", err)
	}
	if len(salt) != 16 {
		t.Fatalf("expected 16 bytes, got %d", len(salt))
	}
}

func TestWipeBytes(t *testing.T) {
	b := []byte{0xff, 0xab, 0x01, 0x99}
	WipeBytes(b)
	for i, v := range b {
		if v != 0 {
			t.Fatalf("byte %d not wiped: got %d", i, v)
		}
	}
}
