package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/fips140"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

func testKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return key
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key := testKey(t)
	plaintext := []byte("super secret value")

	ct, nonce, err := Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	got, err := Decrypt(ct, nonce, key)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if !bytes.Equal(got, plaintext) {
		t.Fatalf("expected %q, got %q", plaintext, got)
	}
}

func TestDecryptWrongKey(t *testing.T) {
	key1 := testKey(t)
	key2 := testKey(t)

	ct, nonce, err := Encrypt([]byte("data"), key1)
	if err != nil {
		t.Fatal(err)
	}

	_, err = Decrypt(ct, nonce, key2)
	if err == nil {
		t.Fatal("expected error decrypting with wrong key")
	}
}

func TestDecryptTamperedCiphertext(t *testing.T) {
	key := testKey(t)

	ct, nonce, err := Encrypt([]byte("data"), key)
	if err != nil {
		t.Fatal(err)
	}

	// Flip a byte in ciphertext.
	ct[0] ^= 0xff

	_, err = Decrypt(ct, nonce, key)
	if err == nil {
		t.Fatal("expected error decrypting tampered ciphertext")
	}
}

func TestNonceUniqueness(t *testing.T) {
	key := testKey(t)
	plaintext := []byte("same data")

	_, nonce1, _ := Encrypt(plaintext, key)
	_, nonce2, _ := Encrypt(plaintext, key)

	if bytes.Equal(nonce1, nonce2) {
		t.Fatal("nonces should differ between encryptions")
	}
}

func TestEncryptInvalidKeySize(t *testing.T) {
	_, _, err := Encrypt([]byte("data"), []byte("short"))
	if err == nil {
		t.Fatal("expected error for invalid key size")
	}
}

func TestDecryptReadsRecordsWrittenWithStandardGCM(t *testing.T) {
	// Sealed with plain cipher.NewGCM (key bytes 0..31, nonce bytes 100..111), the format stored before FIPS mode.
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	nonce := make([]byte, 12)
	for i := range nonce {
		nonce[i] = byte(100 + i)
	}
	ct, err := hex.DecodeString("3b6fb1141c8d76fc5b04309abf452cb412912667e408965026f299238bc04eddac6a4d6823278e")
	if err != nil {
		t.Fatal(err)
	}

	got, err := Decrypt(ct, nonce, key)
	if err != nil || string(got) != "stored before FIPS mode" {
		t.Fatalf("legacy ciphertext did not decrypt: %q %v", got, err)
	}
}

func TestDecryptRejectsWrongNonceLength(t *testing.T) {
	if _, err := Decrypt([]byte("ciphertext-and-tag"), []byte("short"), testKey(t)); err == nil {
		t.Fatal("expected error for a short nonce")
	}
}

func TestEncryptNonceDoesNotShareTheCiphertextArray(t *testing.T) {
	ct, nonce, err := Encrypt([]byte("data"), testKey(t))
	if err != nil {
		t.Fatal(err)
	}
	want := append([]byte(nil), ct...)
	_ = append(nonce, 0xff, 0xff, 0xff, 0xff)
	if !bytes.Equal(ct, want) {
		t.Fatal("appending to the nonce changed the ciphertext")
	}
	if cap(nonce) != len(nonce) {
		t.Fatalf("nonce has spare capacity %d", cap(nonce)-len(nonce))
	}
}

func TestNewCiphertextOpensWithPlainGCM(t *testing.T) {
	key := testKey(t)
	ct, nonce, err := Encrypt([]byte("opens on an older image"), key)
	if err != nil {
		t.Fatal(err)
	}
	var got []byte
	fips140.WithoutEnforcement(func() {
		block, berr := aes.NewCipher(key)
		if berr != nil {
			t.Fatal(berr)
		}
		gcm, gerr := cipher.NewGCM(block)
		if gerr != nil {
			t.Fatal(gerr)
		}
		got, err = gcm.Open(nil, nonce, ct, nil)
	})
	if err != nil || string(got) != "opens on an older image" {
		t.Fatalf("plain GCM could not open new ciphertext: %q %v", got, err)
	}
}
