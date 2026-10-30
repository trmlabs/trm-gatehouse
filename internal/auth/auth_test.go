package auth

import (
	"testing"

	"github.com/Infisical/agent-vault/internal/crypto"
)

func TestSetupWithPasswordAndUnlockRoundTrip(t *testing.T) {
	password := []byte("correct-horse-battery-staple")

	mk, rec, err := SetupWithPassword(password)
	if err != nil {
		t.Fatalf("SetupWithPassword: %v", err)
	}
	defer mk.Wipe()

	if len(mk.Key()) != 32 {
		t.Fatalf("expected 32-byte DEK, got %d", len(mk.Key()))
	}

	// Wrapped DEK fields should be populated, plaintext DEK should be nil.
	if rec.DEKCiphertext == nil || rec.DEKNonce == nil {
		t.Fatal("expected DEKCiphertext and DEKNonce to be set")
	}
	if rec.DEKPlaintext != nil {
		t.Fatal("expected DEKPlaintext to be nil for password-protected setup")
	}

	// Unlock with the same password should succeed and return the same DEK.
	mk2, err := Unlock(password, rec)
	if err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	defer mk2.Wipe()

	if string(mk.Key()) != string(mk2.Key()) {
		t.Fatal("DEKs from SetupWithPassword and Unlock differ")
	}
}

func TestSetupPasswordlessAndUnlockRoundTrip(t *testing.T) {
	mk, rec, err := SetupPasswordless()
	if err != nil {
		t.Fatalf("SetupPasswordless: %v", err)
	}
	defer mk.Wipe()

	if len(mk.Key()) != 32 {
		t.Fatalf("expected 32-byte DEK, got %d", len(mk.Key()))
	}

	// Plaintext DEK should be populated, wrapped DEK fields should be nil.
	if rec.DEKPlaintext == nil {
		t.Fatal("expected DEKPlaintext to be set")
	}
	if rec.DEKCiphertext != nil || rec.DEKNonce != nil {
		t.Fatal("expected DEKCiphertext/DEKNonce to be nil for passwordless setup")
	}

	// UnlockPasswordless should return the same DEK.
	mk2, err := UnlockPasswordless(rec)
	if err != nil {
		t.Fatalf("UnlockPasswordless: %v", err)
	}
	defer mk2.Wipe()

	if string(mk.Key()) != string(mk2.Key()) {
		t.Fatal("DEKs from SetupPasswordless and UnlockPasswordless differ")
	}
}

func TestUnlockWrongPassword(t *testing.T) {
	password := []byte("correct-password")
	wrong := []byte("wrong-password")

	_, rec, err := SetupWithPassword(password)
	if err != nil {
		t.Fatalf("SetupWithPassword: %v", err)
	}

	_, err = Unlock(wrong, rec)
	if err != ErrWrongPassword {
		t.Fatalf("expected ErrWrongPassword, got %v", err)
	}
}

func TestWipeZerosKey(t *testing.T) {
	mk, _, err := SetupPasswordless()
	if err != nil {
		t.Fatalf("SetupPasswordless: %v", err)
	}

	key := mk.Key()
	mk.Wipe()

	for i, b := range key {
		if b != 0 {
			t.Fatalf("byte %d not wiped: got %d", i, b)
		}
	}
}

func TestSetupProducesDifferentDEKs(t *testing.T) {
	mk1, _, err := SetupPasswordless()
	if err != nil {
		t.Fatal(err)
	}
	mk2, _, err := SetupPasswordless()
	if err != nil {
		t.Fatal(err)
	}

	if string(mk1.Key()) == string(mk2.Key()) {
		t.Fatal("two SetupPasswordless calls produced the same DEK")
	}
}

func TestWrapDEKRoundTrip(t *testing.T) {
	mk, _, err := SetupPasswordless()
	if err != nil {
		t.Fatal(err)
	}
	defer mk.Wipe()

	password := []byte("test-password")
	salt, dekCT, dekNonce, params, err := WrapDEK(mk.Key(), password)
	if err != nil {
		t.Fatalf("WrapDEK: %v", err)
	}

	// Build a verification record to unlock.
	sentinelCT, sentinelNonce, err := crypto.Encrypt([]byte(sentinel), mk.Key())
	if err != nil {
		t.Fatal(err)
	}

	rec := &VerificationRecord{
		Sentinel:      sentinelCT,
		SentinelNonce: sentinelNonce,
		DEKCiphertext: dekCT,
		DEKNonce:      dekNonce,
		Salt:          salt,
		Params:        params,
	}

	mk2, err := Unlock(password, rec)
	if err != nil {
		t.Fatalf("Unlock after WrapDEK: %v", err)
	}
	defer mk2.Wipe()

	if string(mk.Key()) != string(mk2.Key()) {
		t.Fatal("DEK mismatch after WrapDEK round-trip")
	}
}

func TestPasswordChangePreservesDEK(t *testing.T) {
	oldPw := []byte("old-password")
	newPw := []byte("new-password")

	mk, rec, err := SetupWithPassword(oldPw)
	if err != nil {
		t.Fatal(err)
	}
	defer mk.Wipe()

	originalDEK := make([]byte, len(mk.Key()))
	copy(originalDEK, mk.Key())

	// Re-wrap the DEK under a new password.
	salt, dekCT, dekNonce, params, err := WrapDEK(mk.Key(), newPw)
	if err != nil {
		t.Fatal(err)
	}

	// Update the verification record.
	rec.DEKCiphertext = dekCT
	rec.DEKNonce = dekNonce
	rec.Salt = salt
	rec.Params = params

	// Old password should no longer work.
	_, err = Unlock(oldPw, rec)
	if err != ErrWrongPassword {
		t.Fatalf("expected ErrWrongPassword with old password, got %v", err)
	}

	// New password should work and return the same DEK.
	mk2, err := Unlock(newPw, rec)
	if err != nil {
		t.Fatalf("Unlock with new password: %v", err)
	}
	defer mk2.Wipe()

	if string(mk2.Key()) != string(originalDEK) {
		t.Fatal("DEK changed after password change — it should be preserved")
	}
}

var legacyParams = crypto.KDFParams{Algorithm: crypto.AlgoArgon2id, Time: 1, Memory: 1024, Threads: 1, KeyLen: 32, SaltLen: 16}

// legacyRecord builds a master-key record wrapped under Argon2id, as written before PBKDF2.
func legacyRecord(t *testing.T, password []byte) (*MasterKey, *VerificationRecord) {
	t.Helper()
	mk, _, err := SetupPasswordless()
	if err != nil {
		t.Fatal(err)
	}
	salt, err := crypto.GenerateSalt(16)
	if err != nil {
		t.Fatal(err)
	}
	kek, err := crypto.DeriveKey(password, salt, legacyParams)
	if err != nil {
		t.Fatal(err)
	}
	dekCT, dekNonce, err := crypto.Encrypt(mk.Key(), kek)
	if err != nil {
		t.Fatal(err)
	}
	sentinelCT, sentinelNonce, err := crypto.Encrypt([]byte(sentinel), mk.Key())
	if err != nil {
		t.Fatal(err)
	}
	return mk, &VerificationRecord{
		Sentinel: sentinelCT, SentinelNonce: sentinelNonce,
		DEKCiphertext: dekCT, DEKNonce: dekNonce, Salt: salt, Params: legacyParams,
	}
}

func TestSetupWithPasswordUsesPBKDF2(t *testing.T) {
	t.Setenv(crypto.KDFUpgradeEnv, "true")
	password := []byte("a-long-master-password")
	mk, rec, err := SetupWithPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	defer mk.Wipe()

	if rec.Params.Algorithm != crypto.AlgoPBKDF2SHA256 || rec.Params.Time != crypto.DefaultPBKDF2Iterations {
		t.Fatalf("unexpected params for a new record: %+v", rec.Params)
	}
	mk2, err := Unlock(password, rec)
	if err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	defer mk2.Wipe()
	if string(mk.Key()) != string(mk2.Key()) {
		t.Fatal("DEK mismatch after unlock")
	}
	if _, err := Unlock([]byte("a-wrong-master-password"), rec); err != ErrWrongPassword {
		t.Fatalf("expected ErrWrongPassword, got %v", err)
	}
}

func TestUnlockLegacyArgon2idRecord(t *testing.T) {
	password := []byte("a-long-master-password")
	mk, rec := legacyRecord(t, password)
	defer mk.Wipe()

	mk2, err := Unlock(password, rec)
	if err != nil {
		t.Fatalf("Unlock legacy record: %v", err)
	}
	defer mk2.Wipe()
	if string(mk.Key()) != string(mk2.Key()) {
		t.Fatal("DEK mismatch on legacy unlock")
	}
	if _, err := Unlock([]byte("a-wrong-master-password"), rec); err != ErrWrongPassword {
		t.Fatalf("expected ErrWrongPassword for legacy record, got %v", err)
	}
}

func TestRewrapLegacyRecordUnderPBKDF2(t *testing.T) {
	t.Setenv(crypto.KDFUpgradeEnv, "true")
	password := []byte("a-long-master-password")
	mk, rec := legacyRecord(t, password)
	defer mk.Wipe()

	unlocked, err := Unlock(password, rec)
	if err != nil {
		t.Fatal(err)
	}
	defer unlocked.Wipe()

	salt, dekCT, dekNonce, params, err := WrapDEK(unlocked.Key(), password)
	if err != nil {
		t.Fatal(err)
	}
	if params.Algorithm != crypto.AlgoPBKDF2SHA256 {
		t.Fatalf("re-wrap should use PBKDF2, got %q", params.Algorithm)
	}
	rec.DEKCiphertext, rec.DEKNonce, rec.Salt, rec.Params = dekCT, dekNonce, salt, params

	again, err := Unlock(password, rec)
	if err != nil {
		t.Fatalf("Unlock after re-wrap: %v", err)
	}
	defer again.Wipe()
	if string(again.Key()) != string(mk.Key()) {
		t.Fatal("DEK changed across re-wrap")
	}
}

func TestHashUserPasswordUsesPBKDF2(t *testing.T) {
	t.Setenv(crypto.KDFUpgradeEnv, "true")
	password := []byte("a-long-user-password")
	hash, salt, params, err := HashUserPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	if params.Algorithm != crypto.AlgoPBKDF2SHA256 || params.Time != crypto.DefaultPBKDF2Iterations {
		t.Fatalf("unexpected params: %+v", params)
	}
	if !VerifyUserPassword(password, hash, salt, params) {
		t.Fatal("correct password should verify")
	}
	if VerifyUserPassword([]byte("a-wrong-user-password"), hash, salt, params) {
		t.Fatal("wrong password must not verify")
	}
}

func TestVerifyUserPasswordLegacyArgon2id(t *testing.T) {
	password := []byte("a-long-user-password")
	salt, err := crypto.GenerateSalt(16)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := crypto.DeriveKey(password, salt, legacyParams)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyUserPassword(password, hash, salt, legacyParams) {
		t.Fatal("legacy hash should verify")
	}
	if VerifyUserPassword([]byte("a-wrong-user-password"), hash, salt, legacyParams) {
		t.Fatal("wrong password must not verify against a legacy hash")
	}
	// A legacy hash must not verify when mislabelled as PBKDF2.
	if VerifyUserPassword(password, hash, salt, crypto.KDFParams{Algorithm: crypto.AlgoPBKDF2SHA256, Time: crypto.MinPBKDF2Iterations, KeyLen: 32}) {
		t.Fatal("argon2id hash verified as pbkdf2")
	}
	empty := legacyParams
	empty.Algorithm = ""
	if !VerifyUserPassword(password, hash, salt, empty) {
		t.Fatal("an empty algorithm must verify as Argon2id")
	}
	if VerifyUserPassword(password, hash, salt, crypto.KDFParams{Algorithm: "md5", Time: 1, KeyLen: 32}) {
		t.Fatal("unknown algorithm must not verify")
	}
	if VerifyUserPassword(password, hash, salt, crypto.KDFParams{KeyLen: 32}) {
		t.Fatal("zeroed Argon2id params must fail, not panic")
	}
}

func TestOffModeWritesArgon2idAndStaysReadable(t *testing.T) {
	t.Setenv(crypto.KDFUpgradeEnv, "")
	password := []byte("a-long-master-password")
	mk, rec, err := SetupWithPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	defer mk.Wipe()
	if rec.Params.Algorithm != crypto.AlgoArgon2id || rec.Params.Memory != 64*1024 {
		t.Fatalf("off mode must write Argon2id, got %+v", rec.Params)
	}
	mk2, err := Unlock(password, rec)
	if err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	mk2.Wipe()
	if _, err := Unlock([]byte("a-wrong-master-password"), rec); err != ErrWrongPassword {
		t.Fatalf("expected ErrWrongPassword, got %v", err)
	}

	userPw := []byte("a-long-user-password")
	hash, salt, params, err := HashUserPassword(userPw)
	if err != nil || params.Algorithm != crypto.AlgoArgon2id {
		t.Fatalf("off mode must hash with Argon2id: %+v %v", params, err)
	}
	if !VerifyUserPassword(userPw, hash, salt, params) || VerifyUserPassword([]byte("a-wrong-user-password"), hash, salt, params) {
		t.Fatal("off-mode hash verification wrong")
	}
}

func TestBothAlgorithmsVerifyInEitherMode(t *testing.T) {
	password := []byte("a-long-user-password")
	for _, mode := range []string{"", "true"} {
		t.Setenv(crypto.KDFUpgradeEnv, "true")
		hashA, saltA, pA, _ := HashUserPassword(password)
		t.Setenv(crypto.KDFUpgradeEnv, "")
		hashB, saltB, pB, _ := HashUserPassword(password)
		t.Setenv(crypto.KDFUpgradeEnv, mode)
		if !VerifyUserPassword(password, hashA, saltA, pA) || !VerifyUserPassword(password, hashB, saltB, pB) {
			t.Fatalf("both record kinds must verify with upgrade=%q", mode)
		}
	}
}
