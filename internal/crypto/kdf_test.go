package crypto

import (
	"bytes"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/argon2"
)

var (
	testPBKDF2 = KDFParams{Algorithm: AlgoPBKDF2SHA256, Time: MinPBKDF2Iterations, KeyLen: 32, SaltLen: 16}
	testArgon2 = KDFParams{Algorithm: AlgoArgon2id, Time: 1, Memory: 1024, Threads: 1, KeyLen: 32, SaltLen: 16}
)

func mustDerive(t *testing.T, password, salt []byte, p KDFParams) []byte {
	t.Helper()
	key, err := DeriveKey(password, salt, p)
	if err != nil {
		t.Fatalf("DeriveKey: %v", err)
	}
	return key
}

func TestDeriveKeySameSaltSameKey(t *testing.T) {
	salt := []byte("0123456789abcdef")
	password := []byte("my-secret-password")

	if !bytes.Equal(mustDerive(t, password, salt, testPBKDF2), mustDerive(t, password, salt, testPBKDF2)) {
		t.Fatal("same password and salt should produce the same key")
	}
}

func TestDeriveKeyDifferentSaltsDifferentKeys(t *testing.T) {
	password := []byte("my-secret-password")

	key1 := mustDerive(t, password, []byte("salt-aaaaaaaaaaaa"), testPBKDF2)
	key2 := mustDerive(t, password, []byte("salt-bbbbbbbbbbbb"), testPBKDF2)

	if bytes.Equal(key1, key2) {
		t.Fatal("different salts should produce different keys")
	}
}

func TestDeriveKeyOutputLength(t *testing.T) {
	key := mustDerive(t, []byte("a-long-enough-password"), []byte("0123456789abcdef"), testPBKDF2)
	if len(key) != 32 {
		t.Fatalf("expected 32-byte key, got %d", len(key))
	}
}

func TestPBKDF2KnownAnswer(t *testing.T) {
	// PBKDF2-HMAC-SHA256 vector, 600000 iterations, 40-byte output, cross-checked against Python hashlib.
	p := KDFParams{Algorithm: AlgoPBKDF2SHA256, Time: 600_000, KeyLen: 40}
	got := mustDerive(t, []byte("passwordPASSWORDpassword"), []byte("saltSALTsaltSALTsaltSALTsaltSALTsalt"), p)
	want := "b51565c8bb9dcde57bc26aa72fb65d0fe7b4cbdb42aed0dbd456a145980fb1892939949d7b50a4e8"
	if hex.EncodeToString(got) != want {
		t.Fatalf("PBKDF2 mismatch: got %x", got)
	}
}

func TestDeriveKeyAlgorithmsDiffer(t *testing.T) {
	password, salt := []byte("a-long-enough-password"), []byte("0123456789abcdef")
	if bytes.Equal(mustDerive(t, password, salt, testPBKDF2), mustDerive(t, password, salt, testArgon2)) {
		t.Fatal("PBKDF2 and Argon2id outputs should differ")
	}
}

func TestDeriveKeyLegacyArgon2idStillDerives(t *testing.T) {
	password, salt := []byte("a-long-enough-password"), []byte("0123456789abcdef")
	if !testArgon2.IsLegacy() || testPBKDF2.IsLegacy() {
		t.Fatal("IsLegacy should be true only for argon2id")
	}
	if !bytes.Equal(mustDerive(t, password, salt, testArgon2), mustDerive(t, password, salt, testArgon2)) {
		t.Fatal("argon2id derivation should be deterministic")
	}
}

func TestDeriveKeyUnknownAlgorithm(t *testing.T) {
	if _, err := DeriveKey([]byte("pw"), []byte("0123456789abcdef"), KDFParams{Algorithm: "md5", Time: 1, KeyLen: 32}); err == nil {
		t.Fatal("expected error for unknown algorithm")
	}
}

func TestDeriveKeyEmptyAlgorithmIsArgon2id(t *testing.T) {
	password, salt := []byte("a-long-enough-password"), []byte("0123456789abcdef")
	empty := testArgon2
	empty.Algorithm = ""
	if !bytes.Equal(mustDerive(t, password, salt, empty), mustDerive(t, password, salt, testArgon2)) {
		t.Fatal("an empty algorithm must derive as Argon2id")
	}
	if !empty.IsLegacy() {
		t.Fatal("an empty algorithm must count as legacy")
	}
}

func TestDefaultKDFParamsOffWritesArgon2id(t *testing.T) {
	t.Setenv(KDFUpgradeEnv, "")
	t.Setenv(IterationsEnv, "")
	p, err := DefaultKDFParams()
	if err != nil {
		t.Fatal(err)
	}
	if p.Algorithm != AlgoArgon2id || p.Time != 3 || p.Memory != 64*1024 || p.Threads != 4 || p.KeyLen != 32 || p.SaltLen != 16 {
		t.Fatalf("off mode must write the legacy Argon2id params an older image reads, got %+v", p)
	}
	if UpgradeEnabled() {
		t.Fatal("upgrade must default to off")
	}
}

func TestDefaultKDFParamsOnWritesPBKDF2(t *testing.T) {
	t.Setenv(KDFUpgradeEnv, "true")
	t.Setenv(IterationsEnv, "")
	p, err := DefaultKDFParams()
	if err != nil {
		t.Fatal(err)
	}
	if p.Algorithm != AlgoPBKDF2SHA256 || p.Time != 600_000 || p.Memory != 0 || p.Threads != 0 || p.KeyLen != 32 || p.SaltLen != 16 {
		t.Fatalf("unexpected defaults: %+v", p)
	}
}

func TestDefaultKDFParamsIterationsConfigurable(t *testing.T) {
	t.Setenv(KDFUpgradeEnv, "true")
	t.Setenv(IterationsEnv, "750000")
	p, err := DefaultKDFParams()
	if err != nil || p.Time != 750000 {
		t.Fatalf("expected 750000 iterations, got %+v err=%v", p, err)
	}
}

func TestKDFConfigRejectsBadValues(t *testing.T) {
	for _, bad := range []string{"abc", "599999", "10000001", "-5", "0"} {
		t.Setenv(IterationsEnv, bad)
		if _, err := DefaultKDFParams(); err == nil {
			t.Fatalf("iterations %q should be an error, not a silent fallback", bad)
		}
		if _, _, err := KDFConfig(); err == nil {
			t.Fatalf("KDFConfig should reject iterations %q", bad)
		}
	}
	t.Setenv(IterationsEnv, "")
	t.Setenv(KDFUpgradeEnv, "maybe")
	if _, _, err := KDFConfig(); err == nil {
		t.Fatal("a non-boolean upgrade setting should be an error")
	}
	for _, edge := range []string{"600000", "10000000"} {
		t.Setenv(KDFUpgradeEnv, "true")
		t.Setenv(IterationsEnv, edge)
		if _, _, err := KDFConfig(); err != nil {
			t.Fatalf("iterations %s should be accepted: %v", edge, err)
		}
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

func TestOffModeRecordMatchesWhatTheOlderImageDerives(t *testing.T) {
	t.Setenv(KDFUpgradeEnv, "")
	p, err := DefaultKDFParams()
	if err != nil {
		t.Fatal(err)
	}
	password, salt := []byte("a-long-enough-password"), []byte("0123456789abcdef")
	got := mustDerive(t, password, salt, p)
	// The pre-PBKDF2 code called argon2.IDKey directly with these stored params.
	want := argon2.IDKey(password, salt, p.Time, p.Memory, p.Threads, p.KeyLen)
	if !bytes.Equal(got, want) {
		t.Fatal("off-mode derivation differs from the legacy argon2id call")
	}
}

func TestMislabelledPBKDF2RecordDerivesAsArgon2id(t *testing.T) {
	password, salt := []byte("a-long-enough-password"), []byte("0123456789abcdef")
	want := mustDerive(t, password, salt, testArgon2)
	p := KDFParams{Algorithm: AlgoPBKDF2SHA256, Time: 1, Memory: 1024, Threads: 1, KeyLen: 32}
	if p.EffectiveAlgorithm() != AlgoArgon2id || !bytes.Equal(mustDerive(t, password, salt, p), want) {
		t.Fatal("a pbkdf2-labelled record with Argon2id params must derive as Argon2id")
	}
	if (KDFParams{Algorithm: AlgoPBKDF2SHA256, Time: MinPBKDF2Iterations, Threads: 1}).EffectiveAlgorithm() != AlgoArgon2id {
		t.Fatal("threads on a pbkdf2 record mean it is Argon2id")
	}
	low := KDFParams{Algorithm: AlgoPBKDF2SHA256, Time: MinPBKDF2Iterations - 1, KeyLen: 32}
	if low.EffectiveAlgorithm() != AlgoPBKDF2SHA256 {
		t.Fatal("the iteration count must not decide whether a record is mislabelled")
	}
	if _, err := DeriveKey([]byte("pw"), []byte("0123456789abcdef"), KDFParams{Algorithm: AlgoPBKDF2SHA256, Time: 0, KeyLen: 32}); err == nil {
		t.Fatal("zero iterations must be an invalid record, not a re-read as Argon2id")
	}
	if testPBKDF2.EffectiveAlgorithm() != AlgoPBKDF2SHA256 {
		t.Fatal("a real PBKDF2 record must stay PBKDF2")
	}
}

func TestDeriveKeyBoundsParamsFromTheDatabase(t *testing.T) {
	password, salt := []byte("a-long-enough-password"), []byte("0123456789abcdef")
	bad := map[string]KDFParams{
		"pbkdf2 above max":      {Algorithm: AlgoPBKDF2SHA256, Time: MaxPBKDF2Iterations + 1, KeyLen: 32},
		"argon2 memory above":   {Algorithm: AlgoArgon2id, Time: 1, Memory: MaxArgon2idMemoryKiB + 1, Threads: 1, KeyLen: 32},
		"argon2 passes above":   {Algorithm: AlgoArgon2id, Time: MaxArgon2idPasses + 1, Memory: 1024, Threads: 1, KeyLen: 32},
		"argon2 zero memory":    {Algorithm: AlgoArgon2id, Time: 1, Memory: 0, Threads: 1, KeyLen: 32},
		"argon2 zero passes":    {Algorithm: AlgoArgon2id, Time: 0, Memory: 1024, Threads: 1, KeyLen: 32},
		"argon2 zero threads":   {Algorithm: AlgoArgon2id, Time: 1, Memory: 1024, Threads: 0, KeyLen: 32},
		"mislabelled huge pass": {Algorithm: AlgoPBKDF2SHA256, Time: 11, Memory: 1024, Threads: 1, KeyLen: 32},
	}
	for name, p := range bad {
		if _, err := DeriveKey(password, salt, p); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	for name, p := range map[string]KDFParams{
		"argon2 max passes": {Algorithm: AlgoArgon2id, Time: MaxArgon2idPasses, Memory: 8, Threads: 1, KeyLen: 32},
		"argon2 max memory": {Algorithm: AlgoArgon2id, Time: 1, Memory: MaxArgon2idMemoryKiB, Threads: 1, KeyLen: 32},
		"pbkdf2 min":        testPBKDF2,
	} {
		if _, err := DeriveKey(password, salt, p); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestRecordsReadTheSameWhenTheConfiguredMinimumChanges(t *testing.T) {
	password, salt := []byte("a-long-enough-password"), []byte("0123456789abcdef")
	old := KDFParams{Algorithm: AlgoPBKDF2SHA256, Time: 100_000, KeyLen: 32}
	want, err := pbkdf2.Key(sha256.New, string(password), salt, int(old.Time), int(old.KeyLen))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(IterationsEnv, "900000")
	if old.EffectiveAlgorithm() != AlgoPBKDF2SHA256 || !bytes.Equal(mustDerive(t, password, salt, old), want) {
		t.Fatal("a stored record below the configured count must still read as PBKDF2 at its own count")
	}
}
