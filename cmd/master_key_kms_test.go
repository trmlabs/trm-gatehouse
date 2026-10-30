package cmd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/auth"
	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/keywrap"
	"github.com/Infisical/agent-vault/internal/store"
	"github.com/spf13/cobra"
)

const testKMSKey = "gcpkms://projects/p/locations/l/keyRings/r/cryptoKeys/k"

// fakeKMS wraps with its own AES key; the flags simulate an outage or a misbehaving service.
type fakeKMS struct {
	name         string
	key          []byte
	down         bool          // every call fails
	denied       bool          // every call fails with a permission error
	lastDeadline time.Duration // time left on the context of the last Wrap
	failWrap     bool
	failUnwrap   bool
	readBack     []byte // when set, Unwrap returns this instead of the plaintext
	onUnwrap     func() // runs inside Unwrap, to land a concurrent write between a read and its write
	wraps        int
	unwraps      int
}

func newFakeKMS(t *testing.T, name string) *fakeKMS {
	t.Helper()
	key, err := crypto.GenerateSalt(32)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeKMS{name: name, key: key}
}

func (f *fakeKMS) KeyName() string { return f.name }

// keyFor derives the key for one binding, so a wrap only opens under the binding it was made with.
func (f *fakeKMS) keyFor(binding string) []byte {
	sum := sha256.Sum256(append(append([]byte(nil), f.key...), binding...))
	return sum[:]
}

func (f *fakeKMS) Wrap(ctx context.Context, plaintext []byte, binding string) ([]byte, error) {
	f.wraps++
	if dl, ok := ctx.Deadline(); ok {
		f.lastDeadline = time.Until(dl)
	}
	if f.denied {
		return nil, errors.New("rpc error: code = PermissionDenied desc = permission denied")
	}
	if f.down || f.failWrap {
		return nil, errors.New("kms unreachable")
	}
	ct, nonce, err := crypto.Encrypt(plaintext, f.keyFor(binding))
	if err != nil {
		return nil, err
	}
	return append(nonce, ct...), nil
}

func (f *fakeKMS) Unwrap(_ context.Context, wrapped []byte, binding string) ([]byte, error) {
	f.unwraps++
	if f.onUnwrap != nil {
		f.onUnwrap()
	}
	if f.denied {
		return nil, errors.New("rpc error: code = PermissionDenied desc = permission denied")
	}
	if f.down || f.failUnwrap {
		return nil, errors.New("kms unreachable")
	}
	if f.readBack != nil {
		return f.readBack, nil
	}
	if len(wrapped) < 12 {
		return nil, errors.New("ciphertext too short")
	}
	return crypto.Decrypt(wrapped[12:], wrapped[:12], f.keyFor(binding))
}

// seedPasswordVault creates a password-wrapped vault and returns its DEK.
func seedPasswordVault(t *testing.T, db store.Store, password string) []byte {
	t.Helper()
	mk, err := unlockOrSetupWithPassword(db, []byte(password))
	if err != nil {
		t.Fatal(err)
	}
	return append([]byte(nil), mk.Key()...)
}

func unlockKMS(db store.Store, w keywrap.Wrapper, password string) (*auth.MasterKey, error) {
	var pw []byte
	if password != "" {
		pw = []byte(password)
	}
	return unlockWithKMS(context.Background(), db, w, pw, nil)
}

func sameRecord(a, b *store.MasterKeyRecord) bool {
	return bytes.Equal(a.Sentinel, b.Sentinel) && bytes.Equal(a.DEKCiphertext, b.DEKCiphertext) &&
		bytes.Equal(a.DEKNonce, b.DEKNonce) && bytes.Equal(a.Salt, b.Salt) &&
		bytes.Equal(a.KMSWrappedDEK, b.KMSWrappedDEK) && a.KMSKeyName == b.KMSKeyName &&
		a.WrapKind == b.WrapKind && a.KDFAlgorithm == b.KDFAlgorithm
}

func TestNewVaultWithKMSNeedsNoPassword(t *testing.T) {
	db := openTestDB(t)
	kms := newFakeKMS(t, testKMSKey)

	mk, err := unlockKMS(db, kms, "")
	if err != nil {
		t.Fatal(err)
	}
	rec := readRecord(t, db)
	if rec.WrapKind != store.WrapKindKMS || rec.KMSKeyName != testKMSKey || rec.KMSWrappedDEK == nil {
		t.Fatalf("KMS wrap not recorded: %+v", rec)
	}
	if rec.DEKCiphertext != nil || rec.DEKPlaintext != nil || rec.Salt != nil {
		t.Fatalf("a KMS vault must hold no password wrap or plaintext key: %+v", rec)
	}

	again, err := unlockKMS(db, kms, "")
	if err != nil {
		t.Fatalf("restart: %v", err)
	}
	if !bytes.Equal(again.Key(), mk.Key()) {
		t.Fatal("restart returned a different DEK")
	}
}

func TestSwitchOverKeepsThePasswordWrapAndTheDEK(t *testing.T) {
	db := openTestDB(t)
	dek := seedPasswordVault(t, db, "a-long-master-password")
	before := readRecord(t, db)
	kms := newFakeKMS(t, testKMSKey)

	mk, err := unlockKMS(db, kms, "a-long-master-password")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(mk.Key(), dek) {
		t.Fatal("switch-over changed the DEK")
	}
	if kms.wraps != 1 || kms.unwraps != 1 {
		t.Fatalf("expected one wrap and one verifying unwrap, got %d and %d", kms.wraps, kms.unwraps)
	}
	rec := readRecord(t, db)
	if rec.WrapKind != store.WrapKindKMS || rec.KMSKeyName != testKMSKey || rec.KMSWrappedDEK == nil {
		t.Fatalf("KMS wrap not saved: %+v", rec)
	}
	if !bytes.Equal(rec.DEKCiphertext, before.DEKCiphertext) || !bytes.Equal(rec.Salt, before.Salt) || !bytes.Equal(rec.Sentinel, before.Sentinel) {
		t.Fatal("switch-over must keep the password wrap and re-encrypt nothing")
	}

	kms.unwraps = 0
	mk2, err := unlockKMS(db, kms, "")
	if err != nil || !bytes.Equal(mk2.Key(), dek) {
		t.Fatalf("restart with KMS alone: %v", err)
	}
	if kms.unwraps != 1 {
		t.Fatalf("restart should unlock through KMS, unwraps=%d", kms.unwraps)
	}
}

func TestSwitchOverVerifiesBeforeSaving(t *testing.T) {
	for name, mutate := range map[string]func(*fakeKMS){
		"wrap fails":          func(f *fakeKMS) { f.failWrap = true },
		"read-back fails":     func(f *fakeKMS) { f.failUnwrap = true },
		"read-back differs":   func(f *fakeKMS) { f.readBack = bytes.Repeat([]byte{7}, 32) },
		"service unreachable": func(f *fakeKMS) { f.down = true },
	} {
		t.Run(name, func(t *testing.T) {
			db := openTestDB(t)
			seedPasswordVault(t, db, "a-long-master-password")
			before := readRecord(t, db)
			kms := newFakeKMS(t, testKMSKey)
			mutate(kms)

			_, err := unlockKMS(db, kms, "a-long-master-password")
			if err == nil || !strings.Contains(err.Error(), "nothing was changed") {
				t.Fatalf("expected a clear switch-over error, got %v", err)
			}
			if !sameRecord(before, readRecord(t, db)) {
				t.Fatal("a failed switch-over must not change the record")
			}
		})
	}
}

func TestSwitchOverNeedsTheRightPassword(t *testing.T) {
	db := openTestDB(t)
	seedPasswordVault(t, db, "a-long-master-password")
	before := readRecord(t, db)
	kms := newFakeKMS(t, testKMSKey)

	if _, err := unlockKMS(db, kms, ""); err == nil || !strings.Contains(err.Error(), "AGENT_VAULT_MASTER_PASSWORD") {
		t.Fatalf("expected a hint to provide the password, got %v", err)
	}
	if _, err := unlockKMS(db, kms, "a-wrong-master-password"); err == nil {
		t.Fatal("wrong password must fail")
	}
	if kms.wraps != 0 {
		t.Fatal("KMS must not be called before the password is right")
	}
	if !sameRecord(before, readRecord(t, db)) {
		t.Fatal("record changed")
	}
}

func TestSwitchOverPromptsWhenNoPasswordWasGiven(t *testing.T) {
	db := openTestDB(t)
	dek := seedPasswordVault(t, db, "a-long-master-password")
	prompt := func() ([]byte, error) { return []byte("a-long-master-password"), nil }

	mk, err := unlockWithKMS(context.Background(), db, newFakeKMS(t, testKMSKey), nil, prompt)
	if err != nil || !bytes.Equal(mk.Key(), dek) {
		t.Fatalf("prompted switch-over: %v", err)
	}
}

func TestPasswordlessVaultIsNotSwitchedSilently(t *testing.T) {
	db := openTestDB(t)
	if _, err := unlockOrSetupWithPassword(db, nil); err != nil {
		t.Fatal(err)
	}
	before := readRecord(t, db)
	if _, err := unlockKMS(db, newFakeKMS(t, testKMSKey), ""); err == nil || !strings.Contains(err.Error(), "master-password set") {
		t.Fatalf("expected guidance to set a password first, got %v", err)
	}
	if !sameRecord(before, readRecord(t, db)) {
		t.Fatal("record changed")
	}
}

func TestWrongKMSKeyFailsClearlyAndChangesNothing(t *testing.T) {
	db := openTestDB(t)
	if _, err := unlockKMS(db, newFakeKMS(t, testKMSKey), ""); err != nil {
		t.Fatal(err)
	}
	before := readRecord(t, db)

	other := newFakeKMS(t, testKMSKey) // same name, different key material
	if _, err := unlockKMS(db, other, ""); err == nil || !strings.Contains(err.Error(), "unwrapping with KMS key") {
		t.Fatalf("expected an unwrap error, got %v", err)
	}

	renamed := newFakeKMS(t, "gcpkms://projects/p/locations/l/keyRings/r/cryptoKeys/other")
	if _, err := unlockKMS(db, renamed, ""); err == nil || !strings.Contains(err.Error(), "is wrapped by "+testKMSKey) {
		t.Fatalf("expected a key-name mismatch error, got %v", err)
	}
	if renamed.unwraps != 0 {
		t.Fatal("a different key name must be refused before calling KMS")
	}

	impostor := newFakeKMS(t, testKMSKey)
	impostor.readBack = bytes.Repeat([]byte{9}, 32)
	if _, err := unlockKMS(db, impostor, ""); !errors.Is(err, auth.ErrWrongKMSKey) {
		t.Fatalf("expected ErrWrongKMSKey, got %v", err)
	}
	if !sameRecord(before, readRecord(t, db)) {
		t.Fatal("a failed unlock must not change the record")
	}
}

// captureLogs routes slog to a buffer for the test.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(old) })
	return &buf
}

// switchedVault returns a password vault already switched to KMS, still holding its password wrap.
func switchedVault(t *testing.T, password string) (store.Store, []byte, *fakeKMS) {
	t.Helper()
	db := openTestDB(t)
	dek := seedPasswordVault(t, db, password)
	kms := newFakeKMS(t, testKMSKey)
	if _, err := unlockKMS(db, kms, password); err != nil {
		t.Fatal(err)
	}
	return db, dek, kms
}

func TestKMSFailureRefusesUnlessBreakGlassIsOn(t *testing.T) {
	const password = "a-long-master-password"
	failures := map[string]func(base *fakeKMS) *fakeKMS{
		"wrong key": func(base *fakeKMS) *fakeKMS { return newFakeKMS(t, testKMSKey) },
		"permission denied": func(base *fakeKMS) *fakeKMS {
			f := newFakeKMSLike(base)
			f.denied = true
			return f
		},
		"unreachable": func(base *fakeKMS) *fakeKMS {
			f := newFakeKMSLike(base)
			f.down = true
			return f
		},
		"other key name": func(base *fakeKMS) *fakeKMS {
			return newFakeKMS(t, "gcpkms://projects/pr-other/locations/l/keyRings/r/cryptoKeys/other")
		},
	}
	for name, mk := range failures {
		t.Run(name+"/off", func(t *testing.T) {
			db, _, base := switchedVault(t, password)
			before := readRecord(t, db)
			logs := captureLogs(t)
			if _, err := unlockKMS(db, mk(base), password); err == nil || !strings.Contains(err.Error(), envKMSBreakGlass) {
				t.Fatalf("with break-glass off the start must refuse and name the setting, got %v", err)
			}
			if !sameRecord(before, readRecord(t, db)) {
				t.Fatal("a refused start must change nothing")
			}
			if strings.Contains(logs.String(), "unlocked with the break-glass") {
				t.Fatal("must not log a break-glass unlock")
			}
		})
		t.Run(name+"/on", func(t *testing.T) {
			t.Setenv(envKMSBreakGlass, "true")
			db, dek, base := switchedVault(t, password)
			logs := captureLogs(t)
			got, err := unlockKMS(db, mk(base), password)
			if err != nil || !bytes.Equal(got.Key(), dek) {
				t.Fatalf("break-glass unlock: %v", err)
			}
			if !strings.Contains(logs.String(), "level=ERROR") || !strings.Contains(logs.String(), "break-glass master password") {
				t.Fatalf("the fallback must log at Error, got %q", logs.String())
			}
			if readRecord(t, db).WrapKind != store.WrapKindKMSFallback {
				t.Fatal("the fallback unlock was not recorded")
			}
		})
	}
}

func TestBreakGlassNeedsAPasswordAndARemainingWrap(t *testing.T) {
	t.Setenv(envKMSBreakGlass, "true")
	db, _, kms := switchedVault(t, "a-long-master-password")
	down := newFakeKMSLike(kms)
	down.down = true
	if _, err := unlockKMS(db, down, ""); err == nil || !strings.Contains(err.Error(), "no master password was provided") {
		t.Fatalf("got %v", err)
	}
	if _, err := unlockKMS(db, down, "a-wrong-master-password"); err == nil || !strings.Contains(err.Error(), "also failed") {
		t.Fatalf("a wrong break-glass password should say so, got %v", err)
	}
	if err := removePasswordWrap(context.Background(), db, kms); err != nil {
		t.Fatal(err)
	}
	if _, err := unlockKMS(db, down, "a-long-master-password"); err == nil || !strings.Contains(err.Error(), "no break-glass") {
		t.Fatalf("with no password wrap, KMS down must fail, got %v", err)
	}
}

func TestBreakGlassSettingMustParse(t *testing.T) {
	t.Setenv(envKMSBreakGlass, "yes please")
	db, _, kms := switchedVault(t, "a-long-master-password")
	kms.down = true
	if _, err := unlockKMS(db, kms, "a-long-master-password"); err == nil || !strings.Contains(err.Error(), "must be true or false") {
		t.Fatalf("got %v", err)
	}
	if _, err := kmsWrapperFromEnv(context.Background()); err == nil {
		t.Fatal("an unparseable break-glass setting must stop startup")
	}
}

func TestKMSFIPSSettingMustParse(t *testing.T) {
	t.Setenv(keywrap.EnvKMS, testKMSKey)
	t.Setenv(keywrap.EnvKMSFIPS, "maybe")
	if _, err := kmsWrapperFromEnv(context.Background()); err == nil || !strings.Contains(err.Error(), keywrap.EnvKMSFIPS) {
		t.Fatalf("got %v", err)
	}
}

func TestRemovePasswordWrapRefusesAfterAFallbackUnlock(t *testing.T) {
	t.Setenv(envKMSBreakGlass, "true")
	db, _, kms := switchedVault(t, "a-long-master-password")
	down := newFakeKMSLike(kms)
	down.down = true
	if _, err := unlockKMS(db, down, "a-long-master-password"); err != nil {
		t.Fatal(err)
	}
	before := readRecord(t, db)
	if err := removePasswordWrap(context.Background(), db, kms); err == nil || !strings.Contains(err.Error(), "break-glass") {
		t.Fatalf("removal must refuse after a fallback unlock, got %v", err)
	}
	if !sameRecord(before, readRecord(t, db)) {
		t.Fatal("a refused removal must not change the record")
	}
	if _, err := unlockKMS(db, kms, ""); err != nil {
		t.Fatal(err)
	}
	if readRecord(t, db).WrapKind != store.WrapKindKMS {
		t.Fatal("a KMS unlock should clear the fallback mark")
	}
	if err := removePasswordWrap(context.Background(), db, kms); err != nil {
		t.Fatalf("removal after a healthy KMS unlock: %v", err)
	}
}

func TestWrapIsBoundToItsVault(t *testing.T) {
	kms := newFakeKMS(t, testKMSKey)
	dbA, dbB := openTestDB(t), openTestDB(t)
	if _, err := unlockKMS(dbA, kms, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := unlockKMS(dbB, kms, ""); err != nil {
		t.Fatal(err)
	}
	a, b := readRecord(t, dbA), readRecord(t, dbB)
	if auth.KMSBinding(a.Sentinel) == auth.KMSBinding(b.Sentinel) {
		t.Fatal("two vaults must not share a binding")
	}
	if _, err := kms.Unwrap(context.Background(), a.KMSWrappedDEK, auth.KMSBinding(b.Sentinel)); err == nil {
		t.Fatal("vault A's wrap must not unwrap under vault B's binding")
	}
	if _, err := kms.Unwrap(context.Background(), a.KMSWrappedDEK, auth.KMSBinding(a.Sentinel)); err != nil {
		t.Fatal(err)
	}
}

func TestKMSTimeoutStartsAfterThePasswordPrompt(t *testing.T) {
	db := openTestDB(t)
	seedPasswordVault(t, db, "a-long-master-password")
	kms := newFakeKMS(t, testKMSKey)
	prompt := func() ([]byte, error) {
		time.Sleep(1500 * time.Millisecond)
		return []byte("a-long-master-password"), nil
	}
	if _, err := unlockWithKMS(context.Background(), db, kms, nil, prompt); err != nil {
		t.Fatal(err)
	}
	// The prompt takes 1.5s, so a timeout started before it leaves under kmsTimeout-1s; the margin absorbs the unlock under -race.
	if kms.lastDeadline < kmsTimeout-time.Second {
		t.Fatalf("the KMS timeout started before the prompt: %v left", kms.lastDeadline)
	}
}

func TestKMSVaultStartedWithoutKMSRefusesUnlessBreakGlassIsOn(t *testing.T) {
	const password = "a-long-master-password"
	db, dek, kms := switchedVault(t, password)
	before := readRecord(t, db)

	for name, start := range map[string]func() (*auth.MasterKey, error){
		"env password": func() (*auth.MasterKey, error) { return unlockOrSetupWithPassword(db, []byte(password)) },
		"interactive":  func() (*auth.MasterKey, error) { return unlockOrSetup(&cobra.Command{}, db, false) },
	} {
		t.Setenv(envKMSBreakGlass, "")
		if _, err := start(); err == nil || !strings.Contains(err.Error(), keywrap.EnvKMS) || !strings.Contains(err.Error(), envKMSBreakGlass) {
			t.Fatalf("%s: expected a refusal naming both settings, got %v", name, err)
		}
		if !sameRecord(before, readRecord(t, db)) {
			t.Fatalf("%s: a refused start must not change the record", name)
		}
	}

	t.Setenv(envKMSBreakGlass, "true")
	logs := captureLogs(t)
	mk, err := unlockOrSetupWithPassword(db, []byte(password))
	if err != nil || !bytes.Equal(mk.Key(), dek) {
		t.Fatalf("break-glass start without KMS: %v", err)
	}
	if !strings.Contains(logs.String(), "level=ERROR") || !strings.Contains(logs.String(), keywrap.EnvKMS+" is not set") {
		t.Fatalf("expected an error log, got %q", logs.String())
	}
	if readRecord(t, db).WrapKind != store.WrapKindKMSFallback {
		t.Fatal("a break-glass start without KMS must be recorded like a KMS failure fallback")
	}
	if err := removePasswordWrap(context.Background(), db, kms); err == nil || !strings.Contains(err.Error(), "break-glass") {
		t.Fatalf("removal must refuse after a break-glass unlock, got %v", err)
	}
	if _, err := unlockKMS(db, kms, ""); err != nil {
		t.Fatal(err)
	}
	if readRecord(t, db).WrapKind != store.WrapKindKMS {
		t.Fatal("a KMS unlock should clear the fallback mark")
	}
}

func TestBreakGlassSettingMustParseWhenKMSIsNotConfigured(t *testing.T) {
	db, _, _ := switchedVault(t, "a-long-master-password")
	t.Setenv(envKMSBreakGlass, "yes please")
	if _, err := unlockOrSetupWithPassword(db, []byte("a-long-master-password")); err == nil || !strings.Contains(err.Error(), envKMSBreakGlass) {
		t.Fatalf("got %v", err)
	}
}

// plaintextBesideKMSWrap simulates an old image's 'master-password remove' on a KMS vault.
func plaintextBesideKMSWrap(t *testing.T, db store.Store, plaintext []byte) {
	t.Helper()
	rec := readRecord(t, db)
	rec.DEKPlaintext = plaintext
	if err := db.UpdateMasterKeyRecord(context.Background(), rec); err != nil {
		t.Fatal(err)
	}
}

func TestKMSUnlockClearsAPlaintextKeyBesideTheKMSWrap(t *testing.T) {
	db, dek, kms := switchedVault(t, "a-long-master-password")
	plaintextBesideKMSWrap(t, db, dek)
	logs := captureLogs(t)
	if _, err := unlockKMS(db, kms, ""); err != nil {
		t.Fatal(err)
	}
	rec := readRecord(t, db)
	if rec.DEKPlaintext != nil || rec.KMSWrappedDEK == nil || rec.DEKCiphertext == nil {
		t.Fatalf("only the plaintext key should be cleared: %+v", rec)
	}
	if !strings.Contains(logs.String(), "cleared the plaintext master key") {
		t.Fatalf("expected a log line, got %q", logs.String())
	}
}

func TestKMSUnlockLeavesAPlaintextKeyThatDiffersFromTheWrappedOne(t *testing.T) {
	db, _, kms := switchedVault(t, "a-long-master-password")
	other := bytes.Repeat([]byte{7}, 32)
	plaintextBesideKMSWrap(t, db, other)
	if _, err := unlockKMS(db, kms, ""); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(readRecord(t, db).DEKPlaintext, other) {
		t.Fatal("a plaintext key that does not match the KMS-wrapped one must be left for a person to look at")
	}
}

func TestKMSUnlockDoesNotClearThePlaintextKeyWhenKMSFails(t *testing.T) {
	t.Setenv(envKMSBreakGlass, "true")
	db, dek, kms := switchedVault(t, "a-long-master-password")
	plaintextBesideKMSWrap(t, db, dek)
	down := newFakeKMSLike(kms)
	down.down = true
	if _, err := unlockKMS(db, down, "a-long-master-password"); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(readRecord(t, db).DEKPlaintext, dek) {
		t.Fatal("the plaintext key must stay until KMS has unwrapped the key")
	}
}

func TestRemovePasswordWrapClearsAPlaintextKey(t *testing.T) {
	db, dek, kms := switchedVault(t, "a-long-master-password")
	plaintextBesideKMSWrap(t, db, dek)
	if err := removePasswordWrap(context.Background(), db, kms); err != nil {
		t.Fatal(err)
	}
	if rec := readRecord(t, db); rec.DEKPlaintext != nil || rec.DEKCiphertext != nil || rec.KMSWrappedDEK == nil {
		t.Fatalf("removal must leave only the KMS wrap: %+v", rec)
	}
}

func TestRemovePasswordWrapRefusesAPlaintextKeyThatDiffers(t *testing.T) {
	db, _, kms := switchedVault(t, "a-long-master-password")
	plaintextBesideKMSWrap(t, db, bytes.Repeat([]byte{7}, 32))
	before := readRecord(t, db)
	if err := removePasswordWrap(context.Background(), db, kms); err == nil {
		t.Fatal("expected a refusal")
	}
	if !bytes.Equal(before.DEKPlaintext, readRecord(t, db).DEKPlaintext) || readRecord(t, db).DEKCiphertext == nil {
		t.Fatal("a refused removal must not change the record")
	}
}

func TestRemovePasswordWrapKeepsABreakGlassMarkRecordedMidway(t *testing.T) {
	db, _, kms := switchedVault(t, "a-long-master-password")
	kms.onUnwrap = func() {
		if err := db.SetMasterKeyWrapKind(context.Background(), store.WrapKindKMSFallback); err != nil {
			t.Fatal(err)
		}
	}
	if err := removePasswordWrap(context.Background(), db, kms); err == nil || !strings.Contains(err.Error(), "changed while removing") {
		t.Fatalf("a removal that lost the race must refuse, got %v", err)
	}
	if rec := readRecord(t, db); rec.WrapKind != store.WrapKindKMSFallback || rec.DEKCiphertext == nil || rec.Salt == nil {
		t.Fatalf("the break-glass mark or the password wrap was lost: %+v", rec)
	}
	kms.onUnwrap = nil
	if err := removePasswordWrap(context.Background(), db, kms); err == nil || !strings.Contains(err.Error(), "break-glass") {
		t.Fatalf("a rerun must stop at the break-glass mark, got %v", err)
	}
}

// newFakeKMSLike returns a healthy copy of f that unwraps what f wrapped.
func newFakeKMSLike(f *fakeKMS) *fakeKMS {
	return &fakeKMS{name: f.name, key: f.key}
}

func TestRemovePasswordWrap(t *testing.T) {
	db := openTestDB(t)
	dek := seedPasswordVault(t, db, "a-long-master-password")
	kms := newFakeKMS(t, testKMSKey)
	if _, err := unlockKMS(db, kms, "a-long-master-password"); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	down := newFakeKMSLike(kms)
	down.down = true
	before := readRecord(t, db)
	if err := removePasswordWrap(ctx, db, down); err == nil || !strings.Contains(err.Error(), "KMS cannot unwrap") {
		t.Fatalf("removal must refuse when KMS cannot unwrap, got %v", err)
	}
	wrongKey := newFakeKMS(t, testKMSKey)
	if err := removePasswordWrap(ctx, db, wrongKey); err == nil {
		t.Fatal("removal must refuse when the configured key cannot unwrap")
	}
	if !sameRecord(before, readRecord(t, db)) {
		t.Fatal("a refused removal must not change the record")
	}

	if err := removePasswordWrap(ctx, db, kms); err != nil {
		t.Fatal(err)
	}
	rec := readRecord(t, db)
	if rec.DEKCiphertext != nil || rec.DEKNonce != nil || rec.Salt != nil || rec.DEKPlaintext != nil || rec.KMSWrappedDEK == nil {
		t.Fatalf("password wrap not removed cleanly: %+v", rec)
	}
	mk, err := unlockKMS(db, kms, "")
	if err != nil || !bytes.Equal(mk.Key(), dek) {
		t.Fatalf("start with KMS alone: %v", err)
	}
	if err := removePasswordWrap(ctx, db, kms); err == nil {
		t.Fatal("a second removal should say there is nothing to remove")
	}
}

func TestRemovePasswordWrapNeedsASwitchedVault(t *testing.T) {
	db := openTestDB(t)
	seedPasswordVault(t, db, "a-long-master-password")
	before := readRecord(t, db)
	if err := removePasswordWrap(context.Background(), db, newFakeKMS(t, testKMSKey)); err == nil || !strings.Contains(err.Error(), "not wrapped by KMS yet") {
		t.Fatalf("got %v", err)
	}
	if !sameRecord(before, readRecord(t, db)) {
		t.Fatal("record changed")
	}
}

func TestUnlockOrSetupSelectsKMSFromTheEnvironment(t *testing.T) {
	db := openTestDB(t)
	kms := newFakeKMS(t, testKMSKey)
	orig := newKMSWrapper
	newKMSWrapper = func(_ context.Context, value string) (keywrap.Wrapper, error) {
		if value != testKMSKey {
			t.Errorf("wrapper built for %q", value)
		}
		return kms, nil
	}
	t.Cleanup(func() { newKMSWrapper = orig })
	t.Setenv(keywrap.EnvKMS, testKMSKey)
	t.Setenv("AGENT_VAULT_MASTER_PASSWORD", "")

	if _, err := unlockOrSetup(&cobra.Command{}, db, false); err != nil {
		t.Fatal(err)
	}
	if readRecord(t, db).WrapKind != store.WrapKindKMS {
		t.Fatal("a new vault should be wrapped by KMS when it is configured")
	}

	// Without KMS configured, a KMS-only vault says what to set instead of "wrong password".
	t.Setenv(keywrap.EnvKMS, "")
	if _, err := unlockOrSetupWithPassword(db, []byte("anything-at-all")); err == nil || !strings.Contains(err.Error(), keywrap.EnvKMS) {
		t.Fatalf("expected a hint to set %s, got %v", keywrap.EnvKMS, err)
	}
	if _, err := unlockOrSetup(&cobra.Command{}, db, false); err == nil || !strings.Contains(err.Error(), keywrap.EnvKMS) {
		t.Fatalf("the interactive path should name %s too, got %v", keywrap.EnvKMS, err)
	}
}

func TestBreakGlassPasswordStillUnlocksWithoutKMSConfigured(t *testing.T) {
	t.Setenv(envKMSBreakGlass, "true")
	db := openTestDB(t)
	dek := seedPasswordVault(t, db, "a-long-master-password")
	if _, err := unlockKMS(db, newFakeKMS(t, testKMSKey), "a-long-master-password"); err != nil {
		t.Fatal(err)
	}
	mk, err := unlockOrSetupWithPassword(db, []byte("a-long-master-password"))
	if err != nil || !bytes.Equal(mk.Key(), dek) {
		t.Fatalf("password unlock of a switched vault: %v", err)
	}
}

func TestSwitchOverLeavesALegacyPasswordWrapUntouched(t *testing.T) {
	for _, upgrade := range []string{"", "true"} {
		t.Run("upgrade="+upgrade, func(t *testing.T) {
			t.Setenv(crypto.KDFUpgradeEnv, upgrade)
			db := openTestDB(t)
			dek := seedLegacyMasterKey(t, db, []byte("a-long-master-password"))
			before := readRecord(t, db)
			w := newFakeKMS(t, testKMSKey)

			mk, err := unlockKMS(db, w, "a-long-master-password")
			if err != nil || !bytes.Equal(mk.Key(), dek) {
				t.Fatalf("switch-over: %v", err)
			}
			if mk, err = unlockKMS(db, w, ""); err != nil || !bytes.Equal(mk.Key(), dek) {
				t.Fatalf("unlock after switch-over: %v", err)
			}
			rec := readRecord(t, db)
			if rec.KDFAlgorithm != crypto.AlgoArgon2id || !bytes.Equal(rec.DEKCiphertext, before.DEKCiphertext) ||
				!bytes.Equal(rec.DEKNonce, before.DEKNonce) || !bytes.Equal(rec.Salt, before.Salt) {
				t.Fatalf("the password wrap must be exactly as it was: %+v", rec)
			}
		})
	}
}

// racingStore changes the password wrap between the switch-over's read and its write.
type racingStore struct {
	store.Store
	race func()
}

func (r racingStore) SetMasterKeyKMSWrap(ctx context.Context, expected *store.MasterKeyRecord, wrapped []byte, keyName string) (bool, error) {
	r.race()
	return r.Store.SetMasterKeyKMSWrap(ctx, expected, wrapped, keyName)
}

func TestSwitchOverNeverWritesBackAStalePasswordWrap(t *testing.T) {
	db := openTestDB(t)
	seedPasswordVault(t, db, "a-long-master-password")
	changed := readRecord(t, db)
	changed.Salt = append([]byte("changed-"), changed.Salt...)
	racing := racingStore{Store: db, race: func() {
		if err := db.UpdateMasterKeyRecord(context.Background(), changed); err != nil {
			t.Error(err)
		}
	}}
	if _, err := unlockWithKMS(context.Background(), racing, newFakeKMS(t, testKMSKey), []byte("a-long-master-password"), nil); err == nil || !strings.Contains(err.Error(), "changed while switching") {
		t.Fatalf("got %v", err)
	}
	rec := readRecord(t, db)
	if rec.KMSWrappedDEK != nil || !bytes.Equal(rec.Salt, changed.Salt) {
		t.Fatalf("the concurrent change was lost or a KMS wrap slipped in: %+v", rec)
	}
}
