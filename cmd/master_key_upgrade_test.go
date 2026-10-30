package cmd

import (
	"context"
	"errors"
	"testing"

	"github.com/Infisical/agent-vault/internal/auth"
	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/store"
)

// seedLegacyMasterKey stores a DEK wrapped under Argon2id, as written before PBKDF2.
func seedLegacyMasterKey(t *testing.T, db store.Store, password []byte) []byte {
	t.Helper()
	mk, sentinelRec, err := auth.SetupPasswordless()
	if err != nil {
		t.Fatal(err)
	}
	p := crypto.KDFParams{Algorithm: crypto.AlgoArgon2id, Time: 1, Memory: 1024, Threads: 1, KeyLen: 32, SaltLen: 16}
	salt, err := crypto.GenerateSalt(16)
	if err != nil {
		t.Fatal(err)
	}
	kek, err := crypto.DeriveKey(password, salt, p)
	if err != nil {
		t.Fatal(err)
	}
	dekCT, dekNonce, err := crypto.Encrypt(mk.Key(), kek)
	if err != nil {
		t.Fatal(err)
	}
	err = db.SetMasterKeyRecord(context.Background(), &store.MasterKeyRecord{
		Sentinel: sentinelRec.Sentinel, SentinelNonce: sentinelRec.SentinelNonce,
		DEKCiphertext: dekCT, DEKNonce: dekNonce, Salt: salt,
		KDFTime: &p.Time, KDFMemory: &p.Memory, KDFThreads: &p.Threads, KDFAlgorithm: p.Algorithm,
	})
	if err != nil {
		t.Fatal(err)
	}
	return append([]byte(nil), mk.Key()...)
}

func readRecord(t *testing.T, db store.Store) *store.MasterKeyRecord {
	t.Helper()
	rec, err := db.GetMasterKeyRecord(context.Background())
	if err != nil || rec == nil {
		t.Fatalf("GetMasterKeyRecord: %v", err)
	}
	return rec
}

func TestUnlockRewrapsLegacyMasterKeyUnderPBKDF2WhenOn(t *testing.T) {
	t.Setenv(crypto.KDFUpgradeEnv, "true")
	db := openTestDB(t)
	password := "a-long-master-password"
	dek := seedLegacyMasterKey(t, db, []byte(password))

	mk, err := unlockOrSetupWithPassword(db, []byte(password))
	if err != nil {
		t.Fatalf("unlock legacy record: %v", err)
	}
	if string(mk.Key()) != string(dek) {
		t.Fatal("unlock returned a different DEK")
	}
	rec := readRecord(t, db)
	if rec.KDFAlgorithm != crypto.AlgoPBKDF2SHA256 || *rec.KDFTime != 600000 || *rec.KDFMemory != 0 || *rec.KDFThreads != 0 {
		t.Fatalf("record not re-wrapped under PBKDF2: %+v", rec)
	}

	mk2, err := unlockOrSetupWithPassword(db, []byte(password))
	if err != nil {
		t.Fatalf("unlock after re-wrap: %v", err)
	}
	if string(mk2.Key()) != string(dek) {
		t.Fatal("DEK changed across re-wrap")
	}
}

func TestUnlockNeverRewrapsWhenOff(t *testing.T) {
	t.Setenv(crypto.KDFUpgradeEnv, "")
	db := openTestDB(t)
	password := "a-long-master-password"
	seedLegacyMasterKey(t, db, []byte(password))
	before := readRecord(t, db)

	if _, err := unlockOrSetupWithPassword(db, []byte(password)); err != nil {
		t.Fatal(err)
	}
	after := readRecord(t, db)
	if after.KDFAlgorithm != crypto.AlgoArgon2id || string(after.Salt) != string(before.Salt) || string(after.DEKCiphertext) != string(before.DEKCiphertext) {
		t.Fatal("off mode must leave the record as an older image wrote it")
	}
}

func TestWrongPasswordLeavesLegacyMasterKeyUntouched(t *testing.T) {
	t.Setenv(crypto.KDFUpgradeEnv, "true")
	db := openTestDB(t)
	seedLegacyMasterKey(t, db, []byte("a-long-master-password"))

	if _, err := unlockOrSetupWithPassword(db, []byte("a-wrong-master-password")); err == nil {
		t.Fatal("expected wrong password to fail")
	}
	if rec := readRecord(t, db); rec.KDFAlgorithm != crypto.AlgoArgon2id {
		t.Fatalf("a failed unlock must not re-wrap, got %q", rec.KDFAlgorithm)
	}
}

func TestNewMasterKeyAlgorithmFollowsTheMode(t *testing.T) {
	for mode, want := range map[string]string{"": crypto.AlgoArgon2id, "true": crypto.AlgoPBKDF2SHA256} {
		t.Setenv(crypto.KDFUpgradeEnv, mode)
		db := openTestDB(t)
		if _, err := unlockOrSetupWithPassword(db, []byte("a-long-master-password")); err != nil {
			t.Fatal(err)
		}
		if rec := readRecord(t, db); rec.KDFAlgorithm != want {
			t.Fatalf("upgrade=%q: new record uses %q, want %q", mode, rec.KDFAlgorithm, want)
		}
	}
}

func TestRewrapLosingTheRaceWritesNothing(t *testing.T) {
	t.Setenv(crypto.KDFUpgradeEnv, "true")
	db := openTestDB(t)
	password := []byte("a-long-master-password")
	seedLegacyMasterKey(t, db, password)
	stale := readRecord(t, db) // what this pod read before unlocking
	mk, err := auth.Unlock(password, buildVerificationRecord(stale))
	if err != nil {
		t.Fatal(err)
	}

	// `master-password change` on another pod lands first, with a new salt.
	changed := *stale
	changed.Salt = []byte("salt-from-the-change")
	if err := db.UpdateMasterKeyRecord(context.Background(), &changed); err != nil {
		t.Fatal(err)
	}

	rewrapLegacyMasterKey(db, mk, password, stale)

	if rec := readRecord(t, db); string(rec.Salt) != "salt-from-the-change" || rec.KDFAlgorithm != crypto.AlgoArgon2id {
		t.Fatalf("the stale re-wrap overwrote the newer record: %+v", rec)
	}
}

type failingUpgradeStore struct{ store.Store }

func (failingUpgradeStore) UpgradeMasterKeyRecord(context.Context, *store.MasterKeyRecord, *store.MasterKeyRecord) (bool, error) {
	return false, errors.New("database unavailable")
}

func TestUnlockSurvivesAFailedRewrap(t *testing.T) {
	t.Setenv(crypto.KDFUpgradeEnv, "true")
	db := openTestDB(t)
	password := "a-long-master-password"
	dek := seedLegacyMasterKey(t, db, []byte(password))

	mk, err := unlockOrSetupWithPassword(failingUpgradeStore{db}, []byte(password))
	if err != nil {
		t.Fatalf("a failed re-wrap must not fail the unlock: %v", err)
	}
	if string(mk.Key()) != string(dek) {
		t.Fatal("wrong DEK")
	}
	if rec := readRecord(t, db); rec.KDFAlgorithm != crypto.AlgoArgon2id {
		t.Fatal("a failed re-wrap must leave the record as it was")
	}
}

func TestUnlockUpgradesAMislabelledMasterKey(t *testing.T) {
	t.Setenv(crypto.KDFUpgradeEnv, "true")
	db := openTestDB(t)
	password := "a-long-master-password"
	dek := seedLegacyMasterKey(t, db, []byte(password))
	rec := readRecord(t, db)
	rec.KDFAlgorithm = crypto.AlgoPBKDF2SHA256 // an older image's password change leaves the label alone
	if err := db.UpdateMasterKeyRecord(context.Background(), rec); err != nil {
		t.Fatal(err)
	}

	mk, err := unlockOrSetupWithPassword(db, []byte(password))
	if err != nil || string(mk.Key()) != string(dek) {
		t.Fatalf("unlock of a mislabelled record: %v", err)
	}
	got := readRecord(t, db)
	if got.KDFAlgorithm != crypto.AlgoPBKDF2SHA256 || *got.KDFTime != 600000 || *got.KDFMemory != 0 || *got.KDFThreads != 0 {
		t.Fatalf("mislabelled record not re-wrapped as PBKDF2: %+v", got)
	}
}

// seedPBKDF2MasterKey stores a DEK wrapped under PBKDF2 at the given iteration count.
func seedPBKDF2MasterKey(t *testing.T, db store.Store, password []byte, iterations uint32) []byte {
	t.Helper()
	mk, sentinelRec, err := auth.SetupPasswordless()
	if err != nil {
		t.Fatal(err)
	}
	zero32, zero8 := uint32(0), uint8(0)
	p := crypto.KDFParams{Algorithm: crypto.AlgoPBKDF2SHA256, Time: iterations, KeyLen: 32, SaltLen: 16}
	salt, err := crypto.GenerateSalt(16)
	if err != nil {
		t.Fatal(err)
	}
	kek, err := crypto.DeriveKey(password, salt, p)
	if err != nil {
		t.Fatal(err)
	}
	dekCT, dekNonce, err := crypto.Encrypt(mk.Key(), kek)
	if err != nil {
		t.Fatal(err)
	}
	err = db.SetMasterKeyRecord(context.Background(), &store.MasterKeyRecord{
		Sentinel: sentinelRec.Sentinel, SentinelNonce: sentinelRec.SentinelNonce,
		DEKCiphertext: dekCT, DEKNonce: dekNonce, Salt: salt,
		KDFTime: &p.Time, KDFMemory: &zero32, KDFThreads: &zero8, KDFAlgorithm: p.Algorithm,
	})
	if err != nil {
		t.Fatal(err)
	}
	return append([]byte(nil), mk.Key()...)
}

func TestUnlockRewrapsAMasterKeyAtADifferentIterationCountOnlyWhenOn(t *testing.T) {
	password := "a-long-master-password"
	for _, tc := range []struct {
		name, upgrade string
		stored, want  uint32
	}{
		{"below, on", "true", 600_000, 700_000},
		{"above, on", "true", 800_000, 700_000},
		{"below, off", "", 600_000, 600_000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(crypto.KDFUpgradeEnv, tc.upgrade)
			t.Setenv(crypto.IterationsEnv, "700000")
			db := openTestDB(t)
			dek := seedPBKDF2MasterKey(t, db, []byte(password), tc.stored)
			mk, err := unlockOrSetupWithPassword(db, []byte(password))
			if err != nil || string(mk.Key()) != string(dek) {
				t.Fatalf("unlock: %v", err)
			}
			if got := readRecord(t, db); *got.KDFTime != tc.want {
				t.Fatalf("stored count %d, want %d", *got.KDFTime, tc.want)
			}
			again, err := unlockOrSetupWithPassword(db, []byte(password))
			if err != nil || string(again.Key()) != string(dek) {
				t.Fatalf("unlock after the re-wrap: %v", err)
			}
		})
	}
}
