package store

import (
	"context"
	"path/filepath"
	"testing"
)

func TestMigrateDataKeepsTheKDFLabels(t *testing.T) {
	ctx := context.Background()
	src, err := Open(filepath.Join(t.TempDir(), "source.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	if _, err := src.CreateUser(ctx, "p@test.com", []byte("h"), []byte("s"), "owner", 600000, 0, 0, "pbkdf2-sha256"); err != nil {
		t.Fatal(err)
	}
	if _, err := src.CreateUser(ctx, "a@test.com", []byte("h"), []byte("s"), "member", 3, 65536, 4, "argon2id"); err != nil {
		t.Fatal(err)
	}
	time, mem, threads := uint32(600000), uint32(0), uint8(0)
	if err := src.SetMasterKeyRecord(ctx, &MasterKeyRecord{
		Sentinel: []byte("s"), SentinelNonce: []byte("n"), DEKCiphertext: []byte("d"), DEKNonce: []byte("n"), Salt: []byte("salt"),
		KDFTime: &time, KDFMemory: &mem, KDFThreads: &threads, KDFAlgorithm: "pbkdf2-sha256",
	}); err != nil {
		t.Fatal(err)
	}

	dst, err := Open(filepath.Join(t.TempDir(), "dest.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer dst.Close()
	if err := MigrateData(ctx, src, dst, nil); err != nil {
		t.Fatal(err)
	}
	for email, want := range map[string]string{"p@test.com": "pbkdf2-sha256", "a@test.com": "argon2id"} {
		u, err := dst.GetUserByEmail(ctx, email)
		if err != nil {
			t.Fatal(err)
		}
		if u.KDFAlgorithm != want {
			t.Fatalf("%s: label %q, want %q", email, u.KDFAlgorithm, want)
		}
	}
	rec, err := dst.GetMasterKeyRecord(ctx)
	if err != nil || rec.KDFAlgorithm != "pbkdf2-sha256" || *rec.KDFTime != 600000 {
		t.Fatalf("master key record changed in migration: %+v %v", rec, err)
	}
}
