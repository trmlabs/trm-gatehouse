//go:build realpg

package store

import (
	"os"
	"testing"
)

func TestRealPostgres_KDFUpgradesAreConditional(t *testing.T) {
	dsn := os.Getenv("AV_TEST_STORE_PG_URL")
	if dsn == "" {
		t.Skip("set AV_TEST_STORE_PG_URL to a disposable PostgreSQL database")
	}
	s, err := openPostgres(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { s.Close() }()
	checkUpgradeUserPasswordHash(t, s)
	checkUpgradeMasterKeyRecord(t, s)
}

func TestRealPostgres_MasterKeyKMSColumnsAreConditional(t *testing.T) {
	dsn := os.Getenv("AV_TEST_STORE_PG_URL")
	if dsn == "" {
		t.Skip("set AV_TEST_STORE_PG_URL to a disposable PostgreSQL database")
	}
	s, err := openPostgres(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { s.Close() }()
	checkSetMasterKeyKMSWrap(t, s)
	checkSetMasterKeyWrapKind(t, s)
	checkClearMasterKeyPlaintext(t, s)
	checkRemoveMasterKeyPasswordWrap(t, s)
}
