//go:build realpg

package store

import (
	"fmt"
	"os"
	"testing"
	"time"
)

func TestRealPostgres_CreateVaultWithSettingAndGrantIfAbsent(t *testing.T) {
	dsn := os.Getenv("AV_TEST_STORE_PG_URL")
	if dsn == "" {
		t.Skip("set AV_TEST_STORE_PG_URL")
	}
	s, err := openPostgres(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	checkVaultSettingAndGrantIfAbsent(t, s, fmt.Sprintf("marked-%d", time.Now().UnixNano()))
}
