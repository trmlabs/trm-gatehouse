package cmd

import (
	"bytes"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/crypto"
)

func TestCheckFIPSLogsTheModeAndRefusesWhenRequired(t *testing.T) {
	for _, tc := range []struct {
		require          string
		fips, kdfUpgrade bool
		wantErr          string
	}{
		{"", false, false, ""},
		{"false", false, false, ""},
		{"true", true, true, ""},
		{"true", false, true, "FIPS 140-3 mode is off"},
		{"true", true, false, crypto.KDFUpgradeEnv},
		{"true", false, false, "FIPS 140-3 mode is off"},
		{"yes", true, true, "must be true or false"},
		{"1 ", true, true, "must be true or false"},
	} {
		t.Setenv(envRequireFIPS, tc.require)
		var buf bytes.Buffer
		err := checkFIPS(slog.New(slog.NewTextHandler(&buf, nil)), tc.fips, tc.kdfUpgrade)
		if tc.wantErr == "" {
			if err != nil {
				t.Errorf("require=%q fips=%v upgrade=%v: %v", tc.require, tc.fips, tc.kdfUpgrade, err)
			}
		} else if err == nil || !strings.Contains(err.Error(), tc.wantErr) || !strings.Contains(err.Error(), envRequireFIPS) {
			t.Errorf("require=%q fips=%v upgrade=%v: want an error naming %s and %q, got %v", tc.require, tc.fips, tc.kdfUpgrade, envRequireFIPS, tc.wantErr, err)
		}
		if tc.wantErr != "must be true or false" && !strings.Contains(buf.String(), "FIPS 140-3 mode") {
			t.Errorf("require=%q: the FIPS mode was not logged: %q", tc.require, buf.String())
		}
		if tc.wantErr == "" && !strings.Contains(buf.String(), fmt.Sprintf("enabled=%v", tc.fips)) {
			t.Errorf("require=%q: the log should show enabled=%v: %q", tc.require, tc.fips, buf.String())
		}
	}
}
