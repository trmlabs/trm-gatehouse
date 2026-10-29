package cmd

import (
	"context"
	"log/slog"
	"testing"
)

func resetSharedDecoys() {
	sharedDecoys.Lock()
	sharedDecoys.source, sharedDecoys.started = nil, false
	sharedDecoys.Unlock()
}

// Without AGENT_VAULT_DECOY_VAULT_PREFIX there is no decoy source, and a
// location that is not mount/prefix, or one without a Vault client, fails
// startup instead of running with no decoys.
func TestDecoySourceSettings(t *testing.T) {
	resetSharedDecoys()
	t.Cleanup(resetSharedDecoys)
	logger := slog.New(slog.DiscardHandler)
	if src, err := decoySource(context.Background(), nil, func(string) string { return "" }, logger); err != nil || src != nil {
		t.Fatalf("unset: %v %v", src, err)
	}
	for _, location := range []string{"gatehouse", "gatehouse/", "/decoys", "gatehouse/decoys"} {
		resetSharedDecoys()
		getenv := func(key string) string {
			if key == "AGENT_VAULT_DECOY_VAULT_PREFIX" {
				return location
			}
			return ""
		}
		if _, err := decoySource(context.Background(), nil, getenv, logger); err == nil {
			t.Fatalf("%q without a Vault client accepted", location)
		}
	}
}

func TestWholeNumberFallsBackOnBadInput(t *testing.T) {
	for in, want := range map[string]int{"": 7, "x": 7, "0": 7, "-3": 7, "25": 25} {
		if got := wholeNumber(in, 7); got != want {
			t.Errorf("wholeNumber(%q) = %d, want %d", in, got, want)
		}
	}
}
