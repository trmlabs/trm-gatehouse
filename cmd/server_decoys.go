package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/Infisical/agent-vault/internal/decoy"
	"github.com/Infisical/agent-vault/internal/hashicorp"
)

var sharedDecoys struct {
	sync.Mutex
	source  *decoy.Source
	started bool
}

// A full reread on a slower cycle covers a head write that never landed.
const (
	decoyPollInterval = 30 * time.Second
	decoyFullReload   = 10 * time.Minute
)

// decoySource loads decoy credentials once per process for both brokers when AGENT_VAULT_DECOY_VAULT_PREFIX is set.
// A failed load is logged and the last good set stays in force; logs name a decoy by label, never value.
func decoySource(ctx context.Context, client *hashicorp.Client, getenv func(string) string, logger *slog.Logger) (*decoy.Source, error) {
	sharedDecoys.Lock()
	defer sharedDecoys.Unlock()
	if sharedDecoys.started {
		return sharedDecoys.source, nil
	}
	location := getenv("AGENT_VAULT_DECOY_VAULT_PREFIX")
	if location == "" {
		sharedDecoys.started = true
		return nil, nil
	}
	mount, prefix, ok := strings.Cut(location, "/")
	if !ok || mount == "" || prefix == "" || client == nil {
		return nil, fmt.Errorf("AGENT_VAULT_DECOY_VAULT_PREFIX needs mount/prefix and a Vault client")
	}
	load := decoy.VaultLoader(client.Logical(), mount, prefix)
	source := decoy.NewSource(nil)
	report := func(rejected []decoy.Rejected, err error) {
		if err != nil {
			logger.Error("decoy credentials unavailable; keeping the last set", slog.String("error", err.Error()))
		}
		for _, r := range rejected {
			logger.Error("decoy credential left out", slog.String("label", r.Label), slog.String("reason", r.Reason))
		}
	}
	loadCtx, cancel := context.WithTimeout(ctx, decoyPollInterval)
	rejected, err := source.Load(loadCtx, load, true)
	cancel()
	report(rejected, err)
	if err == nil {
		logger.Info("decoy credentials loaded", slog.Int("count", source.Current().Len()), slog.Int("version", source.Version()))
	}
	go source.Watch(ctx, decoyPollInterval, decoyFullReload, load, report)
	sharedDecoys.source, sharedDecoys.started = source, true
	return source, nil
}
