package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"golang.org/x/oauth2/google"

	"github.com/Infisical/agent-vault/internal/httpcatalog"
	"github.com/Infisical/agent-vault/internal/mitm"
	"github.com/Infisical/agent-vault/internal/netguard"
)

// googleTokens is the Google token minter for gcp catalog entries. The
// broker's own Workload Identity is the root; per-entry tokens are downscoped
// from it or minted for the entry's service account.
func googleTokens(ctx context.Context) (*httpcatalog.GCPTokens, error) {
	root, err := google.DefaultTokenSource(ctx, "https://www.googleapis.com/auth/cloud-platform")
	if err != nil {
		return nil, fmt.Errorf("gcp catalog entries need the broker's Google identity: %w", err)
	}
	return &httpcatalog.GCPTokens{Root: root, Client: &http.Client{Timeout: 10 * time.Second,
		Transport: &http.Transport{DialContext: netguard.SafeDialContext(netguard.AllowPrivateFromEnv()), TLSHandshakeTimeout: 5 * time.Second}}}, nil
}

// attachGoogleMinter gives the adapter a minter that follows the catalog: it
// is built when the catalog holds its first gcp entry and dropped with the
// last, with no restart. A broker with no Google identity still starts; its
// gcp entries answer 503 until the next catalog change finds one.
func attachGoogleMinter(adapter *mitm.HeaderAdapter, source *httpcatalog.Source, build func() (*httpcatalog.GCPTokens, error), logger *slog.Logger) {
	minter := &httpcatalog.GCPMinter{Build: build, Failed: func(err error) {
		logger.Error("Google token minter not built; gcp entries are refused until the next catalog change", slog.String("error", err.Error()))
	}}
	minter.Follow(source.Current())
	source.OnChange(minter.Follow)
	adapter.GCPTokens = minter
}
