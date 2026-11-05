package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"cloud.google.com/go/compute/metadata"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/Infisical/agent-vault/internal/httpcatalog"
	"github.com/Infisical/agent-vault/internal/mitm"
	"github.com/Infisical/agent-vault/internal/netguard"
)

const googleScope = "https://www.googleapis.com/auth/cloud-platform"

// googleTokens is the Google token minter for gcp entries; with no identity yet each mint is refused and retried.
func googleTokens(ctx context.Context, logger *slog.Logger) *httpcatalog.GCPTokens {
	root, err := google.DefaultTokenSource(ctx, googleScope)
	if err != nil {
		// DefaultTokenSource caches a "no" from an unreachable metadata server, so ask it directly.
		logger.Warn("default Google credentials not found; asking the metadata server for the broker's identity", slog.String("error", err.Error()))
		root = oauth2.ReuseTokenSourceWithExpiry(nil, metadataTokens{}, 225*time.Second)
	}
	return &httpcatalog.GCPTokens{Root: reportFailures(root, logger), Client: &http.Client{Timeout: 10 * time.Second,
		Transport: &http.Transport{DialContext: netguard.SafeDialContext(netguard.AllowPrivateFromEnv()), TLSHandshakeTimeout: 5 * time.Second}}}
}

// reportFailures logs the error, never a token, each time the identity cannot give one.
func reportFailures(src oauth2.TokenSource, logger *slog.Logger) oauth2.TokenSource {
	return failureLogger{src: src, logger: logger}
}

type failureLogger struct {
	src    oauth2.TokenSource
	logger *slog.Logger
}

func (f failureLogger) Token() (*oauth2.Token, error) {
	token, err := f.src.Token()
	if err != nil {
		f.logger.Error("the broker's Google identity gave no token; gcp entries answer 503 until it does", slog.String("error", err.Error()))
	}
	return token, err
}

// metadataTokens fetches the token on each call, so a server unreachable earlier recovers.
type metadataTokens struct{}

func (metadataTokens) Token() (*oauth2.Token, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	token, err := metadata.GetWithContext(ctx, "instance/service-accounts/default/token?scopes="+googleScope)
	if err != nil {
		return nil, err
	}
	var res struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal([]byte(token), &res); err != nil || res.AccessToken == "" || res.ExpiresIn == 0 {
		return nil, errors.New("metadata server returned no usable token")
	}
	return &oauth2.Token{AccessToken: res.AccessToken, TokenType: res.TokenType, Expiry: time.Now().Add(time.Duration(res.ExpiresIn) * time.Second)}, nil
}

// attachGoogleMinter builds the minter with the catalog's first gcp entry and drops it with the last;
// a broker with no Google identity still starts and answers 503 for gcp entries.
func attachGoogleMinter(adapter *mitm.HeaderAdapter, source *httpcatalog.Source, build func() *httpcatalog.GCPTokens) {
	minter := &httpcatalog.GCPMinter{Build: build}
	minter.Follow(source.Current())
	source.OnChange(minter.Follow)
	adapter.GCPTokens = minter
}
