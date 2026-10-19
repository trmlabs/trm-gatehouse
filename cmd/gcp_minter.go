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

// googleTokens is the Google token minter for gcp catalog entries. The
// broker's own Workload Identity is the root; per-entry tokens are downscoped
// from it or minted for the entry's service account. It never fails: with no
// identity yet, each mint is refused and tries again.
func googleTokens(ctx context.Context, logger *slog.Logger) *httpcatalog.GCPTokens {
	root, err := google.DefaultTokenSource(ctx, googleScope)
	if err != nil {
		// DefaultTokenSource asks once per process whether this is Google
		// Cloud and keeps a "no", so a metadata server unreachable at that
		// moment would fail every later build. Ask it directly instead.
		logger.Warn("default Google credentials not found; asking the metadata server for the broker's identity", slog.String("error", err.Error()))
		root = oauth2.ReuseTokenSourceWithExpiry(nil, metadataTokens{}, 225*time.Second)
	}
	return &httpcatalog.GCPTokens{Root: reportFailures(root, logger), Client: &http.Client{Timeout: 10 * time.Second,
		Transport: &http.Transport{DialContext: netguard.SafeDialContext(netguard.AllowPrivateFromEnv()), TLSHandshakeTimeout: 5 * time.Second}}}
}

// reportFailures logs, with the error and never a token, each time the broker's
// identity cannot give one, since GCPTokens answers only "unavailable".
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

// metadataTokens fetches the broker's access token from the metadata server
// on each call, so one that was unreachable earlier works once it is.
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

// attachGoogleMinter gives the adapter a minter that follows the catalog: it
// is built when the catalog holds its first gcp entry and dropped with the
// last, with no restart. It cannot stop the broker from starting: a broker
// with no Google identity still serves every other entry, and its gcp entries
// answer 503 until the identity appears.
func attachGoogleMinter(adapter *mitm.HeaderAdapter, source *httpcatalog.Source, build func() *httpcatalog.GCPTokens) {
	minter := &httpcatalog.GCPMinter{Build: build}
	minter.Follow(source.Current())
	source.OnChange(minter.Follow)
	adapter.GCPTokens = minter
}
