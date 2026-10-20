package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/Infisical/agent-vault/internal/httpcatalog"
	"github.com/Infisical/agent-vault/internal/mitm"
)

const (
	gcpMinterHeaderDoc = `{"entries":[{"name":"serpapi","host":"serpapi.com","pathPrefixes":["/search"],"methods":["get"],"header":"x-api-key",
	  "placeholder":"__vault_SERPAPI_KEY__","key":{"mount":"gatehouse","path":"vendors/serpapi","field":"key"},"pools":["pool-a"]}]}`
	gcpMinterGCPDoc = `{"pools":[{"name":"claude","namespace":"n","serviceAccount":"claude","identity":"claude-session","ccpoolID":"ccpool_abc","ceiling":"T1"}],
	  "entries":[{"name":"bq-cases","kind":"gcp","host":"bigquery.googleapis.com","tier":"T1","requires":["22222222-2222-2222-2222-222222222222"],
	  "placeholder":"__vault_GCP__","pools":["claude"],"pathPrefixes":["/bigquery/v2/projects/example-analytics/"],
	  "gcp":{"serviceAccount":"bq-cases@example-analytics.iam.gserviceaccount.com"}}]}`
)

// lockedBuffer is a log sink the Watch goroutine writes and the test reads.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type gcpMinterLoader struct {
	doc     atomic.Value
	version atomic.Int32
}

func (l *gcpMinterLoader) set(doc string, version int) {
	l.doc.Store(doc)
	l.version.Store(int32(version))
}

func (l *gcpMinterLoader) load(context.Context) ([]byte, int, error) {
	return []byte(l.doc.Load().(string)), int(l.version.Load()), nil
}

type tokenSourceFunc func() (*oauth2.Token, error)

func (f tokenSourceFunc) Token() (*oauth2.Token, error) { return f() }

// fakeGoogle is a minter whose identity can be switched on, and an IAM
// Credentials that answers every impersonation with a token.
type fakeGoogle struct {
	identity atomic.Bool
	builds   atomic.Int32
	entry    httpcatalog.Entry
	srv      *httptest.Server
}

func newFakeGoogle(t *testing.T) *fakeGoogle {
	t.Helper()
	c, err := httpcatalog.Parse([]byte(gcpMinterGCPDoc))
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeGoogle{entry: c.Entries()[0]}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"accessToken": "impersonated", "expireTime": time.Now().Add(15 * time.Minute).UTC().Format(time.RFC3339)})
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeGoogle) build() *httpcatalog.GCPTokens {
	f.builds.Add(1)
	root := tokenSourceFunc(func() (*oauth2.Token, error) {
		if !f.identity.Load() {
			return nil, errors.New("no identity")
		}
		return &oauth2.Token{AccessToken: "root-token", Expiry: time.Now().Add(time.Hour)}, nil
	})
	return &httpcatalog.GCPTokens{Root: root, Client: f.srv.Client(), STSURL: f.srv.URL + "/v1/token", IAMCredentialsURL: f.srv.URL}
}

func (f *fakeGoogle) mint(adapter *mitm.HeaderAdapter) error {
	_, err := adapter.GCPTokens.Token(context.Background(), &f.entry)
	return err
}

// A broker that starts with no gcp entry mints once a later catalog version
// adds one, and lets the minter go when the last one is removed.
func TestAttachGoogleMinterFollowsTheCatalog(t *testing.T) {
	loader := &gcpMinterLoader{}
	loader.set(gcpMinterHeaderDoc, 1)
	source, err := httpcatalog.Open(context.Background(), loader.load)
	if err != nil {
		t.Fatal(err)
	}
	google := newFakeGoogle(t)
	google.identity.Store(true)
	adapter := &mitm.HeaderAdapter{}
	var applied atomic.Int32
	attachGoogleMinter(adapter, source, google.build)
	source.OnChange(func(httpcatalog.Catalog) { applied.Add(1) }) // runs after the minter's hook
	if err := google.mint(adapter); !errors.Is(err, httpcatalog.ErrGCPToken) || google.builds.Load() != 0 {
		t.Fatalf("no gcp entry: %v, %d builds", err, google.builds.Load())
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go source.Watch(ctx, 5*time.Millisecond, loader.load, func(int, error) {})
	published := int32(0)
	publish := func(doc string, version int) {
		t.Helper()
		published++
		loader.set(doc, version)
		for deadline := time.Now().Add(2 * time.Second); applied.Load() != published; time.Sleep(5 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatalf("version %d never applied", version)
			}
		}
	}
	publish(gcpMinterGCPDoc, 2)
	if err := google.mint(adapter); err != nil || google.builds.Load() != 1 {
		t.Fatalf("first gcp entry: %v, %d builds", err, google.builds.Load())
	}
	publish(gcpMinterHeaderDoc, 3)
	if err := google.mint(adapter); !errors.Is(err, httpcatalog.ErrGCPToken) {
		t.Fatalf("last gcp entry removed: %v", err)
	}
	publish(gcpMinterGCPDoc, 4)
	if err := google.mint(adapter); err != nil || google.builds.Load() != 2 {
		t.Fatalf("gcp entry again: %v, %d builds", err, google.builds.Load())
	}
}

// A broker that starts with a gcp entry and no Google identity still starts,
// and only that entry is refused. It mints as soon as the identity appears,
// with no restart and no catalog change.
func TestABrokerWithoutItsGoogleIdentityStillStarts(t *testing.T) {
	loader := &gcpMinterLoader{}
	loader.set(gcpMinterGCPDoc, 1)
	source, err := httpcatalog.Open(context.Background(), loader.load)
	if err != nil {
		t.Fatal(err)
	}
	google := newFakeGoogle(t)
	adapter := &mitm.HeaderAdapter{}
	attachGoogleMinter(adapter, source, google.build) // returns no error: nothing here can stop the start
	if adapter.GCPTokens == nil {
		t.Fatal("no minter attached")
	}
	if err := google.mint(adapter); !errors.Is(err, httpcatalog.ErrGCPToken) {
		t.Fatalf("no identity: %v", err)
	}
	google.identity.Store(true)
	if err := google.mint(adapter); err != nil {
		t.Fatalf("identity appeared: %v", err)
	}
	if google.builds.Load() != 1 {
		t.Fatalf("builds %d, want 1", google.builds.Load())
	}
}

// The identity's failures reach the log, without a token, since the minter
// itself answers only "unavailable".
func TestAFailedIdentityIsLoggedWithoutATokenValue(t *testing.T) {
	var logs lockedBuffer
	src := reportFailures(tokenSourceFunc(func() (*oauth2.Token, error) { return nil, errors.New("no identity") }), slog.New(slog.NewTextHandler(&logs, nil)))
	if _, err := src.Token(); err == nil || !strings.Contains(logs.String(), "no identity") {
		t.Fatalf("failure not logged: %v %q", err, logs.String())
	}
	good := reportFailures(tokenSourceFunc(func() (*oauth2.Token, error) { return &oauth2.Token{AccessToken: "synthetic-token"}, nil }), slog.New(slog.NewTextHandler(&logs, nil)))
	if _, err := good.Token(); err != nil || strings.Contains(logs.String(), "synthetic-token") {
		t.Fatalf("token handling: %v %q", err, logs.String())
	}
}

// The direct metadata source fails while the metadata server answers nothing
// usable and works as soon as it does, without a restart.
func TestMetadataTokensRecover(t *testing.T) {
	var up atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !up.Load() {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Metadata-Flavor") != "Google" || !strings.HasSuffix(r.URL.Path, "/instance/service-accounts/default/token") ||
			r.URL.Query().Get("scopes") != googleScope {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(`{"access_token":"synthetic-token","expires_in":3600,"token_type":"Bearer"}`))
	}))
	defer srv.Close()
	t.Setenv("GCE_METADATA_HOST", strings.TrimPrefix(srv.URL, "http://"))
	if _, err := (metadataTokens{}).Token(); err == nil {
		t.Fatal("token from a metadata server that has none")
	}
	up.Store(true)
	token, err := (metadataTokens{}).Token()
	if err != nil || token.AccessToken != "synthetic-token" || token.TokenType != "Bearer" || time.Until(token.Expiry) < 59*time.Minute {
		t.Fatalf("token %v: %v", token, err)
	}
}
