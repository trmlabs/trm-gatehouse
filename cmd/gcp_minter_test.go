package cmd

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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

// The broker's adapter gets a minter that follows the catalog: with no gcp
// entry at start it refuses, and a later catalog version with one builds the
// minter, which a failed build leaves unset until the next version.
func TestAttachGoogleMinterFollowsTheCatalog(t *testing.T) {
	loader := &gcpMinterLoader{}
	loader.set(gcpMinterHeaderDoc, 1)
	source, err := httpcatalog.Open(context.Background(), loader.load)
	if err != nil {
		t.Fatal(err)
	}
	var builds atomic.Int32
	var logs lockedBuffer
	adapter := &mitm.HeaderAdapter{}
	attachGoogleMinter(adapter, source, func() (*httpcatalog.GCPTokens, error) {
		if builds.Add(1) == 1 {
			return nil, errors.New("no identity")
		}
		return &httpcatalog.GCPTokens{}, nil
	}, slog.New(slog.NewTextHandler(&logs, nil)))
	if adapter.GCPTokens == nil || builds.Load() != 0 {
		t.Fatalf("started with no gcp entry: tokens %v, %d builds", adapter.GCPTokens, builds.Load())
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go source.Watch(ctx, 5*time.Millisecond, loader.load, func(int, error) {})
	publish := func(n int32, version int) {
		t.Helper()
		loader.set(gcpMinterGCPDoc, version)
		for deadline := time.Now().Add(2 * time.Second); builds.Load() != n; time.Sleep(5 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatalf("builds %d, want %d", builds.Load(), n)
			}
		}
	}
	publish(1, 2) // fails: logged, and the broker keeps serving
	if !strings.Contains(logs.String(), "Google token minter not built") || !strings.Contains(logs.String(), "no identity") {
		t.Fatalf("failed build not logged: %q", logs.String())
	}
	publish(2, 3) // the next version with a gcp entry builds it
}
