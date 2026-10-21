//go:build realpg

package workloadidentity

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/store"
)

// Replicas each hold their own connection pool to one shared store.
func TestRealPostgres_ProvisionPoolsReplicas(t *testing.T) {
	dsn := os.Getenv("AV_TEST_STORE_PG_URL")
	if dsn == "" {
		t.Skip("set AV_TEST_STORE_PG_URL")
	}
	pool := fmt.Sprintf("replica-pool-%d", time.Now().UnixNano())
	replicas := make([]store.Store, 4)
	for i := range replicas {
		s, err := store.OpenStore(store.StoreConfig{DatabaseURL: dsn})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = s.Close() })
		replicas[i] = s
	}
	var wg sync.WaitGroup
	got := make([]Binding, len(replicas))
	errs := make([]error, len(replicas))
	for i, s := range replicas {
		wg.Go(func() {
			c, err := ProvisionPools(context.Background(), Config{Bindings: []Binding{unprovisioned(pool)}}, s, discard)
			got[i], errs[i] = c.Bindings[0], err
		})
	}
	wg.Wait()
	for i := range got {
		if errs[i] != nil || got[i].AgentID != got[0].AgentID || got[i].VaultID != got[0].VaultID {
			t.Fatalf("replica %d: %+v %v", i, got[i], errs[i])
		}
	}
	if !authorized(t, replicas[0], got[0]) {
		t.Fatal("the settled grant must admit")
	}
	assertOne(t, replicas[0], pool)
}
