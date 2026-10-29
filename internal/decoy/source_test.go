package decoy

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
)

// fakeVault serves a decoy layout under gatehouse/decoys from memory.
type fakeVault struct {
	mu          sync.Mutex
	head        map[string]interface{}
	headVersion int
	pools       map[string]map[string]interface{}
	deleted     map[string]bool
	failPool    string
	reads       atomic.Int64
}

func (v *fakeVault) ReadWithDataWithContext(_ context.Context, path string, _ map[string][]string) (*vaultapi.Secret, error) {
	v.reads.Add(1)
	v.mu.Lock()
	defer v.mu.Unlock()
	const base = "gatehouse/data/decoys/"
	name := strings.TrimPrefix(path, base+"pools/")
	switch {
	case path == base+"head":
		if v.head == nil {
			return nil, nil
		}
		return kv(v.head, v.headVersion), nil
	case name == v.failPool:
		return nil, errors.New("permission denied")
	case v.deleted[name]:
		return &vaultapi.Secret{Data: map[string]interface{}{"data": nil,
			"metadata": map[string]interface{}{"version": float64(3), "deletion_time": "2026-10-15T00:00:00Z", "destroyed": false}}}, nil
	case v.pools[name] != nil:
		return kv(v.pools[name], 1), nil
	}
	return nil, nil
}

func kv(data map[string]interface{}, version int) *vaultapi.Secret {
	return &vaultapi.Secret{Data: map[string]interface{}{"data": data, "metadata": map[string]interface{}{"version": float64(version)}}}
}

func newFakeVault() *fakeVault {
	return &fakeVault{
		head:        map[string]interface{}{"names": `["pool-a","pool-b"]`, "versions": `{"pool-a":1,"pool-b":1}`},
		headVersion: 1,
		pools: map[string]map[string]interface{}{
			"pool-a": {"github_token": decoyToken, "count": float64(3), "Bad-Field": "synthetic-decoy-ignored-0000000"},
			"pool-b": {"litellm_key": decoyKey},
		},
		deleted: map[string]bool{},
	}
}

func TestVaultLoaderLoadsEveryPoolAndPollsOnlyTheHead(t *testing.T) {
	v := newFakeVault()
	load := VaultLoader(v, "gatehouse", "decoys")
	s := NewSource(nil)
	// The two fields that are not decoys are reported by label, never value.
	rejected, err := s.Load(context.Background(), load, false)
	if err != nil || len(rejected) != 2 ||
		rejected[0] != (Rejected{Label: "pool-a/Bad-Field", Reason: "field name outside a-z, 0-9 and _"}) ||
		rejected[1] != (Rejected{Label: "pool-a/count", Reason: "value is not a string"}) {
		t.Fatalf("load: %v %+v", err, rejected)
	}
	set := s.Current()
	if set.Len() != 2 || s.Version() != 1 {
		t.Fatalf("set %d version %d", set.Len(), s.Version())
	}
	if m, ok := set.Password(decoyToken); !ok || m.Label != "pool-a/github_token" {
		t.Fatalf("pool-a decoy: %+v %v", m, ok)
	}
	if _, ok := set.Password("synthetic-decoy-ignored-0000000"); ok {
		t.Fatal("a field that is not a plain name was loaded")
	}
	// An unchanged head costs one read and keeps the set.
	before := v.reads.Load()
	if _, err := s.Load(context.Background(), load, false); err != nil || v.reads.Load() != before+1 || s.Current() != set {
		t.Fatalf("unchanged poll: reads %d, err %v", v.reads.Load()-before, err)
	}
	// A forced reload rereads every pool even at the same version.
	before = v.reads.Load()
	if _, err := s.Load(context.Background(), load, true); err != nil || v.reads.Load() != before+3 {
		t.Fatalf("forced reload: reads %d, err %v", v.reads.Load()-before, err)
	}
	// A new head version swaps in the new decoys; a deleted pool has none.
	v.mu.Lock()
	v.pools["pool-a"] = map[string]interface{}{"github_token": "synthetic-decoy-rotated-7c1d9e"}
	v.deleted["pool-b"] = true
	v.headVersion = 2
	v.mu.Unlock()
	if _, err := s.Load(context.Background(), load, false); err != nil || s.Version() != 2 || s.Current().Len() != 1 {
		t.Fatalf("rotation: %v version %d len %d", err, s.Version(), s.Current().Len())
	}
	if _, ok := s.Current().Password(decoyToken); ok {
		t.Fatal("a rotated decoy is still recognized")
	}
}

// Any read failure keeps the last good set in force.
func TestVaultLoaderFailureKeepsTheLastSet(t *testing.T) {
	v := newFakeVault()
	load := VaultLoader(v, "gatehouse", "decoys")
	s := NewSource(nil)
	if _, err := s.Load(context.Background(), load, false); err != nil {
		t.Fatal(err)
	}
	good := s.Current()
	for _, tc := range []struct {
		name   string
		change func()
	}{
		{"pool read fails", func() { v.failPool = "pool-b" }},
		{"head missing", func() { v.head = nil }},
		{"names not a list", func() { v.head = map[string]interface{}{"names": float64(1)} }},
		{"names not JSON", func() { v.head = map[string]interface{}{"names": "pool-a"} }},
		{"names repeat", func() { v.head = map[string]interface{}{"names": []interface{}{"pool-a", "pool-a"}} }},
		{"names hold a path", func() { v.head = map[string]interface{}{"names": []interface{}{"../catalog"}} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			restore := newFakeVault()
			v.mu.Lock()
			v.head, v.pools, v.deleted, v.failPool = restore.head, restore.pools, restore.deleted, ""
			v.headVersion++
			tc.change()
			v.mu.Unlock()
			if _, err := s.Load(context.Background(), load, false); err == nil || s.Current() != good {
				t.Fatalf("err %v; set replaced: %v", err, s.Current() != good)
			}
			if err := errorText(s, load); strings.Contains(err, decoyToken) || strings.Contains(err, decoyKey) {
				t.Fatalf("error carries a decoy: %s", err)
			}
		})
	}
	for _, tc := range []struct {
		vault         Logical
		mount, prefix string
	}{{v, "gatehouse", "../decoys"}, {v, "gatehouse", "decoys/."}, {v, "", "decoys"}, {nil, "gatehouse", "decoys"}} {
		before := v.reads.Load()
		if _, _, _, err := VaultLoader(tc.vault, tc.mount, tc.prefix)(context.Background(), 0); err == nil || !strings.Contains(err.Error(), "not configured") || v.reads.Load() != before {
			t.Fatalf("%q %q: %v", tc.mount, tc.prefix, err)
		}
	}
}

func errorText(s *Source, load Loader) string {
	_, err := s.Load(context.Background(), load, true)
	if err == nil {
		return ""
	}
	return err.Error()
}

// Watch picks up a new head version without a restart.
func TestWatchSwapsInNewVersions(t *testing.T) {
	v := newFakeVault()
	v.pools["pool-a"] = map[string]interface{}{"github_token": decoyToken} // nothing to report
	load := VaultLoader(v, "gatehouse", "decoys")
	s := NewSource(nil)
	if _, err := s.Load(context.Background(), load, false); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var reports atomic.Int64
	go s.Watch(ctx, 100*time.Millisecond, time.Hour, load, func([]Rejected, error) { reports.Add(1) })
	v.mu.Lock()
	v.pools["pool-b"] = map[string]interface{}{"litellm_key": decoyKey, "extra": "synthetic-decoy-added-5e2b8f71"}
	v.headVersion = 2
	v.mu.Unlock()
	deadline := time.Now().Add(5 * time.Second)
	for s.Version() != 2 {
		if time.Now().After(deadline) {
			t.Fatal("watch never loaded version 2")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if s.Current().Len() != 3 || reports.Load() != 0 {
		t.Fatalf("len %d reports %d", s.Current().Len(), reports.Load())
	}
}

// A nil Source is a broker with no decoys configured.
func TestNilSourceHoldsNoSet(t *testing.T) {
	var s *Source
	if s.Current() != nil {
		t.Fatal("nil source returned a set")
	}
}
