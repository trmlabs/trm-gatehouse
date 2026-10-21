package workloadidentity

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/Infisical/agent-vault/internal/store"
	"github.com/Infisical/agent-vault/internal/store/storetest"
)

var discard = slog.New(slog.DiscardHandler)

func unprovisioned(pool string) Binding {
	return Binding{Namespace: "workers", ServiceAccount: pool, ServiceAccountUID: "account-uid", Pool: pool,
		OwnerUIDs: []string{"account-uid"}, ContainerName: "worker", MaxPodSeconds: 3600,
		ImageDigests: []string{"sha256:" + strings.Repeat("a", 64)}}
}

// provisioned runs ProvisionPools on one unprovisioned binding and checks the
// grant it leaves is one admission accepts.
func provisioned(t *testing.T, s PoolStore, pool string) Binding {
	t.Helper()
	c, err := ProvisionPools(context.Background(), Config{Bindings: []Binding{unprovisioned(pool)}}, s, discard)
	if err != nil {
		t.Fatal(err)
	}
	return c.Bindings[0]
}

func authorized(t *testing.T, s Store, b Binding) bool {
	t.Helper()
	ok, err := (&Resolver{config: Config{Bindings: []Binding{b}}, store: s}).BindingsAuthorized(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return ok
}

func TestProvisionPoolsCreatesOnceAndKeepsOtherBindings(t *testing.T) {
	ctx, s := context.Background(), storetest.Open(t)
	withIDs := unprovisioned("named-pool")
	withIDs.AgentID, withIDs.VaultID = "agent-id", "vault-id"
	oneID := unprovisioned("half-pool")
	oneID.AgentID = "agent-id"
	proxy := Binding{Namespace: "edge", ServiceAccount: "edge", ServiceAccountUID: "edge-uid", Proxy: &ProxyBinding{}}
	plain := Binding{Namespace: "work", ServiceAccount: "runner", ServiceAccountUID: "runner-uid"}
	in := Config{Bindings: []Binding{unprovisioned("example-pool"), withIDs, oneID, proxy, plain}}
	out, err := ProvisionPools(ctx, in, s, discard)
	if err != nil {
		t.Fatal(err)
	}
	if in.Bindings[0].AgentID != "" || !reflect.DeepEqual(out.Bindings[1:], in.Bindings[1:]) {
		t.Fatal("only the unprovisioned pool binding may change, and only in the returned copy")
	}
	b := out.Bindings[0]
	agent, err := s.GetAgentByName(ctx, "example-pool")
	if err != nil || agent.ID != b.AgentID || agent.CreatedBy != PoolAgentCreator || agent.Role != "no-access" || agent.Status != "active" {
		t.Fatalf("agent %+v %v", agent, err)
	}
	if vault, err := s.GetVault(ctx, "example-pool"); err != nil || vault.ID != b.VaultID {
		t.Fatalf("vault %+v %v", vault, err)
	}
	if role, err := s.GetVaultRole(ctx, b.AgentID, b.VaultID); err != nil || role != "proxy" || !authorized(t, s, b) {
		t.Fatalf("role %q %v", role, err)
	}
	if again := provisioned(t, s, "example-pool"); again.AgentID != b.AgentID || again.VaultID != b.VaultID {
		t.Fatal("a restart must reuse the pool's agent and vault")
	}
	assertOne(t, s, "example-pool")
}

func TestProvisionPoolsKeepsOperatorChanges(t *testing.T) {
	ctx, s := context.Background(), storetest.Open(t)
	b := provisioned(t, s, "example-pool")
	if err := s.GrantVaultRole(ctx, b.AgentID, "agent", b.VaultID, "member"); err != nil {
		t.Fatal(err)
	}
	provisioned(t, s, "example-pool")
	if role, _ := s.GetVaultRole(ctx, b.AgentID, b.VaultID); role != "member" {
		t.Fatalf("an existing role must stay, got %q", role)
	}
	if err := s.RevokeAgent(ctx, b.AgentID); err != nil {
		t.Fatal(err)
	}
	if again := provisioned(t, s, "example-pool"); again.AgentID != b.AgentID || authorized(t, s, again) {
		t.Fatal("a revoked agent must stay revoked and keep its pool refused")
	}
}

func TestProvisionPoolsRefusesWhatItCannotOwn(t *testing.T) {
	ctx, s := context.Background(), storetest.Open(t)
	if _, err := s.CreateAgent(ctx, "taken-pool", "user-id", "member"); err != nil {
		t.Fatal(err)
	}
	for pool, want := range map[string]string{"taken-pool": "did not create", "a.b": "lowercase letters", "ab": "at least 3"} {
		_, err := ProvisionPools(ctx, Config{Bindings: []Binding{unprovisioned(pool)}}, s, discard)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s: %v", pool, err)
		}
		if _, err := s.GetVault(ctx, pool); !errors.Is(err, sql.ErrNoRows) {
			t.Fatalf("%s: a refused pool must leave no vault: %v", pool, err)
		}
	}
}

// lostRace creates each record once before the caller's own create, as a
// replica that started first would.
type lostRace struct{ *store.SQLStore }

func (l lostRace) CreateVault(ctx context.Context, name string) (*store.Vault, error) {
	if _, err := l.SQLStore.CreateVault(ctx, name); err != nil {
		return nil, err
	}
	return l.SQLStore.CreateVault(ctx, name)
}

func (l lostRace) CreateAgent(ctx context.Context, name, createdBy, role string) (*store.Agent, error) {
	if _, err := l.SQLStore.CreateAgent(ctx, name, createdBy, role); err != nil {
		return nil, err
	}
	return l.SQLStore.CreateAgent(ctx, name, createdBy, role)
}

func TestProvisionPoolsSettlesReplicaRaces(t *testing.T) {
	s := storetest.Open(t)
	if b := provisioned(t, lostRace{s}, "lost-pool"); !authorized(t, s, b) {
		t.Fatal("a replica that loses both creates must use the winner's records")
	}
	assertOne(t, s, "lost-pool")

	var wg sync.WaitGroup
	got := make([]Binding, 8)
	errs := make([]error, len(got))
	for i := range got {
		wg.Go(func() {
			c, err := ProvisionPools(context.Background(), Config{Bindings: []Binding{unprovisioned("shared-pool")}}, s, discard)
			got[i], errs[i] = c.Bindings[0], err
		})
	}
	wg.Wait()
	for i := range got {
		if errs[i] != nil || got[i].AgentID != got[0].AgentID || got[i].VaultID != got[0].VaultID {
			t.Fatalf("replica %d: %+v %v", i, got[i], errs[i])
		}
	}
	assertOne(t, s, "shared-pool")
}

func assertOne(t *testing.T, s store.Store, name string) {
	t.Helper()
	vaults, err := s.ListVaults(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	agents, err := s.ListAllAgents(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, v := range vaults {
		if v.Name == name {
			count++
		}
	}
	for _, a := range agents {
		if a.Name == name {
			count++
		}
	}
	if count != 2 {
		t.Fatalf("want one vault and one agent named %q, found %d records", name, count)
	}
}
