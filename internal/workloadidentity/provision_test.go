package workloadidentity

import (
	"context"
	"database/sql"
	"encoding/pem"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/store"
	"github.com/Infisical/agent-vault/internal/store/storetest"
)

var discard = slog.New(slog.DiscardHandler)

func poolBinding(pool string) Binding {
	return Binding{Namespace: "workers", ServiceAccount: pool, ServiceAccountUID: "account-uid", Pool: pool,
		OwnerUIDs: []string{"account-uid"}, ContainerName: "worker", MaxPodSeconds: 3600,
		ImageDigests: []string{"sha256:" + strings.Repeat("a", 64)}}
}

// poolConfig is a valid policy holding these bindings.
func poolConfig(t *testing.T, bindings ...Binding) Config {
	t.Helper()
	tls := httptest.NewTLSServer(http.NotFoundHandler())
	tls.Close()
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tls.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return Config{APIServer: "https://kubernetes.example.test", CAFile: ca, ReviewerTokenFile: filepath.Join(dir, "token"),
		Issuer: "https://issuer.example.test", Audience: "workers", Bindings: bindings}
}

// provisioned runs ProvisionPools on one pool binding without IDs.
func provisioned(t *testing.T, s PoolStore, pool string) Binding {
	t.Helper()
	c, err := ProvisionPools(context.Background(), poolConfig(t, poolBinding(pool)), s, discard)
	if err != nil {
		t.Fatal(err)
	}
	return c.Bindings[0]
}

// authorized applies the readiness check, which uses admission's store checks.
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
	withIDs := poolBinding("named-pool")
	withIDs.AgentID, withIDs.VaultID = "agent-id", "vault-id"
	plain := Binding{Namespace: "work", ServiceAccount: "runner", ServiceAccountUID: "runner-uid", AgentID: "agent-id", VaultID: "vault-id"}
	in := poolConfig(t, poolBinding("example-pool"), withIDs, plain)
	out, err := ProvisionPools(ctx, in, s, discard)
	if err != nil {
		t.Fatal(err)
	}
	if in.Bindings[0].AgentID != "" || !reflect.DeepEqual(out.Bindings[1:], in.Bindings[1:]) {
		t.Fatal("only the pool binding without IDs may change, and only in the returned copy")
	}
	b := out.Bindings[0]
	agent, err := s.GetAgentByName(ctx, "example-pool")
	if err != nil || agent.ID != b.AgentID || agent.CreatedBy != PoolCreator || agent.Role != "no-access" || agent.Status != "active" {
		t.Fatalf("agent %+v %v", agent, err)
	}
	vault, err := s.GetVault(ctx, "example-pool")
	if err != nil || vault.ID != b.VaultID {
		t.Fatalf("vault %+v %v", vault, err)
	}
	if mark, err := s.GetVaultSetting(ctx, vault.ID, provisionedBySetting); err != nil || mark != PoolCreator {
		t.Fatalf("vault mark %q %v", mark, err)
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

// With no race, each refusal names why and writes nothing: no agent, and no
// new grant.
func TestProvisionPoolsRefusesWhatItCannotOwn(t *testing.T) {
	ctx, s := context.Background(), storetest.Open(t)
	if _, err := s.CreateAgent(ctx, "taken-pool", "user-id", "member"); err != nil {
		t.Fatal(err)
	}
	// A vault a member made and administers.
	secrets, err := s.CreateVault(ctx, "team-secrets")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.GrantVaultRole(ctx, "user-id", "user", secrets.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	halfIDs := poolBinding("half-pool")
	halfIDs.AgentID = "agent-id"
	noImages := poolBinding("other-pool")
	noImages.ImageDigests = nil
	for name, tc := range map[string]struct {
		bindings []Binding
		want     string
	}{
		"agent made by a member": {[]Binding{poolBinding("taken-pool")}, "agent: one of that name exists that the broker did not create"},
		"vault made by a member": {[]Binding{poolBinding("team-secrets")}, "vault: one of that name exists that the broker did not create"},
		"default vault":          {[]Binding{poolBinding("default")}, "reserved name"},
		"web interface route":    {[]Binding{poolBinding("users")}, "reserved name"},
		"not an agent name":      {[]Binding{poolBinding("a.b")}, "lowercase letters"},
		"one ID only":            {[]Binding{poolBinding("good-pool"), halfIDs}, "requires namespace, account, account UID, agent and vault"},
		"invalid other binding":  {[]Binding{poolBinding("good-pool"), noImages}, "at least one image digest"},
	} {
		_, err := ProvisionPools(ctx, poolConfig(t, tc.bindings...), s, discard)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: %v", name, err)
		}
		for _, b := range tc.bindings {
			if a, err := s.GetAgentByName(ctx, b.Pool); b.Pool != "taken-pool" && !errors.Is(err, sql.ErrNoRows) {
				t.Fatalf("%s: a refusal must create no agent, found %+v %v", name, a, err)
			}
		}
	}
	for _, vault := range []string{"default", "team-secrets"} {
		v, err := s.GetVault(ctx, vault)
		if err != nil {
			t.Fatal(err)
		}
		if members, err := s.ListVaultMembersByType(ctx, v.ID, "agent"); err != nil || len(members) != 0 {
			t.Fatalf("%s gained agent members %+v %v", vault, members, err)
		}
	}
	// Ownership alone refuses the default vault, without the reserved name.
	b := poolBinding("default")
	if err := provision(ctx, &b, s, discard); !errors.Is(err, errNotOurs) {
		t.Fatalf("default vault: %v", err)
	}
}

// lostRace creates each record once before the caller's own create, as a
// replica that started first would.
type lostRace struct{ *store.SQLStore }

func (l lostRace) CreateVaultWithSetting(ctx context.Context, name, key, value string) (*store.Vault, error) {
	if _, err := l.SQLStore.CreateVaultWithSetting(ctx, name, key, value); err != nil {
		return nil, err
	}
	return l.SQLStore.CreateVaultWithSetting(ctx, name, key, value)
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

	config := poolConfig(t, poolBinding("shared-pool"))
	var wg sync.WaitGroup
	got := make([]Binding, 8)
	errs := make([]error, len(got))
	for i := range got {
		wg.Go(func() {
			c, err := ProvisionPools(context.Background(), config, s, discard)
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

// stalled never answers a lookup until its deadline.
type stalled struct{ *store.SQLStore }

func (stalled) GetAgentByName(ctx context.Context, _ string) (*store.Agent, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestProvisionPoolsStopsAtTheDeadline(t *testing.T) {
	config := poolConfig(t, poolBinding("example-pool"))
	config.TimeoutSeconds = 1
	start := time.Now()
	_, err := ProvisionPools(context.Background(), config, stalled{storetest.Open(t)}, discard)
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 10*time.Second {
		t.Fatalf("after %s: %v", time.Since(start), err)
	}
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
