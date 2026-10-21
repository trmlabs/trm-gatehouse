package workloadidentity

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/store"
)

// PoolStore is the store access ProvisionPools needs.
type PoolStore interface {
	Store
	GetAgentByName(ctx context.Context, name string) (*store.Agent, error)
	CreateAgent(ctx context.Context, name, createdBy, role string) (*store.Agent, error)
	GetVault(ctx context.Context, name string) (*store.Vault, error)
	GetVaultSetting(ctx context.Context, vaultID, key string) (string, error)
	CreateVaultWithSetting(ctx context.Context, name, key, value string) (*store.Vault, error)
	GrantVaultRoleIfAbsent(ctx context.Context, actorID, actorType, vaultID, role string) (bool, error)
}

// PoolCreator marks what ProvisionPools creates: it is the agent's creator
// and the vault's provisionedBySetting. It is no user's ID and the settings
// API cannot write that key, so no member can forge the mark.
const PoolCreator = "workload-identity"

const provisionedBySetting = "provisioned_by"

// reservedPools are names a pool may not take: the vault every owner is
// granted, and a name the web interface routes.
var reservedPools = map[string]bool{"default": true, "users": true}

var errNotOurs = errors.New("one of that name exists that the broker did not create; to use it, name the binding's agentID and vaultID")

func needsProvisioning(b Binding) bool {
	return b.Pool != "" && b.Proxy == nil && b.AgentID == "" && b.VaultID == ""
}

// ProvisionPools gives each pool binding that names its pool but neither
// agentID nor vaultID the agent and the vault of that name, creating either
// when missing, and grants the agent proxy on the vault when it holds no role
// there. A deployment with no signed-in owner can then run its pools.
//
// It validates the whole policy as New does before writing anything. It
// adopts only an agent and a vault it created itself and refuses any other of
// the pool's name, so a binding never reaches a record someone else made. A
// member who creates an agent or vault named after a pool first therefore
// stops startup until an owner removes it: it fails closed. It is idempotent,
// and replicas starting together settle on one agent and one vault because
// both names are unique in the store. It never changes an existing role and
// never reactivates a revoked agent; a deleted grant returns at the next
// start, so withdraw a pool by removing its binding or revoking its agent.
// Each pool's store calls share one deadline of the policy's timeoutSeconds.
// Bindings that carry IDs are returned unchanged.
func ProvisionPools(ctx context.Context, c Config, s PoolStore, logger *slog.Logger) (Config, error) {
	standIn := c
	standIn.Bindings = append([]Binding(nil), c.Bindings...)
	for i := range standIn.Bindings {
		b := &standIn.Bindings[i]
		if !needsProvisioning(*b) {
			continue
		}
		if err := broker.ValidateSlug(b.Pool); err != nil {
			return c, fmt.Errorf("pool binding cannot name its agent and vault: %w", err)
		}
		if reservedPools[b.Pool] {
			return c, fmt.Errorf("pool binding cannot take the reserved name %q", b.Pool)
		}
		b.AgentID, b.VaultID = "pending", "pending"
	}
	r, err := New(standIn, s)
	if err != nil {
		return c, err
	}
	bindings := append([]Binding(nil), c.Bindings...)
	for i := range bindings {
		if !needsProvisioning(bindings[i]) {
			continue
		}
		pctx, cancel := context.WithTimeout(ctx, time.Duration(r.config.TimeoutSeconds)*time.Second)
		err := provision(pctx, &bindings[i], s, logger)
		cancel()
		if err != nil {
			return c, fmt.Errorf("pool %q %w", bindings[i].Pool, err)
		}
	}
	c.Bindings = bindings
	return c, nil
}

func provision(ctx context.Context, b *Binding, s PoolStore, logger *slog.Logger) error {
	agentOurs := func(a *store.Agent) (bool, error) { return a.CreatedBy == PoolCreator, nil }
	vaultOurs := func(v *store.Vault) (bool, error) {
		mark, err := s.GetVaultSetting(ctx, v.ID, provisionedBySetting)
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return mark == PoolCreator, err
	}
	// Both are read before either is made, so a refusal writes nothing. An
	// agent someone else made would bring its tokens to the pool's vault, and
	// proxy on a vault someone else made would reach their credentials.
	agent, err := lookup(ctx, b.Pool, s.GetAgentByName, agentOurs)
	if err != nil {
		return fmt.Errorf("agent: %w", err)
	}
	vault, err := lookup(ctx, b.Pool, s.GetVault, vaultOurs)
	if err != nil {
		return fmt.Errorf("vault: %w", err)
	}
	if agent == nil {
		if agent, err = create(ctx, b.Pool, func(ctx context.Context, name string) (*store.Agent, error) {
			return s.CreateAgent(ctx, name, PoolCreator, "no-access")
		}, s.GetAgentByName, agentOurs); err != nil {
			return fmt.Errorf("agent: %w", err)
		}
		logger.Info("workloadidentity: pool agent ready", slog.String("pool", b.Pool))
	}
	if vault == nil {
		if vault, err = create(ctx, b.Pool, func(ctx context.Context, name string) (*store.Vault, error) {
			return s.CreateVaultWithSetting(ctx, name, provisionedBySetting, PoolCreator)
		}, s.GetVault, vaultOurs); err != nil {
			return fmt.Errorf("vault: %w", err)
		}
		logger.Info("workloadidentity: pool vault ready", slog.String("pool", b.Pool))
	}
	granted, err := s.GrantVaultRoleIfAbsent(ctx, agent.ID, "agent", vault.ID, "proxy")
	if err != nil {
		return fmt.Errorf("grant: %w", err)
	}
	if granted {
		logger.Info("workloadidentity: granted pool agent proxy on its vault", slog.String("pool", b.Pool))
	}
	b.AgentID, b.VaultID = agent.ID, vault.ID
	return nil
}

// lookup returns the broker's record of that name, nil when there is none,
// and errNotOurs for one someone else made.
func lookup[T any](ctx context.Context, name string, get func(context.Context, string) (*T, error), ours func(*T) (bool, error)) (*T, error) {
	found, err := get(ctx, name)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if found == nil {
		return nil, errors.New("store returned no record")
	}
	if ok, err := ours(found); err != nil {
		return nil, err
	} else if !ok {
		return nil, errNotOurs
	}
	return found, nil
}

// create makes the record. A replica that loses the race fails on the unique
// name, and lookup then finds the winner's record.
func create[T any](ctx context.Context, name string, insert, get func(context.Context, string) (*T, error), ours func(*T) (bool, error)) (*T, error) {
	made, err := insert(ctx, name)
	if err == nil && made != nil {
		return made, nil
	}
	found, lookErr := lookup(ctx, name, get, ours)
	if lookErr != nil {
		return nil, lookErr
	}
	if found != nil {
		return found, nil
	}
	if err == nil {
		err = errors.New("store returned no record")
	}
	return nil, err
}
