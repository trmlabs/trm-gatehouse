package workloadidentity

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/store"
)

// PoolStore is the store access ProvisionPools needs.
type PoolStore interface {
	GetVault(ctx context.Context, name string) (*store.Vault, error)
	CreateVault(ctx context.Context, name string) (*store.Vault, error)
	GetAgentByName(ctx context.Context, name string) (*store.Agent, error)
	CreateAgent(ctx context.Context, name, createdBy, role string) (*store.Agent, error)
	GetVaultRole(ctx context.Context, actorID, vaultID string) (string, error)
	GrantVaultRole(ctx context.Context, actorID, actorType, vaultID, role string) error
}

// PoolAgentCreator is recorded as the creator of an agent ProvisionPools
// makes. It is no user's ID, so no member owns the agent, and an agent of a
// pool's name is adopted only when it carries this mark.
const PoolAgentCreator = "workload-identity"

// ProvisionPools gives each pool binding that names its pool but neither
// agentID nor vaultID the agent and vault of that name, creating either when
// missing, and grants the agent proxy on the vault when it has no role there.
// A deployment with no signed-in owner can then run pools: the reviewed
// identity file already maps each account to its pool, so this adds no
// authority. It is idempotent, and replicas starting together settle on one
// agent and one vault because both names are unique in the store. It never
// changes an existing role and never reactivates a revoked agent; a deleted
// grant returns at the next start, so withdraw a pool by removing its binding
// or revoking its agent. Bindings that carry IDs are returned unchanged.
func ProvisionPools(ctx context.Context, c Config, s PoolStore, logger *slog.Logger) (Config, error) {
	bindings := append([]Binding(nil), c.Bindings...)
	for i := range bindings {
		b := &bindings[i]
		if b.Pool == "" || b.Proxy != nil || b.AgentID != "" || b.VaultID != "" {
			continue
		}
		if err := broker.ValidateSlug(b.Pool); err != nil {
			return c, fmt.Errorf("pool binding cannot name its agent and vault: %w", err)
		}
		agent, created, err := getOrCreate(ctx, b.Pool, s.GetAgentByName, func(ctx context.Context, name string) (*store.Agent, error) {
			return s.CreateAgent(ctx, name, PoolAgentCreator, "no-access")
		})
		if err != nil {
			return c, fmt.Errorf("pool %q agent: %w", b.Pool, err)
		}
		if agent.CreatedBy != PoolAgentCreator {
			// Its tokens would gain the pool's vault.
			return c, fmt.Errorf("pool %q: an agent of that name exists that the broker did not create; name its agentID and vaultID instead", b.Pool)
		}
		if created {
			logger.Info("workloadidentity: created pool agent", slog.String("pool", b.Pool))
		}
		vault, created, err := getOrCreate(ctx, b.Pool, s.GetVault, s.CreateVault)
		if err != nil {
			return c, fmt.Errorf("pool %q vault: %w", b.Pool, err)
		}
		if created {
			logger.Info("workloadidentity: created pool vault", slog.String("pool", b.Pool))
		}
		if _, err := s.GetVaultRole(ctx, agent.ID, vault.ID); errors.Is(err, sql.ErrNoRows) {
			// An upsert, so replicas granting together leave one row.
			if err := s.GrantVaultRole(ctx, agent.ID, "agent", vault.ID, "proxy"); err != nil {
				return c, fmt.Errorf("pool %q grant: %w", b.Pool, err)
			}
			logger.Info("workloadidentity: granted pool agent proxy on its vault", slog.String("pool", b.Pool))
		} else if err != nil {
			return c, fmt.Errorf("pool %q grant: %w", b.Pool, err)
		}
		b.AgentID, b.VaultID = agent.ID, vault.ID
	}
	c.Bindings = bindings
	return c, nil
}

// getOrCreate reads name, creating it when absent. A create that loses to
// another replica fails on the unique name, and the reread finds the winner.
func getOrCreate[T any](ctx context.Context, name string, get, create func(context.Context, string) (*T, error)) (*T, bool, error) {
	found, err := get(ctx, name)
	if err == nil && found != nil {
		return found, false, nil
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, false, err
	}
	made, err := create(ctx, name)
	if err == nil && made != nil {
		return made, true, nil
	}
	if found, getErr := get(ctx, name); getErr == nil && found != nil {
		return found, false, nil
	}
	if err == nil {
		err = errors.New("store returned no record")
	}
	return nil, false, err
}
