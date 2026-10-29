package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/hashicorp"
	"github.com/Infisical/agent-vault/internal/pgproxy"
	"github.com/Infisical/agent-vault/internal/store"
)

// NewDurableVaultLeaseMinter requires the SQL cleanup journal. Call Close after
// the PostgreSQL broker has stopped; a failed cleanup remains pending on disk.
// Owner IDs carry the replica name the audit chain uses, so operators can tell
// which broker holds a record.
func NewDurableVaultLeaseMinter(ctx context.Context, client *hashicorp.Client, st any) (*pgproxy.DurableLeaseMinter, error) {
	journal, ok := st.(pgproxy.CleanupJournal)
	if !ok {
		return nil, fmt.Errorf("PostgreSQL broker requires durable cleanup storage")
	}
	replica, err := brokercore.FleetReplicaName(os.Getenv)
	if err != nil {
		return nil, err
	}
	if !brokercore.ValidReplicaName(replica) {
		return nil, fmt.Errorf("broker replica name must be a DNS-style name (set AGENT_VAULT_REPLICA from the Pod name)")
	}
	opts := pgproxy.DurableLeaseOptions{Replica: replica, Logger: slog.Default()}
	if v := os.Getenv("AGENT_VAULT_DB_SHARED_ROLE_MAX_TTL"); v != "" {
		if opts.SharedRoleMaxTTL, err = parseSharedRoleMaxTTL(v); err != nil {
			return nil, err
		}
	}
	return pgproxy.NewDurableLeaseMinter(ctx, client, journal, opts)
}

// minSharedRoleMaxTTL keeps a short setting from closing a record while its shared-role credential may still be live.
const minSharedRoleMaxTTL = 24 * time.Hour

// parseSharedRoleMaxTTL accepts 0 (use the default) or a duration of at least minSharedRoleMaxTTL.
func parseSharedRoleMaxTTL(v string) (time.Duration, error) {
	d, err := time.ParseDuration(v)
	if err != nil || d < 0 || (d != 0 && d < minSharedRoleMaxTTL) {
		return 0, fmt.Errorf("AGENT_VAULT_DB_SHARED_ROLE_MAX_TTL must be a duration of at least %s, such as 168h, and no shorter than the role's max_ttl", minSharedRoleMaxTTL)
	}
	return d, nil
}

// brokerSessionStore is the store surface the fleet-wide session cap needs.
type brokerSessionStore interface {
	AddBrokerSession(ctx context.Context, owner, id, pod string, limit int) error
	RemoveBrokerSession(ctx context.Context, id string) error
}

// sessionLedger records live sessions under this replica's cleanup owner, so
// a dead replica's sessions stop counting when its owner row expires.
type sessionLedger struct {
	store brokerSessionStore
	owner func() string
}

// NewSessionLedger returns the fleet-wide per-Pod session ledger, or nil when
// the store cannot hold broker sessions (single-replica stores keep the
// in-memory cap only).
func NewSessionLedger(st any, minter *pgproxy.DurableLeaseMinter) pgproxy.SessionLedger {
	store, ok := st.(brokerSessionStore)
	if !ok || minter == nil {
		return nil
	}
	return sessionLedger{store: store, owner: minter.Owner}
}

func (l sessionLedger) Add(ctx context.Context, sessionID, workload string, limit int) error {
	err := l.store.AddBrokerSession(ctx, l.owner(), sessionID, workload, limit)
	if errors.Is(err, store.ErrPodSessionLimit) {
		return pgproxy.ErrSessionLimit
	}
	return err
}

func (l sessionLedger) Remove(ctx context.Context, sessionID string) error {
	return l.store.RemoveBrokerSession(ctx, sessionID)
}
