package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// DatabaseCleanup stores only a revocation reference, never a token or password.
// Empty ActorID or WorkloadID is unattributed and counts against every actor or instance; TokenTTL is written as an expiry, not read back.
type DatabaseCleanup struct {
	Accessor, Binding, LeaseID, ActorID, WorkloadID string
	Mount, Role                                     string
	TokenTTL                                        time.Duration
	// Quarantined: Vault cannot revoke an orphan lease under the role. Read back, never written by Add.
	Quarantined bool
}

// ErrReplicaNameInUse: two processes under one replica name would share an audit chain and confuse cleanup ownership.
var ErrReplicaNameInUse = errors.New("another live broker process holds this replica name")

// replicaPattern is the LIKE pattern for the owner's replica, or "". Replica names are DNS-style, so hold no wildcards.
func replicaPattern(owner string) string {
	replica, _, ok := strings.Cut(owner, "/")
	if !ok || replica == "" {
		return ""
	}
	return replica + "/%"
}

func (s *SQLStore) replicaNameInUse(ctx context.Context, owner string) (bool, error) {
	pattern := replicaPattern(owner)
	if pattern == "" {
		return false, nil
	}
	var n int
	err := s.db.QueryRowContext(ctx, s.dialect.Rebind(`SELECT COUNT(*) FROM database_cleanup_replica
		WHERE owner LIKE ? AND owner <> ? AND expires_ms > `+s.dbNowMs()), pattern, owner).Scan(&n)
	return n > 0, err
}

// noOtherLiveReplicaOwner takes (pattern, owner) and holds while no other live owner row shares the replica name.
func (s *SQLStore) noOtherLiveReplicaOwner() string {
	return `NOT EXISTS (SELECT 1 FROM database_cleanup_replica other WHERE other.owner LIKE ? AND other.owner <> ? AND other.expires_ms > ` + s.dbNowMs() + `)`
}

// ErrDatabaseCleanupOwnershipLost: an expired owner can never renew, so its records belong to the survivors.
var ErrDatabaseCleanupOwnershipLost = errors.New("database cleanup ownership lost")

var ErrPodSessionLimit = errors.New("pod session limit reached")

func (s *SQLStore) databaseCleanupExec(ctx context.Context, query string, args ...any) (sql.Result, error) {
	var result sql.Result
	err := s.auditWrite(ctx, func(tx *sql.Tx) error {
		var err error
		result, err = tx.ExecContext(ctx, query, args...)
		return err
	})
	return result, err
}

// dbNowMs is the database clock in Unix milliseconds; owner expiry uses it so replica clocks never decide ownership.
func (s *SQLStore) dbNowMs() string {
	if s.dialect.Name() == "postgres" {
		return `CAST(EXTRACT(EPOCH FROM now()) * 1000 AS BIGINT)`
	}
	return `CAST((julianday('now') - 2440587.5) * 86400000 AS INTEGER)`
}

// liveOwner holds while the owner bound at its placeholder has an unexpired row.
func (s *SQLStore) liveOwner() string {
	return `EXISTS (SELECT 1 FROM database_cleanup_replica WHERE owner = ? AND expires_ms > ` + s.dbNowMs() + `)`
}

func affectedOne(result sql.Result, err error, lost error) error {
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return lost
	}
	return nil
}

// ClaimDatabaseCleanupOwner registers one broker process; each owner holds only the records it wrote or claimed.
func (s *SQLStore) ClaimDatabaseCleanupOwner(ctx context.Context, owner string, ttl time.Duration) error {
	if owner == "" || ttl <= 0 {
		return fmt.Errorf("invalid database cleanup owner")
	}
	// Owner IDs are replica/boot; a second live boot under one replica name is refused in the registering statement.
	pattern := replicaPattern(owner)
	var result sql.Result
	err := s.auditWrite(ctx, func(tx *sql.Tx) error {
		// Under READ COMMITTED two simultaneous boots could both pass the NOT EXISTS check;
		// the advisory lock makes check and insert one step.
		if pattern != "" && s.dialect.Name() == "postgres" {
			if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, "gatehouse-replica:"+pattern); err != nil {
				return err
			}
		}
		var err error
		result, err = tx.ExecContext(ctx, s.dialect.Rebind(`INSERT INTO database_cleanup_replica (owner, expires_ms)
		SELECT ?, `+s.dbNowMs()+` + ? WHERE NOT EXISTS (SELECT 1 FROM database_cleanup_replica WHERE owner = ?)
		AND (CAST(? AS TEXT) = '' OR `+s.noOtherLiveReplicaOwner()+`)`), owner, ttl.Milliseconds(), owner, pattern, pattern, owner)
		return err
	})
	if err = affectedOne(result, err, fmt.Errorf("database cleanup owner already registered")); err != nil {
		if inUse, checkErr := s.replicaNameInUse(ctx, owner); checkErr == nil && inUse {
			return ErrReplicaNameInUse
		}
	}
	return err
}

// RenewDatabaseCleanupOwner never revives an expired owner: a survivor may already have claimed its records.
func (s *SQLStore) RenewDatabaseCleanupOwner(ctx context.Context, owner string, ttl time.Duration) error {
	now := s.dbNowMs()
	pattern := replicaPattern(owner)
	result, err := s.databaseCleanupExec(ctx, s.dialect.Rebind(`UPDATE database_cleanup_replica SET expires_ms = `+now+` + ?
		WHERE owner = ? AND expires_ms > `+now+` AND (CAST(? AS TEXT) = '' OR `+s.noOtherLiveReplicaOwner()+`)`), ttl.Milliseconds(), owner, pattern, pattern, owner)
	if err = affectedOne(result, err, ErrDatabaseCleanupOwnershipLost); errors.Is(err, ErrDatabaseCleanupOwnershipLost) {
		// Both processes under a duplicated name stop renewing.
		if inUse, checkErr := s.replicaNameInUse(ctx, owner); checkErr == nil && inUse {
			return ErrReplicaNameInUse
		}
	}
	return err
}

// ReleaseDatabaseCleanupOwner makes the owner's records claimable by the next survivor heartbeat.
func (s *SQLStore) ReleaseDatabaseCleanupOwner(ctx context.Context, owner string) error {
	_, err := s.databaseCleanupExec(ctx, s.dialect.Rebind(`DELETE FROM database_cleanup_replica WHERE owner = ?`), owner)
	return err
}

func (s *SQLStore) CheckDatabaseCleanupOwner(ctx context.Context, owner string) error {
	var owned bool
	err := s.db.QueryRowContext(ctx, s.dialect.Rebind(`SELECT `+s.liveOwner()), owner).Scan(&owned)
	if err != nil {
		return err
	}
	if !owned {
		return ErrDatabaseCleanupOwnershipLost
	}
	return nil
}

func (s *SQLStore) LiveDatabaseCleanupOwners(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM database_cleanup_replica WHERE expires_ms > `+s.dbNowMs()).Scan(&n)
	return n, err
}

// ClaimOrphanedDatabaseCleanup moves each record only from the owner read in the same statement, so racing survivors claim nothing twice.
// It also drops session rows of dead owners and owner rows expired for a minute.
func (s *SQLStore) ClaimOrphanedDatabaseCleanup(ctx context.Context, owner string) (int, error) {
	now := s.dbNowMs()
	var claimed int64
	err := s.auditWrite(ctx, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, s.dialect.Rebind(`UPDATE database_cleanup SET owner = ?
			WHERE (accessor, owner) IN (SELECT accessor, owner FROM database_cleanup
				WHERE reconciliation_evidence = '' AND owner NOT IN (SELECT owner FROM database_cleanup_replica WHERE expires_ms > `+now+`))
			AND `+s.liveOwner()), owner, owner)
		if err != nil {
			return err
		}
		if claimed, err = result.RowsAffected(); err != nil {
			return err
		}
		// #nosec G202 -- now is a constant SQL clock expression, not input.
		if _, err = tx.ExecContext(ctx, `DELETE FROM broker_sessions WHERE owner NOT IN
			(SELECT owner FROM database_cleanup_replica WHERE expires_ms > `+now+`)`); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `DELETE FROM database_cleanup_replica WHERE expires_ms <= `+now+` - 60000`) // #nosec G202 -- constant clock expression
		return err
	})
	return int(claimed), err
}

func (s *SQLStore) AddDatabaseCleanup(ctx context.Context, owner string, record DatabaseCleanup) error {
	if record.Accessor == "" || record.Binding == "" {
		return fmt.Errorf("incomplete database cleanup record")
	}
	// The token predates this write, so database now plus its lifetime is no earlier than its real expiry.
	result, err := s.databaseCleanupExec(ctx, s.dialect.Rebind(`INSERT INTO database_cleanup (accessor, binding, actor_id, workload_id, owner, mount, role, token_expires_ms)
		SELECT ?, ?, ?, ?, ?, ?, ?, CASE WHEN CAST(? AS BIGINT) > 0 THEN `+s.dbNowMs()+` + CAST(? AS BIGINT) ELSE 0 END WHERE `+s.liveOwner()),
		record.Accessor, record.Binding, record.ActorID, record.WorkloadID, owner, record.Mount, record.Role,
		record.TokenTTL.Milliseconds(), record.TokenTTL.Milliseconds(), owner)
	return affectedOne(result, err, ErrDatabaseCleanupOwnershipLost)
}

// MarkDatabaseCleanupTokenRevoked is written after Vault confirmed the revocation, so the token was dead by then.
func (s *SQLStore) MarkDatabaseCleanupTokenRevoked(ctx context.Context, owner, accessor string) error {
	result, err := s.databaseCleanupExec(ctx, s.dialect.Rebind(`UPDATE database_cleanup SET token_revoked_ms = `+s.dbNowMs()+`
		WHERE accessor = ? AND owner = ? AND lease_id = '' AND reconciliation_evidence = '' AND `+s.liveOwner()), accessor, owner, owner)
	return affectedOne(result, err, ErrDatabaseCleanupOwnershipLost)
}

// AdoptDatabaseCleanup gives a record without a credential path the binding's current mount and role, and expiry now plus ttl.
// ttl must be the longest lifetime a child token could have had. It also lifts any quarantine mark an older build wrote.
func (s *SQLStore) AdoptDatabaseCleanup(ctx context.Context, owner, accessor, mount, role string, ttl time.Duration) error {
	if mount == "" || role == "" || ttl <= 0 {
		return fmt.Errorf("mount, role and token lifetime are required")
	}
	result, err := s.databaseCleanupExec(ctx, s.dialect.Rebind(`UPDATE database_cleanup SET mount = ?, role = ?, quarantined = 0, token_expires_ms = `+s.dbNowMs()+` + CAST(? AS BIGINT)
		WHERE accessor = ? AND owner = ? AND mount = '' AND lease_id = '' AND reconciliation_evidence = '' AND `+s.liveOwner()),
		mount, role, ttl.Milliseconds(), accessor, owner, owner)
	return affectedOne(result, err, ErrDatabaseCleanupOwnershipLost)
}

// SettledDatabaseCleanup returns this owner's unknown issuances whose child token has been dead for at least settle.
func (s *SQLStore) SettledDatabaseCleanup(ctx context.Context, owner string, settle time.Duration) ([]DatabaseCleanup, error) {
	return s.listDatabaseCleanup(ctx, s.dialect.Rebind(`SELECT `+databaseCleanupColumns+` FROM database_cleanup
		WHERE reconciliation_evidence = '' AND lease_id = '' AND owner = ? AND mount <> '' AND role <> '' AND token_expires_ms > 0
		AND (CASE WHEN token_revoked_ms > 0 AND token_revoked_ms < token_expires_ms THEN token_revoked_ms ELSE token_expires_ms END) + CAST(? AS BIGINT) <= `+s.dbNowMs()+`
		ORDER BY accessor`), owner, settle.Milliseconds())
}

func (s *SQLStore) ListDatabaseCleanup(ctx context.Context) ([]DatabaseCleanup, error) {
	return s.listDatabaseCleanup(ctx, `SELECT `+databaseCleanupColumns+` FROM database_cleanup WHERE reconciliation_evidence = '' ORDER BY accessor`)
}

const databaseCleanupColumns = `accessor, binding, lease_id, actor_id, workload_id, mount, role, quarantined`

func (s *SQLStore) ListOwnedDatabaseCleanup(ctx context.Context, owner string) ([]DatabaseCleanup, error) {
	return s.listDatabaseCleanup(ctx, s.dialect.Rebind(`SELECT `+databaseCleanupColumns+` FROM database_cleanup
		WHERE reconciliation_evidence = '' AND owner = ? ORDER BY accessor`), owner)
}

func (s *SQLStore) listDatabaseCleanup(ctx context.Context, query string, args ...any) ([]DatabaseCleanup, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var records []DatabaseCleanup
	for rows.Next() {
		var record DatabaseCleanup
		var quarantined int
		if err := rows.Scan(&record.Accessor, &record.Binding, &record.LeaseID, &record.ActorID, &record.WorkloadID, &record.Mount, &record.Role, &quarantined); err != nil {
			return nil, err
		}
		record.Quarantined = quarantined != 0
		records = append(records, record)
	}
	return records, rows.Err()
}

func (s *SQLStore) SetDatabaseCleanupLease(ctx context.Context, owner, accessor, leaseID string) error {
	if leaseID == "" {
		return fmt.Errorf("database lease ID is required")
	}
	result, err := s.databaseCleanupExec(ctx, s.dialect.Rebind(`UPDATE database_cleanup SET lease_id = ?
		WHERE accessor = ? AND owner = ? AND reconciliation_evidence = '' AND `+s.liveOwner()), leaseID, accessor, owner, owner)
	return affectedOne(result, err, fmt.Errorf("database cleanup ownership or record lost"))
}

// QuarantineDatabaseCleanup closes the binding fleet-wide until the record is confirmed or the mark is released.
func (s *SQLStore) QuarantineDatabaseCleanup(ctx context.Context, owner, accessor string) error {
	_, err := s.databaseCleanupExec(ctx, s.dialect.Rebind(`UPDATE database_cleanup SET quarantined = 1
		WHERE accessor = ? AND owner = ? AND lease_id = '' AND reconciliation_evidence = ''`), accessor, owner)
	return err
}

func (s *SQLStore) ReleaseDatabaseCleanupQuarantine(ctx context.Context, owner, accessor string) error {
	_, err := s.databaseCleanupExec(ctx, s.dialect.Rebind(`UPDATE database_cleanup SET quarantined = 0
		WHERE accessor = ? AND owner = ?`), accessor, owner)
	return err
}

func (s *SQLStore) DatabaseBindingQuarantined(ctx context.Context, binding string) (bool, error) {
	var quarantined bool
	err := s.db.QueryRowContext(ctx, s.dialect.Rebind(`SELECT EXISTS (SELECT 1 FROM database_cleanup
		WHERE binding = ? AND quarantined = 1 AND lease_id = '' AND reconciliation_evidence = '')`), binding).Scan(&quarantined)
	return quarantined, err
}

// ConfirmDatabaseCleanup records the resolving evidence (operator attestation or automated lease check); any live replica may record it.
func (s *SQLStore) ConfirmDatabaseCleanup(ctx context.Context, owner, accessor, evidence string) error {
	if strings.TrimSpace(accessor) == "" || strings.TrimSpace(evidence) == "" {
		return fmt.Errorf("accessor and database reconciliation evidence are required")
	}
	result, err := s.databaseCleanupExec(ctx, s.dialect.Rebind(`UPDATE database_cleanup SET reconciliation_evidence = ?
		WHERE accessor = ? AND lease_id = '' AND reconciliation_evidence = '' AND `+s.liveOwner()), evidence, accessor, owner)
	return affectedOne(result, err, fmt.Errorf("unknown-issuance record not found"))
}

func (s *SQLStore) DeleteDatabaseCleanup(ctx context.Context, accessor string) error {
	_, err := s.databaseCleanupExec(ctx, s.dialect.Rebind(`DELETE FROM database_cleanup WHERE accessor = ?`), accessor)
	return err
}

// AddBrokerSession records a session against its Pod for a fleet-wide cap (zero limit: no cap); database connections use a "database:" pod key.
// Rows count only while their owner is live.
func (s *SQLStore) AddBrokerSession(ctx context.Context, owner, id, pod string, limit int) error {
	if owner == "" || id == "" || pod == "" {
		return fmt.Errorf("incomplete broker session")
	}
	return s.auditWrite(ctx, func(tx *sql.Tx) error {
		if s.dialect.Name() == "postgres" {
			// Serialize admissions per Pod across replicas; SQLite already has one writer.
			if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 7956324892))`, pod); err != nil {
				return err
			}
		}
		if limit > 0 {
			n, err := s.countPodSessions(ctx, tx, pod)
			if err != nil {
				return err
			}
			if n >= limit {
				return ErrPodSessionLimit
			}
		}
		result, err := tx.ExecContext(ctx, s.dialect.Rebind(`INSERT INTO broker_sessions (id, owner, pod)
			SELECT ?, ?, ? WHERE `+s.liveOwner()), id, owner, pod, owner)
		return affectedOne(result, err, ErrDatabaseCleanupOwnershipLost)
	})
}

func (s *SQLStore) RemoveBrokerSession(ctx context.Context, id string) error {
	_, err := s.databaseCleanupExec(ctx, s.dialect.Rebind(`DELETE FROM broker_sessions WHERE id = ?`), id)
	return err
}

func (s *SQLStore) CountPodSessions(ctx context.Context, pod string) (int, error) {
	return s.countPodSessions(ctx, s.db, pod)
}

func (s *SQLStore) countPodSessions(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, pod string) (int, error) {
	var n int
	err := q.QueryRowContext(ctx, s.dialect.Rebind(`SELECT COUNT(*) FROM broker_sessions WHERE pod = ? AND owner IN
		(SELECT owner FROM database_cleanup_replica WHERE expires_ms > `+s.dbNowMs()+`)`), pod).Scan(&n)
	return n, err
}
