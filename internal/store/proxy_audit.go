package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// ProxyAudit has no raw path, URL, headers, body, error string or token fields.
// Outcome unknown means no final outcome was durably recorded, including after a crash.
type ProxyAudit struct {
	RequestID   string
	VaultID     string
	ActorType   string
	ActorID     string
	WorkloadID  string
	Destination string
	Service     string
	MappingIDs  []string
	Method      string
	Decision    string
	Outcome     string
	Status      int
	StartedAt   time.Time
	FinishedAt  *time.Time
}

// auditWrite acknowledges only a committed, synchronously durable transaction: SQLite's pragma is
// connection-local, and PostgreSQL's SET LOCAL overrides a session configured for async commits.
func (s *SQLStore) auditWrite(ctx context.Context, write func(*sql.Tx) error) error {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	if s.dialect.Name() == "sqlite" {
		if _, err = conn.ExecContext(ctx, "PRAGMA synchronous=FULL"); err != nil {
			return err
		}
	}
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if s.dialect.Name() == "postgres" {
		if _, err = tx.ExecContext(ctx, "SET LOCAL synchronous_commit = on"); err != nil {
			return err
		}
	}
	if err = write(tx); err != nil {
		return err
	}
	return tx.Commit()
}

// InsertProxyAudit records the attempt as unknown; a restart never marks pending work successful or replays it.
func (s *SQLStore) InsertProxyAudit(ctx context.Context, r ProxyAudit) error {
	mappings := r.MappingIDs
	if mappings == nil {
		mappings = []string{}
	}
	encoded, err := json.Marshal(mappings)
	if err != nil {
		return err
	}
	return s.auditWrite(ctx, func(tx *sql.Tx) error {
		// Rebind translates placeholders in constant SQL; all request data stays bound.
		// #nosec G701
		_, err := tx.ExecContext(ctx, s.dialect.Rebind(`INSERT INTO credential_proxy_audit
   (request_id,vault_id,actor_type,actor_id,workload_id,destination,service,mapping_ids,method,decision,started_at)
   VALUES (?,?,?,?,?,?,?,?,?,?,?)`), r.RequestID, r.VaultID, r.ActorType, r.ActorID, r.WorkloadID, r.Destination, r.Service, string(encoded), r.Method, r.Decision, time.Now().UTC().Format(time.RFC3339Nano))
		return err
	})
}

// CompleteProxyAudit closes exactly one unknown attempt; a failed write leaves it queryable as unknown.
func (s *SQLStore) CompleteProxyAudit(ctx context.Context, id, outcome string, status int) error {
	if outcome != "completed" && outcome != "denied" && outcome != "upstream_error" {
		return errors.New("invalid audit outcome")
	}
	if status < 100 || status > 599 {
		return errors.New("invalid audit status")
	}
	return s.auditWrite(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, s.dialect.Rebind(`UPDATE credential_proxy_audit SET outcome=?,status=?,finished_at=? WHERE request_id=? AND outcome='unknown'`), outcome, status, time.Now().UTC().Format(time.RFC3339Nano), id)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n != 1 {
			return errors.New("audit attempt absent or already completed")
		}
		return nil
	})
}

// GetProxyAudit returns persisted state without inferring a result or triggering outbound action.
func (s *SQLStore) GetProxyAudit(ctx context.Context, id string) (ProxyAudit, error) {
	var r ProxyAudit
	var mappings, started string
	var finished sql.NullString
	err := s.db.QueryRowContext(ctx, s.dialect.Rebind(`SELECT request_id,vault_id,actor_type,actor_id,workload_id,destination,service,mapping_ids,method,decision,outcome,status,started_at,finished_at FROM credential_proxy_audit WHERE request_id=?`), id).Scan(&r.RequestID, &r.VaultID, &r.ActorType, &r.ActorID, &r.WorkloadID, &r.Destination, &r.Service, &mappings, &r.Method, &r.Decision, &r.Outcome, &r.Status, &started, &finished)
	if err != nil {
		return r, err
	}
	if err = json.Unmarshal([]byte(mappings), &r.MappingIDs); err != nil {
		return r, err
	}
	if r.StartedAt, err = time.Parse(time.RFC3339Nano, started); err != nil {
		return r, err
	}
	if finished.Valid {
		t, e := time.Parse(time.RFC3339Nano, finished.String)
		if e != nil {
			return r, e
		}
		r.FinishedAt = &t
	}
	return r, nil
}
