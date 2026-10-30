package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// RegisterSubagent's first registration wins and an empty parent in the answer means parent is at its limit; racing for the last slot may refuse all, never exceed it.
func (s *SQLStore) RegisterSubagent(ctx context.Context, run, parent, record string, expires time.Time, limit int) (string, string, error) {
	if run == "" || parent == "" || record == "" || limit < 1 {
		return "", "", fmt.Errorf("incomplete subagent registration")
	}
	now := s.dbNowMs()
	if _, err := s.db.ExecContext(ctx, `DELETE FROM cursor_subagent WHERE expires_ms <= `+now); err != nil { // #nosec G202 -- constant clock expression
		return "", "", err
	}
	res, insertErr := s.db.ExecContext(ctx, s.dialect.Rebind(`INSERT INTO cursor_subagent (run, parent, record, expires_ms)
		SELECT ?, ?, ?, ? WHERE NOT EXISTS (SELECT 1 FROM cursor_subagent WHERE run = ?)
		AND (SELECT COUNT(*) FROM cursor_subagent WHERE parent = ?) < ?`), run, parent, record, expires.UnixMilli(), run, parent, limit)
	inserted := false
	if insertErr == nil {
		n, _ := res.RowsAffected()
		inserted = n == 1
	}
	if inserted {
		// Count again after writing: concurrent inserts each passed the check above.
		var held int
		countErr := s.db.QueryRowContext(ctx, s.dialect.Rebind(`SELECT COUNT(*) FROM cursor_subagent WHERE parent = ? AND expires_ms > `+now), parent).Scan(&held) // #nosec G202 -- constant clock expression
		if countErr != nil || held > limit {
			if _, err := s.db.ExecContext(ctx, s.dialect.Rebind(`DELETE FROM cursor_subagent WHERE run = ? AND parent = ?`), run, parent); err != nil {
				return "", "", err
			}
			if countErr != nil {
				return "", "", countErr
			}
			return "", "", nil
		}
	}
	gotParent, gotRecord, err := s.Subagent(ctx, run)
	if err == nil && gotParent == "" && insertErr != nil {
		return "", "", insertErr
	}
	return gotParent, gotRecord, err
}

// Subagent returns an unexpired registration's parent and record, or two empty strings.
func (s *SQLStore) Subagent(ctx context.Context, run string) (string, string, error) {
	var parent, record string
	err := s.db.QueryRowContext(ctx, s.dialect.Rebind(`SELECT parent, record FROM cursor_subagent WHERE run = ? AND expires_ms > `+s.dbNowMs()), run).Scan(&parent, &record) // #nosec G202 -- constant clock expression
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", nil
	}
	return parent, record, err
}
