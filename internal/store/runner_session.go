package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// BindRunnerSession pins a token hash to the first Pod that presents it until the token expires, and returns that Pod.
// The same table pins a Cursor worker Pod ("cursor-pod:<uid>") to its first run owner.
func (s *SQLStore) BindRunnerSession(ctx context.Context, tokenSHA256, pod string, expires time.Time) (string, error) {
	if tokenSHA256 == "" || pod == "" {
		return "", fmt.Errorf("incomplete runner session binding")
	}
	now := s.dbNowMs()
	if _, err := s.db.ExecContext(ctx, `DELETE FROM runner_session_binding WHERE expires_ms <= `+now); err != nil { // #nosec G202 -- constant clock expression
		return "", err
	}
	// Two replicas may race on first use; the primary key keeps one pin.
	_, insertErr := s.db.ExecContext(ctx, s.dialect.Rebind(`INSERT INTO runner_session_binding (token, pod, expires_ms)
		SELECT ?, ?, ? WHERE NOT EXISTS (SELECT 1 FROM runner_session_binding WHERE token = ?)`), tokenSHA256, pod, expires.UnixMilli(), tokenSHA256)
	var bound string
	err := s.db.QueryRowContext(ctx, s.dialect.Rebind(`SELECT pod FROM runner_session_binding WHERE token = ?`), tokenSHA256).Scan(&bound)
	if errors.Is(err, sql.ErrNoRows) && insertErr != nil {
		return "", insertErr
	}
	return bound, err
}

// PodHasSession reports whether a Cursor worker Pod has a live pin to a run owner, which a verified run token sets on its first use.
func (s *SQLStore) PodHasSession(ctx context.Context, pod string) (bool, error) {
	if pod == "" {
		return false, fmt.Errorf("incomplete runner session lookup")
	}
	var one int
	err := s.db.QueryRowContext(ctx, s.dialect.Rebind(`SELECT 1 FROM runner_session_binding WHERE token = ? AND expires_ms > `+s.dbNowMs()), "cursor-pod:"+pod).Scan(&one) // #nosec G202 -- constant clock expression
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}
