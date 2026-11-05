package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

var ErrNoBrokerCatalog = errors.New("no stored broker catalog")

// SaveBrokerCatalog ignores a version below the stored one, so racing replica reloads never move the copy backwards.
// The document holds hosts, pools and key locations, never a key.
func (s *SQLStore) SaveBrokerCatalog(ctx context.Context, location string, version int, document []byte) error {
	if location == "" || version < 1 || len(document) == 0 {
		return fmt.Errorf("incomplete broker catalog")
	}
	_, err := s.db.ExecContext(ctx, s.dialect.Rebind(`INSERT INTO broker_catalog (location, version, document) VALUES (?, ?, ?)
		ON CONFLICT (location) DO UPDATE SET version = excluded.version, document = excluded.document
		WHERE broker_catalog.version <= excluded.version`), location, version, string(document))
	return err
}

func (s *SQLStore) LoadBrokerCatalog(ctx context.Context, location string) ([]byte, int, error) {
	var version int
	var document string
	err := s.db.QueryRowContext(ctx, s.dialect.Rebind(`SELECT version, document FROM broker_catalog WHERE location = ?`), location).Scan(&version, &document)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, 0, ErrNoBrokerCatalog
	}
	if err != nil {
		return nil, 0, err
	}
	return []byte(document), version, nil
}
