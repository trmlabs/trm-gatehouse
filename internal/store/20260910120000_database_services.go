package store

import "gorm.io/gorm"

// New table on both dialects (absent from the Postgres baseline), so each branch is IF NOT EXISTS.
func init() {
	RegisterGORMMigration(func(db *gorm.DB) error {
		var ddl string
		if db.Name() == "postgres" {
			ddl = `CREATE TABLE IF NOT EXISTS database_services (
    id         TEXT PRIMARY KEY,
    vault_id   TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    upstream   TEXT NOT NULL,
    database   TEXT NOT NULL DEFAULT '',
    mount      TEXT NOT NULL,
    role       TEXT NOT NULL,
    sslmode    TEXT NOT NULL DEFAULT 'prefer' CHECK(sslmode IN ('disable','prefer','require','verify-full')),
    max_conns  INTEGER NOT NULL DEFAULT 0 CHECK(max_conns >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(vault_id, name)
)`
		} else {
			ddl = `CREATE TABLE IF NOT EXISTS database_services (
    id         TEXT PRIMARY KEY,
    vault_id   TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    upstream   TEXT NOT NULL,
    database   TEXT NOT NULL DEFAULT '',
    mount      TEXT NOT NULL,
    role       TEXT NOT NULL,
    sslmode    TEXT NOT NULL DEFAULT 'prefer' CHECK(sslmode IN ('disable','prefer','require','verify-full')),
    max_conns  INTEGER NOT NULL DEFAULT 0 CHECK(max_conns >= 0),
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(vault_id, name)
)`
		}
		return db.Exec(ddl).Error
	})
}
