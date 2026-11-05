package store

import "gorm.io/gorm"

// Pre-migration records have no mount or role; the first request for their binding adopts the current ones.
// Quarantine now means only that Vault cannot revoke an orphan lease, so older marks are lifted.
func init() {
	RegisterGORMMigration(func(db *gorm.DB) error {
		for _, column := range []struct{ name, ddl string }{
			{"mount", `ALTER TABLE database_cleanup ADD COLUMN mount TEXT NOT NULL DEFAULT ''`},
			{"role", `ALTER TABLE database_cleanup ADD COLUMN role TEXT NOT NULL DEFAULT ''`},
			{"token_expires_ms", `ALTER TABLE database_cleanup ADD COLUMN token_expires_ms BIGINT NOT NULL DEFAULT 0`},
			{"token_revoked_ms", `ALTER TABLE database_cleanup ADD COLUMN token_revoked_ms BIGINT NOT NULL DEFAULT 0`},
		} {
			if db.Migrator().HasColumn("database_cleanup", column.name) {
				continue
			}
			if err := db.Exec(column.ddl).Error; err != nil {
				return err
			}
		}
		return db.Exec(`UPDATE database_cleanup SET quarantined = 0`).Error
	})
}
