package store

import "gorm.io/gorm"

// Legacy rows keep an empty actor and count against every actor, so per-actor admission fails closed.
func init() {
	RegisterGORMMigration(func(db *gorm.DB) error {
		if db.Migrator().HasColumn("database_cleanup", "actor_id") {
			return nil
		}
		return db.Exec(`ALTER TABLE database_cleanup ADD COLUMN actor_id TEXT NOT NULL DEFAULT ''`).Error
	})
}
