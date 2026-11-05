package store

import "gorm.io/gorm"

// First report per binding, never pruned: the idle janitor deletes nothing until history covers the whole idle window.
func init() {
	RegisterGORMMigration(func(db *gorm.DB) error {
		return db.Exec(`CREATE TABLE IF NOT EXISTS proxy_activity_scope (
			scope TEXT PRIMARY KEY, history_started_ms BIGINT NOT NULL
		)`).Error
	})
}
