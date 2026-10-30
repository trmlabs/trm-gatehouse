package store

import "gorm.io/gorm"

// cursor_subagent is shared by every broker replica so a registration made through one holds on all.
func init() {
	RegisterGORMMigration(func(db *gorm.DB) error {
		if err := db.Exec(`CREATE TABLE IF NOT EXISTS cursor_subagent (
			run TEXT PRIMARY KEY, parent TEXT NOT NULL, record TEXT NOT NULL, expires_ms BIGINT NOT NULL
		)`).Error; err != nil {
			return err
		}
		if err := db.Exec(`CREATE INDEX IF NOT EXISTS cursor_subagent_parent_idx ON cursor_subagent (parent)`).Error; err != nil {
			return err
		}
		return db.Exec(`CREATE INDEX IF NOT EXISTS cursor_subagent_expires_idx ON cursor_subagent (expires_ms)`).Error
	})
}
