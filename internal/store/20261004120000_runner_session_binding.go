package store

import "gorm.io/gorm"

// Pins a runner session token (by hash, never the token) to the first Pod that presented it, so a copied token is refused fleet-wide.
func init() {
	RegisterGORMMigration(func(db *gorm.DB) error {
		if err := db.Exec(`CREATE TABLE IF NOT EXISTS runner_session_binding (
			token TEXT PRIMARY KEY, pod TEXT NOT NULL, expires_ms BIGINT NOT NULL
		)`).Error; err != nil {
			return err
		}
		return db.Exec(`CREATE INDEX IF NOT EXISTS runner_session_binding_expires_idx ON runner_session_binding (expires_ms)`).Error
	})
}
