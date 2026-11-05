package store

import "gorm.io/gorm"

// Per replica: current audit boot and last signed checkpoint, so a deleted boot or truncated tail is detectable.
func init() {
	RegisterGORMMigration(func(db *gorm.DB) error {
		return db.Exec(`CREATE TABLE IF NOT EXISTS audit_chain_replica (
			replica TEXT PRIMARY KEY, boot BIGINT NOT NULL,
			checkpoint_seq BIGINT NOT NULL DEFAULT 0, checkpoint_mac TEXT NOT NULL DEFAULT ''
		)`).Error
	})
}
