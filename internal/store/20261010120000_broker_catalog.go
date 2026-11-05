package store

import "gorm.io/gorm"

// Last accepted catalog version per location, so a broker restarting while Vault is unreachable can start from it.
func init() {
	RegisterGORMMigration(func(db *gorm.DB) error {
		return db.Exec(`CREATE TABLE IF NOT EXISTS broker_catalog (
			location TEXT PRIMARY KEY, version BIGINT NOT NULL, document TEXT NOT NULL
		)`).Error
	})
}
