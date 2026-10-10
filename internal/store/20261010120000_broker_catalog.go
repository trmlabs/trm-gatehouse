package store

import "gorm.io/gorm"

// The last broker catalog version this store's brokers accepted, per catalog
// location, so a broker that restarts while Vault is unreachable starts from
// it instead of exiting.
func init() {
	RegisterGORMMigration(func(db *gorm.DB) error {
		return db.Exec(`CREATE TABLE IF NOT EXISTS broker_catalog (
			location TEXT PRIMARY KEY, version BIGINT NOT NULL, document TEXT NOT NULL
		)`).Error
	})
}
