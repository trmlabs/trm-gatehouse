package store

import "gorm.io/gorm"

// Stored in the database so activity history outlives any one proxy replica.
func init() {
	RegisterGORMMigration(func(db *gorm.DB) error {
		if err := db.Exec(`CREATE TABLE IF NOT EXISTS proxy_activity (
			scope TEXT NOT NULL, owner_uid TEXT NOT NULL, namespace TEXT NOT NULL, last_seen_ms BIGINT NOT NULL,
			PRIMARY KEY (scope, owner_uid)
		)`).Error; err != nil {
			return err
		}
		return db.Exec(`CREATE INDEX IF NOT EXISTS proxy_activity_last_seen_idx ON proxy_activity (last_seen_ms)`).Error
	})
}
