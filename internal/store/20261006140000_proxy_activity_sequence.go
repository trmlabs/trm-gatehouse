package store

import "gorm.io/gorm"

// A gap or missing stream means the store lost writes (a restore) and the binding's history restarts.
// Only the replica advances its own stream; unused streams are pruned after the retention time.
func init() {
	RegisterGORMMigration(func(db *gorm.DB) error {
		if err := db.Exec(`CREATE TABLE IF NOT EXISTS proxy_activity_stream (
			scope TEXT NOT NULL, replica TEXT NOT NULL, seq BIGINT NOT NULL, used_ms BIGINT NOT NULL,
			PRIMARY KEY (scope, replica)
		)`).Error; err != nil {
			return err
		}
		return db.Exec(`CREATE INDEX IF NOT EXISTS proxy_activity_stream_used_idx ON proxy_activity_stream (used_ms)`).Error
	})
}
