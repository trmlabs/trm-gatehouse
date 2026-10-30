package store

import "gorm.io/gorm"

// Records the KDF algorithm beside its params; existing rows are Argon2id, backfilled here rather than by a column default.
func init() {
	RegisterGORMMigration(func(db *gorm.DB) error {
		for _, table := range []string{"users", "master_key"} {
			if db.Migrator().HasColumn(table, "kdf_algorithm") {
				continue
			}
			if err := db.Exec(`ALTER TABLE ` + table + ` ADD COLUMN kdf_algorithm TEXT`).Error; err != nil {
				return err
			}
		}
		if err := db.Exec(`UPDATE users SET kdf_algorithm = 'argon2id' WHERE kdf_algorithm IS NULL`).Error; err != nil {
			return err
		}
		return db.Exec(`UPDATE master_key SET kdf_algorithm = 'argon2id' WHERE kdf_algorithm IS NULL AND kdf_time IS NOT NULL`).Error
	})
}
