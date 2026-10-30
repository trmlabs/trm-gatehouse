package store

import "gorm.io/gorm"

// Adds the cloud-KMS wrap beside the password wrap; rows written before this are wrap kind "password".
func init() {
	RegisterGORMMigration(func(db *gorm.DB) error {
		blob := "BLOB"
		if db.Name() == "postgres" {
			blob = "BYTEA"
		}
		columns := []struct{ name, ddl string }{
			{"kms_wrapped_dek", blob},
			{"kms_key_name", "TEXT NOT NULL DEFAULT ''"},
			{"wrap_kind", "TEXT NOT NULL DEFAULT 'password'"},
		}
		for _, c := range columns {
			if db.Migrator().HasColumn("master_key", c.name) {
				continue
			}
			if err := db.Exec(`ALTER TABLE master_key ADD COLUMN ` + c.name + ` ` + c.ddl).Error; err != nil {
				return err
			}
		}
		return nil
	})
}
