//go:build realpg

package store

// openPostgres opens a test store whose URL never changes.
func openPostgres(databaseURL string) (*SQLStore, error) {
	return openPostgresReloading(databaseURL, nil)
}
