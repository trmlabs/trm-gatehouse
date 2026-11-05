//go:build realpg

package store

func openPostgres(databaseURL string) (*SQLStore, error) {
	return openPostgresReloading(databaseURL, nil, nil)
}
