package store

import (
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
)

// ErrSQLiteMovedToSharedStore refuses a SQLite start after the store was
// copied to the shared store: the copy renames the file to <name>.migrated,
// and opening the path again would create a new, empty store.
var ErrSQLiteMovedToSharedStore = errors.New("local store was moved to the shared store")

// StoreConfig carries the parameters for OpenStore.
// If DatabaseURL is non-empty it takes precedence over SQLitePath.
type StoreConfig struct {
	DatabaseURL string
	SQLitePath  string
	// ReloadDatabaseURL, when set, is called after PostgreSQL refuses a new
	// connection's login; a different URL it returns is used from then on,
	// so a rotated password needs no restart. Unused for SQLite.
	ReloadDatabaseURL func() (string, error)
}

// OpenStore opens a Store backed by either PostgreSQL or SQLite depending on
// the config. When DatabaseURL is set, it must use the postgres:// or
// postgresql:// scheme. When empty, SQLitePath (or the DefaultDBPath
// fallback) is used for a local SQLite file.
func OpenStore(cfg StoreConfig) (Store, error) {
	if cfg.DatabaseURL == "" {
		path := cfg.SQLitePath
		if path == "" {
			var err error
			path, err = DefaultDBPath()
			if err != nil {
				return nil, fmt.Errorf("resolving default db path: %w", err)
			}
		}
		// Before Open, which would create the file.
		switch _, err := os.Stat(path + ".migrated"); {
		case err == nil:
			return nil, fmt.Errorf("%w: %s.migrated exists, so this store was copied to the shared store; set DATABASE_URL or DATABASE_URL_FILE instead of starting on an empty local store", ErrSQLiteMovedToSharedStore, path)
		case !errors.Is(err, fs.ErrNotExist):
			return nil, fmt.Errorf("checking for %s.migrated: %w", path, err)
		}
		return Open(path)
	}

	u, err := url.Parse(cfg.DatabaseURL)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") {
		scheme := ""
		if u != nil {
			scheme = u.Scheme
		}
		return nil, fmt.Errorf("unrecognized DATABASE_URL scheme %q; supported: postgres://, postgresql://", scheme)
	}

	return openPostgresReloading(cfg.DatabaseURL, cfg.ReloadDatabaseURL)
}

// RedactURL returns a URL string with the password replaced by "***".
func RedactURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "***"
	}
	if _, has := u.User.Password(); has {
		u.User = url.UserPassword(u.User.Username(), "***")
	}
	return u.String()
}
