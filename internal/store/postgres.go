package store

import (
	"database/sql"
	"fmt"
	"math"
	"os"
	"strconv"
	"time"
)

func envInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}

func envDuration(key string, fallback time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return d
}

// poolHold returns a switch that, while on, neither retires nor trims open connections, and restores the pool settings when off.
func poolHold(db *sql.DB, maxOpen, maxIdle int, lifetime time.Duration) func(bool) {
	return func(on bool) {
		if !on {
			db.SetMaxIdleConns(maxIdle)
			db.SetConnMaxLifetime(lifetime)
			return
		}
		db.SetConnMaxLifetime(0)
		switch {
		case maxOpen <= 0:
			db.SetMaxIdleConns(math.MaxInt32) // an unlimited pool keeps every open connection
		case maxOpen > maxIdle:
			db.SetMaxIdleConns(maxOpen)
		}
	}
}

// openPostgresReloading: reload, when set, supplies the URL again after a refused login; changed, when set, says the URL file changed.
func openPostgresReloading(databaseURL string, reload func() (string, error), changed func() bool) (*SQLStore, error) {
	connector, err := newReloadingConnector(databaseURL, reload, changed)
	if err != nil {
		return nil, fmt.Errorf("opening postgres: %w", err)
	}
	db := sql.OpenDB(connector)

	maxOpen, maxIdle, lifetime := envInt("DB_MAX_OPEN_CONNS", 25), envInt("DB_MAX_IDLE_CONNS", 10), envDuration("DB_CONN_MAX_LIFETIME", 5*time.Minute)
	db.SetMaxOpenConns(maxOpen)
	db.SetMaxIdleConns(maxIdle)
	db.SetConnMaxLifetime(lifetime)

	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("pinging postgres: %w", err)
	}

	if err := runGORMMigrations(db, "postgres"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("running migrations: %w", err)
	}
	// Only after start, so a wrong password fails the start at once instead of waiting.
	connector.setWait(envDuration("DATABASE_URL_FILE_WAIT", 3*time.Minute), poolHold(db, maxOpen, maxIdle, lifetime))

	return &SQLStore{db: db, dialect: PostgresDialect{}}, nil
}
