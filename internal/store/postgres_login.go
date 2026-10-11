package store

import (
	"context"
	"database/sql/driver"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"sync"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
)

// reloadingConnector opens PostgreSQL connections with the store URL and,
// when the server refuses a new connection's login, reads the URL again and
// retries once with it. A rotated password (a mounted Secret rewritten in
// place) then takes effect on the next connection, without a restart.
// Connections already open keep their session.
type reloadingConnector struct {
	reload func() (string, error) // nil: the URL never changes
	open   func(string) (driver.Connector, error)

	mu    sync.Mutex
	url   string
	inner driver.Connector
}

func newReloadingConnector(databaseURL string, reload func() (string, error)) (*reloadingConnector, error) {
	inner, err := pgxConnector(databaseURL)
	if err != nil {
		return nil, err
	}
	return &reloadingConnector{reload: reload, open: pgxConnector, url: databaseURL, inner: inner}, nil
}

// pgxConnector builds a connector for one PostgreSQL URL. The URL is never
// put in an error.
func pgxConnector(databaseURL string) (driver.Connector, error) {
	u, err := url.Parse(databaseURL)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") {
		return nil, fmt.Errorf("the store URL must use postgres:// or postgresql://")
	}
	cfg, err := pgx.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("the store URL does not parse")
	}
	return stdlib.GetConnector(*cfg), nil
}

func (c *reloadingConnector) current() (string, driver.Connector) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.url, c.inner
}

func (c *reloadingConnector) Connect(ctx context.Context) (driver.Conn, error) {
	used, inner := c.current()
	conn, err := inner.Connect(ctx)
	if err == nil || c.reload == nil || !loginRefused(err) {
		return conn, err
	}
	next, rerr := c.reload()
	if rerr != nil || next == used {
		return nil, err
	}
	fresh, oerr := c.open(next)
	if oerr != nil {
		return nil, err
	}
	c.mu.Lock()
	if c.url == used {
		c.url, c.inner = next, fresh
	}
	c.mu.Unlock()
	slog.Warn("store: PostgreSQL refused the login; reconnecting with the store URL read again")
	return fresh.Connect(ctx)
}

func (c *reloadingConnector) Driver() driver.Driver {
	_, inner := c.current()
	return inner.Driver()
}

// loginRefused is a server refusing the credentials (invalid_password,
// invalid_authorization_specification), not an unreachable server.
func loginRefused(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && (pgErr.Code == "28P01" || pgErr.Code == "28000")
}
