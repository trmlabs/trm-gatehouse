package store

import (
	"context"
	"database/sql/driver"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
)

// rotationPoll is how often a refused login re-reads the URL file while it waits for the rotated URL.
var rotationPoll = time.Second

// reloadingConnector reads the store URL again when its file changes, and once more after a refused login, so a rotated password needs no restart.
type reloadingConnector struct {
	reload  func() (string, error) // nil: the URL never changes
	changed func() bool            // nil: no preflight; true means the URL file changed since the last call
	open    func(string) (driver.Connector, error)

	mu       sync.Mutex
	url      string
	inner    driver.Connector
	lastFail string           // the failure class last logged by swap, so a stuck file warns once
	prev     driver.Connector // the connector before a preflight swap, tried once if the new URL is refused
	prevURL  string

	holdMu  sync.Mutex
	wait    time.Duration // how long a refused login waits for the URL file to change; 0 fails at once
	hold    func(bool)    // nil: no pool to hold; true keeps open connections pooled while a rotated URL is awaited
	waiters int           // connections waiting in awaitRotation; the pool is held while any wait
}

func newReloadingConnector(databaseURL string, reload func() (string, error), changed func() bool) (*reloadingConnector, error) {
	inner, err := pgxConnector(databaseURL)
	if err != nil {
		return nil, err
	}
	return &reloadingConnector{reload: reload, changed: changed, open: pgxConnector, url: databaseURL, inner: inner}, nil
}

// pgxConnector never puts the URL in an error.
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
	if c.reload != nil && c.changed != nil && c.changed() {
		c.swap()
	}
	used, inner := c.current()
	conn, err := inner.Connect(ctx)
	if err == nil {
		c.settle(used)
		return conn, nil
	}
	if c.reload == nil || !loginRefused(err) {
		return conn, err
	}
	if oldURL, old := c.previous(); old != nil {
		if conn, oerr := old.Connect(ctx); oerr == nil {
			if c.revert(used, oldURL, old) {
				slog.Warn("store: PostgreSQL refused the re-read store URL; back on the previous URL until it is refused")
			}
			return conn, nil
		}
	}
	fresh, ok, _ := c.swapFrom(used, false)
	if !ok {
		if fresh, ok = c.awaitRotation(ctx, used); !ok {
			return nil, err
		}
	}
	slog.Warn("store: PostgreSQL refused the login; reconnecting with the store URL read again")
	return fresh.Connect(ctx)
}

// awaitRotation re-reads the URL file until it differs from the refused URL, the wait runs out or ctx ends; open connections stay pooled meanwhile.
func (c *reloadingConnector) awaitRotation(ctx context.Context, used string) (driver.Connector, bool) {
	wait, first := c.enterWait()
	defer c.leaveWait()
	if wait <= 0 {
		return nil, false
	}
	if first {
		slog.Warn("store: PostgreSQL refused the login and the store URL file has not changed yet; keeping open connections and waiting for it", "wait", wait.String())
	}
	deadline := time.NewTimer(wait)
	defer deadline.Stop()
	tick := time.NewTicker(rotationPoll)
	defer tick.Stop()
	reason := "unchanged"
	for {
		select {
		case <-ctx.Done():
			return nil, false
		case <-deadline.C:
			slog.Error("store: the store URL file gave no new usable URL within the wait after a refused login", "wait", wait.String(), "reason", reason)
			return nil, false
		case <-tick.C:
		}
		fresh, ok, fail := c.swapFrom(used, false)
		if ok {
			return fresh, true
		}
		if reason = fail; reason == "" {
			reason = "unchanged"
		}
	}
}

// setWait turns on the wait for a rotated URL once the store has started.
func (c *reloadingConnector) setWait(wait time.Duration, hold func(bool)) {
	c.holdMu.Lock()
	defer c.holdMu.Unlock()
	c.wait, c.hold = wait, hold
}

// enterWait returns the wait and holds the pool for the first waiter, reporting whether it did; a zero wait holds nothing.
func (c *reloadingConnector) enterWait() (time.Duration, bool) {
	c.holdMu.Lock()
	defer c.holdMu.Unlock()
	c.waiters++
	first := c.waiters == 1 && c.wait > 0
	if first && c.hold != nil {
		c.hold(true)
	}
	return c.wait, first
}

// leaveWait releases the pool when the last waiter leaves, whether it found the rotated URL, ran out of time or was cancelled.
func (c *reloadingConnector) leaveWait() {
	c.holdMu.Lock()
	defer c.holdMu.Unlock()
	c.waiters--
	if c.waiters == 0 && c.wait > 0 && c.hold != nil {
		c.hold(false)
	}
}

// swap moves new connections to the re-read URL, if it differs, keeping the old one as the fallback; open connections are left alone.
func (c *reloadingConnector) swap() {
	used, _ := c.current()
	_, _, fail := c.swapFrom(used, true)
	c.mu.Lock()
	repeat := fail == c.lastFail
	c.lastFail = fail
	c.mu.Unlock()
	if fail != "" && !repeat {
		slog.Warn("store: the store URL file changed but could not be used; keeping the current URL", "reason", fail)
	}
}

// swapFrom makes a re-read URL that differs from used current, keeping used as the fallback when asked; failure classes never carry the path or URL.
func (c *reloadingConnector) swapFrom(used string, fallback bool) (driver.Connector, bool, string) {
	next, err := c.reload()
	if err != nil {
		return nil, false, "unreadable"
	}
	if next == used {
		return nil, false, ""
	}
	fresh, err := c.open(next)
	if err != nil {
		return nil, false, "unusable"
	}
	c.mu.Lock()
	moved := c.url == used
	switch {
	case moved && fallback:
		c.prevURL, c.prev = used, c.inner
	case !fallback:
		c.prevURL, c.prev = "", nil // used was refused, so it is no fallback
	}
	if moved {
		c.url, c.inner = next, fresh
	}
	c.mu.Unlock()
	if moved && targetMoved(used, next) {
		slog.Warn("store: the re-read store URL names a different host or database")
	}
	return fresh, true, ""
}

// targetMoved reports whether two store URLs name a different host or database; it never returns either URL.
func targetMoved(a, b string) bool {
	ua, errA := url.Parse(a)
	ub, errB := url.Parse(b)
	if errA != nil || errB != nil || ua.Host == "" || ub.Host == "" {
		return false
	}
	return ua.Host != ub.Host || ua.Path != ub.Path
}

func (c *reloadingConnector) previous() (string, driver.Connector) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.prevURL, c.prev
}

// settle drops the previous URL once used logs in, unless a concurrent swap has already moved past used.
func (c *reloadingConnector) settle(used string) {
	c.mu.Lock()
	if c.url == used {
		c.prevURL, c.prev = "", nil
	}
	c.mu.Unlock()
}

// revert goes back to the previous URL while the swapped one is refused, so later connections skip the refused login.
func (c *reloadingConnector) revert(used, oldURL string, old driver.Connector) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.url != used {
		return false
	}
	c.url, c.inner, c.prevURL, c.prev = oldURL, old, "", nil
	return true
}

func (c *reloadingConnector) Driver() driver.Driver {
	_, inner := c.current()
	return inner.Driver()
}

// loginRefused is a server refusing the credentials, not an unreachable server.
func loginRefused(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && (pgErr.Code == "28P01" || pgErr.Code == "28000")
}
