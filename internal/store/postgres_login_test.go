package store

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

type fakeConn struct{ driver.Conn }

func (fakeConn) Close() error { return nil }

// fakeConnector accepts only the URL "new"; any other login is refused, or fails with err when set.
type fakeConnector struct {
	url string
	err error
}

func (f fakeConnector) Connect(context.Context) (driver.Conn, error) {
	switch {
	case f.err != nil:
		return nil, f.err
	case f.url != "new":
		return nil, &pgconn.PgError{Severity: "FATAL", Code: "28P01", Message: "password authentication failed"}
	}
	return fakeConn{}, nil
}

func (fakeConnector) Driver() driver.Driver { return nil }

// A refused login rereads the URL and retries once; the same URL again, or any other error, returns the original error.
func TestReloadingConnectorRereadsTheURLOnlyAfterARefusedLogin(t *testing.T) {
	file := "old"
	reads := 0
	c := &reloadingConnector{
		reload: func() (string, error) { reads++; return file, nil },
		open:   func(u string) (driver.Connector, error) { return fakeConnector{url: u}, nil },
		url:    "old", inner: fakeConnector{url: "old"},
	}
	if _, err := c.Connect(context.Background()); !loginRefused(err) || reads != 1 {
		t.Fatalf("unchanged file: err %v, reads %d", err, reads)
	}
	file = "new" // the Secret is rotated in place
	if _, err := c.Connect(context.Background()); err != nil || reads != 2 {
		t.Fatalf("rotated file: err %v, reads %d", err, reads)
	}
	if _, err := c.Connect(context.Background()); err != nil || reads != 2 {
		t.Fatalf("after the rotation: err %v, reads %d", err, reads)
	}

	unreachable := errors.New("connection refused")
	c = &reloadingConnector{
		reload: func() (string, error) { reads++; return "new", nil },
		open:   func(u string) (driver.Connector, error) { return fakeConnector{url: u}, nil },
		url:    "old", inner: fakeConnector{url: "old", err: unreachable},
	}
	reads = 0
	if _, err := c.Connect(context.Background()); !errors.Is(err, unreachable) || reads != 0 {
		t.Fatalf("an unreachable server read the URL again: err %v, reads %d", err, reads)
	}
	c = &reloadingConnector{open: func(u string) (driver.Connector, error) { return fakeConnector{url: u}, nil }, url: "old", inner: fakeConnector{url: "old"}}
	if _, err := c.Connect(context.Background()); !loginRefused(err) {
		t.Fatalf("an inline URL: %v", err)
	}
}

// A changed URL file moves new connections to the new URL before any login is refused; without a change the file is not read.
func TestReloadingConnectorSwapsOnAFileChangeBeforeARefusal(t *testing.T) {
	file, reads, dirty := "old", 0, false
	c := &reloadingConnector{
		reload:  func() (string, error) { reads++; return file, nil },
		changed: func() bool { d := dirty; dirty = false; return d },
		open:    func(u string) (driver.Connector, error) { return fakeConnector{url: u}, nil },
		url:     "old", inner: fakeConnector{url: "old"},
	}
	// The old URL is refused, so only the fallback reads; unchanged file means no preflight read.
	if _, err := c.Connect(context.Background()); !loginRefused(err) || reads != 1 {
		t.Fatalf("unchanged file: err %v, reads %d", err, reads)
	}
	file, dirty = "new", true
	reads = 0
	if _, err := c.Connect(context.Background()); err != nil || reads != 1 {
		t.Fatalf("changed file: err %v, reads %d", err, reads)
	}
	if _, err := c.Connect(context.Background()); err != nil || reads != 1 {
		t.Fatalf("after the swap: err %v, reads %d", err, reads)
	}
}

// A failed preflight re-read warns once per distinct failure, never names the path or URL, and the refusal fallback still recovers.
func TestReloadingConnectorWarnsOnceWhenThePreflightRereadFails(t *testing.T) {
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	var readErr error
	readErr = errors.New("open /secret/path/store-url: permission denied")
	c := &reloadingConnector{
		reload:  func() (string, error) { return "new", readErr },
		changed: func() bool { return true },
		open:    func(u string) (driver.Connector, error) { return fakeConnector{url: u}, nil },
		url:     "old", inner: fakeConnector{url: "old"},
	}
	for i := 0; i < 3; i++ {
		if _, err := c.Connect(context.Background()); !loginRefused(err) {
			t.Fatalf("connect %d: %v", i, err)
		}
	}
	out := logs.String()
	if n := strings.Count(out, "could not be used"); n != 1 {
		t.Fatalf("warnings %d, want 1: %s", n, out)
	}
	if strings.Contains(out, "/secret/path") || strings.Contains(out, "permission denied") {
		t.Fatalf("the warning carries the error text: %s", out)
	}

	readErr = nil // the file is fixed; the swap succeeds and the next failure would warn again
	if _, err := c.Connect(context.Background()); err != nil {
		t.Fatalf("after the file is fixed: %v", err)
	}
	if c.lastFail != "" {
		t.Fatalf("failure class not cleared: %q", c.lastFail)
	}
}

// liveSet accepts only the URLs in live; any other login is refused.
type liveSet struct {
	url  string
	live map[string]bool
}

func (l liveSet) Connect(context.Context) (driver.Conn, error) {
	if !l.live[l.url] {
		return nil, &pgconn.PgError{Severity: "FATAL", Code: "28P01", Message: "password authentication failed"}
	}
	return fakeConn{}, nil
}

func (liveSet) Driver() driver.Driver { return nil }

// countingSet is a liveSet that counts refused logins.
type countingSet struct {
	liveSet
	refused *int
}

func (c countingSet) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := c.liveSet.Connect(ctx)
	if err != nil {
		*c.refused++
	}
	return conn, err
}

// A swap to a login that is not live yet goes back to the previous URL with no further refusals, and moves on once that one is revoked.
func TestReloadingConnectorFallsBackToThePreviousURLWhenTheSwappedURLIsRefused(t *testing.T) {
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	live := map[string]bool{"old": true}
	dirty, refused := true, 0
	c := &reloadingConnector{
		reload:  func() (string, error) { return "new", nil },
		changed: func() bool { d := dirty; dirty = false; return d },
		open: func(u string) (driver.Connector, error) {
			return countingSet{liveSet{url: u, live: live}, &refused}, nil
		},
		url: "old", inner: countingSet{liveSet{url: "old", live: live}, &refused},
	}
	if _, err := c.Connect(context.Background()); err != nil {
		t.Fatalf("the previous URL was not tried: %v", err)
	}
	if c.url != "old" {
		t.Fatalf("still on the refused URL: %q", c.url)
	}
	for i := range 3 {
		if _, err := c.Connect(context.Background()); err != nil {
			t.Fatalf("connect %d before the new login is live: %v", i, err)
		}
	}
	if refused != 1 || strings.Count(logs.String(), "back on the previous URL") != 1 {
		t.Fatalf("refused logins %d, logs: %s", refused, logs.String())
	}
	live["new"], live["old"] = true, false // the new login goes live and the old one is revoked
	if _, err := c.Connect(context.Background()); err != nil {
		t.Fatalf("after the new login is live: %v", err)
	}
	if c.url != "new" {
		t.Fatalf("did not move to the new URL: %q", c.url)
	}
	if _, old := c.previous(); old != nil {
		t.Fatal("a previous connector was kept after the new URL worked")
	}
	live["new"] = false
	if _, err := c.Connect(context.Background()); !loginRefused(err) {
		t.Fatalf("a revoked login with no previous URL: %v", err)
	}
}

// swapDuring is a connector that runs a concurrent preflight swap while its own login is in flight, then logs in.
type swapDuring struct{ swap func() }

func (s swapDuring) Connect(context.Context) (driver.Conn, error) {
	s.swap()
	return fakeConn{}, nil
}

func (swapDuring) Driver() driver.Driver { return nil }

// A login on the old URL that finishes after a concurrent swap keeps the previous URL as the fallback for the swapped one.
func TestReloadingConnectorKeepsTheFallbackWhenAnOldLoginFinishesAfterASwap(t *testing.T) {
	live := map[string]bool{"old": true}
	c := &reloadingConnector{
		reload:  func() (string, error) { return "new", nil },
		changed: func() bool { return false },
		open:    func(u string) (driver.Connector, error) { return liveSet{url: u, live: live}, nil },
		url:     "old",
	}
	c.inner = swapDuring{swap: c.swap}
	if _, err := c.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, old := c.previous(); c.url != "new" || old == nil {
		t.Fatalf("after the swap: url %q, fallback kept %v", c.url, old != nil)
	}
	if _, err := c.Connect(context.Background()); err != nil {
		t.Fatalf("the refused swapped URL did not fall back: %v", err)
	}
}

// A file that changes to an unusable URL during the wait is named as the reason when the wait runs out, without the path or URL.
func TestReloadingConnectorNamesWhyTheWaitFailed(t *testing.T) {
	fastRotationPoll(t)
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	c := &reloadingConnector{
		reload: func() (string, error) { return "mysql://synthetic-secret@db/x", nil },
		open: func(u string) (driver.Connector, error) {
			if u != "old" {
				return nil, errors.New("unusable")
			}
			return fakeConnector{url: u}, nil
		},
		url: "old", inner: fakeConnector{url: "old"},
		wait: 20 * time.Millisecond,
	}
	if _, err := c.Connect(context.Background()); !loginRefused(err) {
		t.Fatalf("err %v", err)
	}
	out := logs.String()
	if !strings.Contains(out, "reason=unusable") || strings.Contains(out, "synthetic-secret") {
		t.Fatalf("logs: %s", out)
	}
}

// lockedFile is a URL file another goroutine rotates while a login waits on it.
type lockedFile struct {
	mu    sync.Mutex
	url   string
	reads int
}

func (f *lockedFile) set(url string) {
	f.mu.Lock()
	f.url = url
	f.mu.Unlock()
}

func (f *lockedFile) read() (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reads++
	return f.url, nil
}

func fastRotationPoll(t *testing.T) {
	prev := rotationPoll
	rotationPoll = time.Millisecond
	t.Cleanup(func() { rotationPoll = prev })
}

// A refused login while the file still holds the revoked URL waits for the file, holding the pool, and releases it once the rotated URL logs in.
func TestReloadingConnectorWaitsForALaggingFileWhileHoldingThePool(t *testing.T) {
	fastRotationPoll(t)
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	file := &lockedFile{url: "old"}
	var holds []bool
	c := &reloadingConnector{
		reload: file.read,
		open:   func(u string) (driver.Connector, error) { return fakeConnector{url: u}, nil },
		url:    "old", inner: fakeConnector{url: "old"},
		wait: time.Minute,
		hold: func(on bool) { holds = append(holds, on) },
	}
	go func() {
		for {
			file.mu.Lock()
			n := file.reads
			file.mu.Unlock()
			if n >= 5 {
				file.set("new")
				return
			}
			time.Sleep(time.Millisecond)
		}
	}()
	if _, err := c.Connect(context.Background()); err != nil {
		t.Fatalf("the login did not wait for the rotated URL: %v", err)
	}
	if len(holds) != 2 || !holds[0] || holds[1] {
		t.Fatalf("pool holds %v, want [true false]", holds)
	}
	if c.url != "new" {
		t.Fatalf("current URL %q, want the rotated one", c.url)
	}
	if out := logs.String(); strings.Count(out, "keeping open connections") != 1 {
		t.Fatalf("logs: %s", out)
	}
}

// The wait is bounded and ends with the caller, and every way out releases the pool; a zero wait fails at once without holding.
func TestReloadingConnectorStopsWaitingAtTheBoundOrWithTheCaller(t *testing.T) {
	fastRotationPoll(t)
	file := &lockedFile{url: "old"}
	var holds []bool
	c := &reloadingConnector{
		reload: file.read,
		open:   func(u string) (driver.Connector, error) { return fakeConnector{url: u}, nil },
		url:    "old", inner: fakeConnector{url: "old"},
		wait: 20 * time.Millisecond,
		hold: func(on bool) { holds = append(holds, on) },
	}
	if _, err := c.Connect(context.Background()); !loginRefused(err) {
		t.Fatalf("after the wait ran out: %v", err)
	}
	if file.reads < 2 {
		t.Fatalf("the file was read %d times while waiting", file.reads)
	}
	if len(holds) != 2 || !holds[0] || holds[1] {
		t.Fatalf("pool holds %v after the wait ran out, want [true false]", holds)
	}

	c.wait = time.Hour
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(10*time.Millisecond, cancel)
	start := time.Now()
	if _, err := c.Connect(ctx); !loginRefused(err) || time.Since(start) > 10*time.Second {
		t.Fatalf("a cancelled caller: err %v after %v", err, time.Since(start))
	}
	if len(holds) != 4 || !holds[2] || holds[3] {
		t.Fatalf("pool holds %v after the caller left, want [true false true false]", holds)
	}
	file.set("new")
	if _, err := c.Connect(context.Background()); err != nil || len(holds) != 4 {
		t.Fatalf("after the file caught up: err %v, holds %v", err, holds)
	}

	file.set("old")
	c.url, c.inner, c.wait, holds = "old", fakeConnector{url: "old"}, 0, nil
	if _, err := c.Connect(context.Background()); err == nil || len(holds) != 0 {
		t.Fatalf("a zero wait: err %v, holds %v", err, holds)
	}
}

// While held, the pool neither trims idle connections nor retires old ones; releasing restores both settings.
func TestPoolHoldKeepsOpenConnectionsUntilReleased(t *testing.T) {
	ctx := context.Background()
	db := sql.OpenDB(fakeConnector{url: "new"})
	defer db.Close()
	db.SetMaxOpenConns(5)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(time.Millisecond)
	hold := poolHold(db, 5, 1, time.Millisecond)

	hold(true)
	var conns []*sql.Conn
	for range 3 {
		conn, err := db.Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, conn)
	}
	for _, conn := range conns {
		_ = conn.Close()
	}
	time.Sleep(5 * time.Millisecond)
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if st := db.Stats(); st.OpenConnections != 3 || st.MaxIdleClosed != 0 || st.MaxLifetimeClosed != 0 {
		t.Fatalf("held pool: open %d, idle closed %d, lifetime closed %d", st.OpenConnections, st.MaxIdleClosed, st.MaxLifetimeClosed)
	}

	hold(false)
	time.Sleep(5 * time.Millisecond)
	conn, err = db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if st := db.Stats(); st.MaxIdleClosed != 2 || st.MaxLifetimeClosed == 0 {
		t.Fatalf("released pool: idle closed %d, lifetime closed %d", st.MaxIdleClosed, st.MaxLifetimeClosed)
	}
}

// An unlimited pool keeps every open connection while held.
func TestPoolHoldKeepsAnUnlimitedPool(t *testing.T) {
	ctx := context.Background()
	db := sql.OpenDB(fakeConnector{url: "new"})
	defer db.Close()
	db.SetMaxOpenConns(0)
	db.SetMaxIdleConns(1)
	hold := poolHold(db, 0, 1, time.Hour)

	hold(true)
	var conns []*sql.Conn
	for range 3 {
		conn, err := db.Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, conn)
	}
	for _, conn := range conns {
		_ = conn.Close()
	}
	if st := db.Stats(); st.Idle != 3 || st.MaxIdleClosed != 0 {
		t.Fatalf("held unlimited pool: idle %d, idle closed %d", st.Idle, st.MaxIdleClosed)
	}
	hold(false)
	if st := db.Stats(); st.Idle != 1 || st.MaxIdleClosed != 2 {
		t.Fatalf("released unlimited pool: idle %d, idle closed %d", st.Idle, st.MaxIdleClosed)
	}
}

// rotatedDB accepts only the URL it holds as live, and is safe for concurrent logins.
type rotatedDB struct {
	mu   sync.Mutex
	live string
}

func (r *rotatedDB) connector(url string) driver.Connector { return rotatedLogin{r, url} }

type rotatedLogin struct {
	store *rotatedDB
	url   string
}

func (l rotatedLogin) Connect(context.Context) (driver.Conn, error) {
	l.store.mu.Lock()
	defer l.store.mu.Unlock()
	if l.url != l.store.live {
		return nil, &pgconn.PgError{Severity: "FATAL", Code: "28P01", Message: "password authentication failed"}
	}
	return fakeConn{}, nil
}

func (rotatedLogin) Driver() driver.Driver { return nil }

// Many logins across a rotation with a lagging file all connect once it catches up, and the pool ends released.
func TestReloadingConnectorConcurrentLoginsAcrossARotation(t *testing.T) {
	fastRotationPoll(t)
	db := &rotatedDB{live: "new"} // the database has rotated; the file has not
	file := &lockedFile{url: "old"}
	var dirty sync.Mutex
	changed := false
	var holdMu sync.Mutex
	var holds []bool
	c := &reloadingConnector{
		reload: file.read,
		changed: func() bool {
			dirty.Lock()
			defer dirty.Unlock()
			d := changed
			changed = false
			return d
		},
		open: func(u string) (driver.Connector, error) { return db.connector(u), nil },
		url:  "old", inner: db.connector("old"),
		wait: time.Minute,
		hold: func(on bool) { holdMu.Lock(); holds = append(holds, on); holdMu.Unlock() },
	}
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for i := range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if i == 10 {
				file.set("new")
				dirty.Lock()
				changed = true
				dirty.Unlock()
			}
			_, err := c.Connect(context.Background())
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("a login across the rotation failed: %v", err)
		}
	}
	holdMu.Lock()
	defer holdMu.Unlock()
	if len(holds) > 0 && holds[len(holds)-1] {
		t.Fatalf("pool left held: %v", holds)
	}
	if c.url != "new" || c.waiters != 0 {
		t.Fatalf("url %q, waiters %d", c.url, c.waiters)
	}
}

// A swap to a different host or database is logged without either URL; a password change alone is not.
func TestReloadingConnectorLogsASwapToAnotherTarget(t *testing.T) {
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	oldURL := "postgres://u:first-synthetic@db-a:5432/store"
	file := oldURL
	c := &reloadingConnector{
		reload:  func() (string, error) { return file, nil },
		changed: func() bool { return true },
		open:    func(u string) (driver.Connector, error) { return fakeConnector{url: u}, nil },
		url:     oldURL, inner: fakeConnector{url: oldURL},
	}
	file = "postgres://u:second-synthetic@db-a:5432/store"
	c.swap()
	if strings.Contains(logs.String(), "different host") {
		t.Fatalf("a password change was logged as a new target: %s", logs.String())
	}
	file = "postgres://u:third-synthetic@db-b:5432/store"
	c.swap()
	out := logs.String()
	if strings.Count(out, "different host or database") != 1 || strings.Contains(out, "synthetic") || strings.Contains(out, "db-b") {
		t.Fatalf("logs: %s", out)
	}
}

func TestPgxConnectorRefusesOtherSchemesWithoutEchoingTheURL(t *testing.T) {
	_, err := pgxConnector("mysql://user:synthetic-secret@db/x")
	if err == nil || strings.Contains(err.Error(), "synthetic-secret") {
		t.Fatalf("err %v", err)
	}
}
