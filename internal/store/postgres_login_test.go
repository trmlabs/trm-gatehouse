package store

import (
	"context"
	"database/sql/driver"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

type fakeConn struct{ driver.Conn }

func (fakeConn) Close() error { return nil }

// fakeConnector accepts only the URL "new"; any other login is refused, or
// fails with err when set.
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

// A refused login reads the store URL again and retries once with it; later
// connections use the new URL without reading again. Anything else, or the
// same URL again, returns the original error.
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

func TestPgxConnectorRefusesOtherSchemesWithoutEchoingTheURL(t *testing.T) {
	_, err := pgxConnector("mysql://user:synthetic-secret@db/x")
	if err == nil || strings.Contains(err.Error(), "synthetic-secret") {
		t.Fatalf("err %v", err)
	}
}
