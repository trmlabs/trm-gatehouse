//go:build realpg

package pgproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"
)

// The read-only default holds in every transaction, even where the login holds
// a write grant and a function changed the setting earlier in the session.
func TestRealPostgres_ReadOnlyLoginSurvivesSettingWrapper(t *testing.T) {
	dsn := os.Getenv("AV_TEST_PG_POOL_ADMIN")
	if dsn == "" {
		t.Skip("set AV_TEST_PG_POOL_ADMIN")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(context.Background())
	u, _ := url.Parse(dsn)
	role, pw := "rw_"+randomHex(4), randomHex(16)
	table, unlock, write := "wr_items_"+randomHex(4), "wr_unlock_"+randomHex(4), "wr_write_"+randomHex(4)
	for _, sql := range []string{
		fmt.Sprintf("CREATE ROLE %s LOGIN PASSWORD '%s'", role, pw),
		fmt.Sprintf("CREATE TABLE %s (id int)", table),
		fmt.Sprintf("INSERT INTO %s VALUES (1), (2)", table),
		fmt.Sprintf("GRANT SELECT, INSERT ON %s TO %s", table, role),
		fmt.Sprintf("CREATE FUNCTION %s() RETURNS text LANGUAGE sql AS $$ SELECT set_config('default_transaction_read_only', 'off', false) $$", unlock),
		fmt.Sprintf("CREATE FUNCTION %s() RETURNS void LANGUAGE sql AS $$ INSERT INTO %s VALUES (99) $$", write, table),
	} {
		if _, err := admin.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = admin.Exec(c, fmt.Sprintf("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = '%s'", role))
		_, _ = admin.Exec(c, fmt.Sprintf("DROP FUNCTION IF EXISTS %s(), %s()", unlock, write))
		_, _ = admin.Exec(c, "DROP TABLE IF EXISTS "+table)
		_, _ = admin.Exec(c, "DROP ROLE IF EXISTS "+role)
	})
	rows := func() int {
		var n int
		if err := admin.QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	broker := func(pool *PoolOptions) string {
		lease := &Lease{ID: "lease-" + randomHex(4), Username: role, Password: pw, ExpiresAt: time.Now().Add(time.Hour)}
		_, addr := startBroker(t, Options{
			Auth:      &fakeAuth{scope: &AgentScope{VaultID: "vault-1", ActorID: "agent-uuid-1", WorkloadID: "pod-1", Pool: "cursor"}},
			Databases: &fakeResolver{svc: &DatabaseService{Name: "app", Addr: u.Host, Database: u.Path[1:], Mount: "database", Role: "staging.us.example.app-readonly", SSLMode: "disable", ReadOnly: true}},
			Leases:    &fakeMinter{lease: lease},
			Pool:      pool,
		})
		return addr
	}
	connect := func(addr string) *pgx.Conn {
		host, port, _ := net.SplitHostPort(addr)
		conn, err := pgx.Connect(ctx, fmt.Sprintf("host=%s port=%s user=workload password=agent-token dbname=app sslmode=disable", host, port))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close(context.Background()) })
		return conn
	}
	code := func(err error) string {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			return pgErr.Code
		}
		return fmt.Sprint(err)
	}

	for name, pool := range map[string]*PoolOptions{"unpooled": nil, "pooled": {QueueFactor: 10}} {
		t.Run(name, func(t *testing.T) {
			before := rows()
			conn := connect(broker(pool))
			// The wrapper itself may run; what it changes must not matter.
			_, _ = conn.Exec(ctx, "SELECT "+unlock+"()")
			var readOnly string
			if err := conn.QueryRow(ctx, "SHOW default_transaction_read_only").Scan(&readOnly); err == nil && readOnly != "on" {
				t.Errorf("default_transaction_read_only = %q after the wrapper, want on", readOnly)
			}
			if _, err := conn.Exec(ctx, "SELECT "+write+"()"); err == nil || code(err) != "25006" {
				t.Errorf("a write through a function in the next transaction answered %v, want 25006", err)
			}
			if n := rows(); n != before {
				t.Errorf("%d rows after the attempt, want %d: a write got through", n, before)
			}
		})
	}

	t.Run("one simple query", func(t *testing.T) {
		before := rows()
		conn := connect(broker(nil))
		if _, err := conn.Exec(ctx, "SELECT "+unlock+"(); SELECT "+write+"()"); code(err) != "25006" {
			t.Errorf("two statements in one message answered %v, want 25006", err)
		}
		if n := rows(); n != before {
			t.Errorf("%d rows, want %d", n, before)
		}
	})

	t.Run("pipelined extended protocol", func(t *testing.T) {
		before := rows()
		raw := openAgentSession(t, broker(nil), "agent-token", "app")
		defer raw.close()
		for _, fn := range []string{unlock, write} {
			raw.fe.Send(&pgproto3.Parse{Query: "SELECT " + fn + "()"})
			raw.fe.Send(&pgproto3.Bind{})
			raw.fe.Send(&pgproto3.Execute{})
			raw.fe.Send(&pgproto3.Sync{})
		}
		if err := raw.fe.Flush(); err != nil {
			t.Fatal(err)
		}
		var ready, refused int
		for ready < 2 {
			msg, err := raw.fe.Receive()
			if err != nil {
				t.Fatal(err)
			}
			switch m := msg.(type) {
			case *pgproto3.ErrorResponse:
				if m.Code == "25006" {
					refused++
				}
			case *pgproto3.ReadyForQuery:
				ready++
			}
		}
		if refused != 1 {
			t.Errorf("%d refusals in the pipeline, want 1", refused)
		}
		if n := rows(); n != before {
			t.Errorf("%d rows, want %d", n, before)
		}
	})
}
