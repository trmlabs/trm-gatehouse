package server

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/httpcatalog"
	"github.com/Infisical/agent-vault/internal/pgproxy"
)

const databaseCatalog = `{"pools":[{"name":"cursor","namespace":"agents","serviceAccount":"cursor-worker"},{"name":"ci","namespace":"ci","serviceAccount":"runner"}],
"entries":[
 {"name":"appdb","kind":"postgres","host":"p.abc.db.postgresbridge.com","pools":["cursor"],
  "postgres":{"database":"core","mount":"database","role":"staging.us.pg1.app-readonly","maxConns":20}},
 {"name":"auditlog","kind":"postgres","host":"p.abc.db.postgresbridge.com","pools":["cursor","ci"],
  "postgres":{"database":"auditlog","mount":"database","role":"staging.us.pg1.auditlog-readonly","sslmode":"verify-full","maxConns":5,"serverName":"auditlog.example.com"}}]}`

func TestCatalogDatabaseResolverFollowsTheLiveCatalog(t *testing.T) {
	httpcatalog.Environment.Store("staging")
	t.Cleanup(func() { httpcatalog.Environment.Store("") })
	first, err := httpcatalog.Parse([]byte(databaseCatalog))
	if err != nil {
		t.Fatal(err)
	}
	source := httpcatalog.NewSource(first, 1)
	r := NewCatalogDatabaseResolver(source, nil, nil, nil)
	svc, err := r.ResolveDatabase(context.Background(), pgproxy.AgentScope{ActorID: "agent-uuid-1", Pool: "cursor"}, "appdb")
	if err != nil || svc.Addr != "p.abc.db.postgresbridge.com:5432" || svc.Database != "core" || svc.SSLMode != "verify-full" || svc.MaxConns != 5 || !svc.ReadOnly {
		t.Fatalf("resolved %+v %v", svc, err)
	}
	if svc, err := r.ResolveDatabase(context.Background(), pgproxy.AgentScope{ActorID: "agent-uuid-2", Pool: "ci"}, "auditlog"); err != nil || svc.ServerName != "auditlog.example.com" {
		t.Fatalf("server name: %+v %v", svc, err)
	}
	if _, err := r.ResolveDatabase(context.Background(), pgproxy.AgentScope{ActorID: "agent-uuid-2", Pool: "ci"}, "appdb"); err == nil || !strings.Contains(err.Error(), "not granted") {
		t.Fatalf("ungranted pool: %v", err)
	}
	if _, err := r.ResolveDatabase(context.Background(), pgproxy.AgentScope{ActorID: "agent-uuid-1"}, "appdb"); err == nil {
		t.Fatal("a scope without a catalog pool resolved a database")
	}
	if _, err := r.ResolveDatabase(context.Background(), pgproxy.AgentScope{ActorID: "agent-uuid-1", Pool: "cursor"}, "reports"); err == nil {
		t.Fatal("unknown database resolved")
	}
	// A reload that adds a database makes it reachable with no restart.
	added := strings.Replace(databaseCatalog, `]}`, `,{"name":"reports","kind":"postgres","host":"p.def.db.postgresbridge.com","pools":["cursor"],
  "postgres":{"database":"reports","mount":"database","role":"staging.us.pg1.reports-readonly"}}]}`, 1)
	if strings.Count(added, "reports") < 2 {
		t.Fatal("test catalog not extended")
	}
	if _, err := httpcatalog.Parse([]byte(added)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go source.Watch(ctx, 10*time.Millisecond, func(context.Context) ([]byte, int, error) { return []byte(added), 2, nil }, func(int, error) {})
	for deadline := time.Now().Add(2 * time.Second); source.Version() != 2; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("catalog not reloaded")
		}
	}
	if svc, err := r.ResolveDatabase(context.Background(), pgproxy.AgentScope{ActorID: "agent-uuid-1", Pool: "cursor"}, "reports"); err != nil || svc.Database != "reports" {
		t.Fatalf("reloaded database: %+v %v", svc, err)
	}
}
