package server

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/httpcatalog"
	"github.com/Infisical/agent-vault/internal/pgproxy"
)

const databaseCatalog = `{"pools":[{"name":"cursor","namespace":"agents","serviceAccount":"example-worker"},{"name":"ci","namespace":"ci","serviceAccount":"runner"}],
"entries":[
 {"name":"examplecore","kind":"postgres","host":"p.abc.db.postgresbridge.com","pools":["cursor"],
  "postgres":{"database":"app","mount":"database","role":"staging.us.example.app-readonly","maxConns":20}},
 {"name":"reports","kind":"postgres","host":"p.abc.db.postgresbridge.com","pools":["cursor","ci"],
  "postgres":{"database":"reports","mount":"database","role":"staging.us.example.reports-readonly","sslmode":"verify-full","maxConns":5,"serverName":"reports.example.com"}}]}`

func TestCatalogDatabaseResolverFollowsTheLiveCatalog(t *testing.T) {
	httpcatalog.Environment.Store("staging")
	t.Cleanup(func() { httpcatalog.Environment.Store("") })
	first, err := httpcatalog.Parse([]byte(databaseCatalog))
	if err != nil {
		t.Fatal(err)
	}
	source := httpcatalog.NewSource(first, 1)
	r := NewCatalogDatabaseResolver(source, nil, nil, nil)
	svc, err := r.ResolveDatabase(context.Background(), pgproxy.AgentScope{ActorID: "agent-uuid-1", Pool: "cursor"}, "examplecore")
	if err != nil || svc.Addr != "p.abc.db.postgresbridge.com:5432" || svc.Database != "app" || svc.SSLMode != "verify-full" || svc.MaxConns != 5 || !svc.ReadOnly {
		t.Fatalf("resolved %+v %v", svc, err)
	}
	if svc, err := r.ResolveDatabase(context.Background(), pgproxy.AgentScope{ActorID: "agent-uuid-2", Pool: "ci"}, "reports"); err != nil || svc.ServerName != "reports.example.com" {
		t.Fatalf("server name: %+v %v", svc, err)
	}
	if _, err := r.ResolveDatabase(context.Background(), pgproxy.AgentScope{ActorID: "agent-uuid-2", Pool: "ci"}, "examplecore"); err == nil || !strings.Contains(err.Error(), "not granted") {
		t.Fatalf("ungranted pool: %v", err)
	}
	if _, err := r.ResolveDatabase(context.Background(), pgproxy.AgentScope{ActorID: "agent-uuid-1"}, "examplecore"); err == nil {
		t.Fatal("a scope without a catalog pool resolved a database")
	}
	if _, err := r.ResolveDatabase(context.Background(), pgproxy.AgentScope{ActorID: "agent-uuid-1", Pool: "cursor"}, "events"); err == nil {
		t.Fatal("unknown database resolved")
	}
	// A reload that adds a database makes it reachable with no restart.
	added := strings.Replace(databaseCatalog, `]}`, `,{"name":"events","kind":"postgres","host":"p.def.db.postgresbridge.com","pools":["cursor"],
  "postgres":{"database":"events","mount":"database","role":"staging.us.example.events-readonly"}}]}`, 1)
	if strings.Count(added, "events") < 2 {
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
	if svc, err := r.ResolveDatabase(context.Background(), pgproxy.AgentScope{ActorID: "agent-uuid-1", Pool: "cursor"}, "events"); err != nil || svc.Database != "events" {
		t.Fatalf("reloaded database: %+v %v", svc, err)
	}
}
