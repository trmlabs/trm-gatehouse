package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	vaultapi "github.com/hashicorp/vault/api"

	"github.com/Infisical/agent-vault/internal/authorize/authorizetest"
	"github.com/Infisical/agent-vault/internal/entitlement"
	"github.com/Infisical/agent-vault/internal/httpcatalog"
	"github.com/Infisical/agent-vault/internal/pgproxy"
	"github.com/Infisical/agent-vault/internal/runnerid"
)

func TestCatalogGraphResolver(t *testing.T) {
	httpcatalog.Environment.Store("staging")
	t.Cleanup(func() { httpcatalog.Environment.Store("") })
	catalog, err := httpcatalog.Parse([]byte(`{"pools":[
	  {"name":"cursor","namespace":"n","serviceAccount":"cursor"},
	  {"name":"claude","namespace":"n","serviceAccount":"claude","identity":"claude-session","ccpoolID":"ccpool_abc","ceiling":"T2"}],
	 "entries":[
	  {"name":"graph","kind":"memgraph","host":"memgraph.trm-orion.svc.cluster.local","pools":["cursor","claude"],
	   "memgraph":{"login":{"mount":"gatehouse","path":"vendors/memgraph-graph"},"serverName":"graph.example.com","maxConns":200,"procedures":["schema.node_type_properties"]}},
	  {"name":"t1graph","kind":"memgraph","host":"other.trm-orion.svc.cluster.local","pools":["claude"],"tier":"T1","requires":["` + t1Group + `"],
	   "memgraph":{"login":{"mount":"gatehouse","path":"vendors/memgraph-t1"}}},
	  {"name":"appdb","kind":"postgres","host":"db.example","pools":["cursor"],"postgres":{"database":"app","mount":"database","role":"staging.us.example.app-readonly"}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	runner := fakeRunner{
		"alice": {Kind: runnerid.KindPerson, Subject: "sso|alice", Pools: []string{"ccpool_abc"}, TokenSHA256: "aa"},
		"bob":   {Kind: runnerid.KindPerson, Subject: "sso|bob", Pools: []string{"ccpool_abc"}},
	}
	cache := &entitlement.Cache{Source: directory{"sso|alice": {t1Group}, "sso|bob": {}}}
	r := NewCatalogGraphResolver(httpcatalog.NewSource(catalog, 1), runner, cache, &authorizetest.MemBinder{})

	svc, err := r.ResolveGraph(context.Background(), pgproxy.AgentScope{ActorID: "a", Pool: "cursor", WorkloadID: "pod-a"}, "graph")
	if err != nil {
		t.Fatal(err)
	}
	if svc.Addr != "memgraph.trm-orion.svc.cluster.local:7687" || svc.ServerName != "graph.example.com" || svc.MaxConns != 200 || svc.Plaintext ||
		svc.KeyMount != "gatehouse" || svc.KeyPath != "vendors/memgraph-graph" || len(svc.Procedures) != 1 {
		t.Fatalf("resolved %+v", svc)
	}
	cases := []struct{ name, pool, token, graph, want string }{
		{"T1 member", "claude", "alice", "t1graph", ""},
		{"T1 non-member", "claude", "bob", "t1graph", "not_entitled"},
		{"T1 without a person", "claude", "", "t1graph", "no_person"},
		{"not granted to the pool", "cursor", "", "t1graph", "not granted"},
		{"a postgres entry is no graph", "cursor", "", "appdb", "no graph database"},
		{"unknown", "cursor", "", "nothing", "no graph database"},
	}
	for _, c := range cases {
		_, err := r.ResolveGraph(pgproxy.WithSession(context.Background(), c.token), pgproxy.AgentScope{ActorID: "a", Pool: c.pool, WorkloadID: "pod-a"}, c.graph)
		var refused *pgproxy.RefusedError
		got := ""
		if errors.As(err, &refused) {
			got = refused.Outcome
		} else if err != nil {
			got = err.Error()
		}
		if (c.want == "" && got != "") || !strings.Contains(got, c.want) {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
}

func TestVaultGraphLogins(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/gatehouse/data/vendors/memgraph-graph":
			_, _ = w.Write([]byte(`{"data":{"data":{"username":"gatehouse_reader","password":"synthetic-password"},"metadata":{"version":3}}}`))
		case "/v1/gatehouse/data/vendors/memgraph-half":
			_, _ = w.Write([]byte(`{"data":{"data":{"username":"gatehouse_reader"},"metadata":{"version":1}}}`))
		default:
			http.Error(w, `{"errors":[]}`, http.StatusNotFound)
		}
	}))
	defer srv.Close()
	client, err := vaultapi.NewClient(&vaultapi.Config{Address: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	logins := NewVaultGraphLogins(&httpcatalog.Keys{Vault: client.Logical()})
	login, err := logins.GraphLogin(context.Background(), &pgproxy.GraphService{KeyMount: "gatehouse", KeyPath: "vendors/memgraph-graph"})
	if err != nil || login.Username != "gatehouse_reader" || login.Password != "synthetic-password" {
		t.Fatalf("login: %+v %v", login, err)
	}
	for _, path := range []string{"vendors/memgraph-half", "vendors/missing"} {
		_, err := logins.GraphLogin(context.Background(), &pgproxy.GraphService{KeyMount: "gatehouse", KeyPath: path})
		if err == nil || strings.Contains(err.Error(), "gatehouse_reader") {
			t.Fatalf("%s: %v", path, err)
		}
	}
}
