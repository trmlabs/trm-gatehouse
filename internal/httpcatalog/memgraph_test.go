package httpcatalog

import (
	"errors"
	"strings"
	"testing"
)

const graphEntry = `{"name":"app-graph","kind":"memgraph","host":"memgraph.graphs.svc.cluster.local","pools":["pool-a"],` +
	`"memgraph":{"login":{"mount":"gatehouse","path":"vendors/memgraph-app"},"serverName":"community.memgraph.example.com",` +
	`"procedures":["schema.node_type_properties"],"functions":["date.add"]}}`

func TestMemgraphEntry(t *testing.T) {
	c, err := Parse([]byte(`{"entries":[` + graphEntry + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	e, err := c.Graph("app-graph", "pool-a")
	if err != nil {
		t.Fatal(err)
	}
	m := e.Memgraph
	if e.Port != 7687 || m.Access != "read" || m.SSLMode != "verify-full" || e.Tier != "" {
		t.Fatalf("defaults: port %d access %q sslmode %q tier %q", e.Port, m.Access, m.SSLMode, e.Tier)
	}
	w, err := Parse([]byte(`{"entries":[` + strings.Replace(graphEntry, `"serverName"`, `"access":"write","serverName"`, 1) + `]}`))
	if err != nil {
		t.Fatalf("write access: %v", err)
	}
	if e, err := w.Graph("app-graph", "pool-a"); err != nil || e.Memgraph.Access != "write" {
		t.Fatalf("write access: %v", err)
	}
	if _, err := c.Graph("app-graph", "pool-b"); !errors.Is(err, ErrPool) {
		t.Fatalf("ungranted pool: %v", err)
	}
	if _, err := c.Graph("other", "pool-a"); !errors.Is(err, ErrUnlisted) {
		t.Fatalf("unknown graph: %v", err)
	}
	if _, err := c.Database("app-graph", "pool-a"); !errors.Is(err, ErrUnlisted) {
		t.Fatalf("a graph entry answered as a PostgreSQL database: %v", err)
	}
	// No HTTP tunnel reaches a database host.
	if c.HasHost(e.Host, e.Port) || c.HasHostForPool(e.Host, e.Port, "pool-a") {
		t.Fatal("a graph host is reachable as an HTTP tunnel")
	}
}

func TestMemgraphEntryRefusals(t *testing.T) {
	cases := map[string]string{
		"unknown access":        strings.Replace(graphEntry, `"serverName"`, `"access":"admin","serverName"`, 1),
		"plaintext":             strings.Replace(graphEntry, `"serverName":"community.memgraph.example.com",`, `"sslmode":"disable",`, 1),
		"no login":              strings.Replace(graphEntry, `"login":{"mount":"gatehouse","path":"vendors/memgraph-app"},`, ``, 1),
		"login path escape":     strings.Replace(graphEntry, `vendors/memgraph-app`, `vendors/../catalog`, 1),
		"bare procedure name":   strings.Replace(graphEntry, `"schema.node_type_properties"`, `"node_type_properties"`, 1),
		"function with spaces":  strings.Replace(graphEntry, `"date.add"`, `"date. add"`, 1),
		"http key":              strings.Replace(graphEntry, `"pools"`, `"header":"X-Api-Key","pools"`, 1),
		"postgres settings":     strings.Replace(graphEntry, `"pools"`, `"postgres":{"database":"x","mount":"database","role":"readonly"},"pools"`, 1),
		"no pools":              strings.Replace(graphEntry, `"pools":["pool-a"],`, ``, 1),
		"budget out of range":   strings.Replace(graphEntry, `"serverName"`, `"maxConns":100001,"serverName"`, 1),
		"settings without kind": strings.Replace(graphEntry, `"kind":"memgraph",`, ``, 1),
	}
	for name, entry := range cases {
		if _, err := Parse([]byte(`{"entries":[` + entry + `]}`)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// One host serves one kind: a graph and an HTTP entry cannot share it.
	mixed := `{"entries":[` + graphEntry + `,{"name":"web","host":"memgraph.graphs.svc.cluster.local","port":7687,"pathPrefixes":["/"],"methods":["GET"],` +
		`"header":"X-Api-Key","placeholder":"__vault_X__","key":{"mount":"gatehouse","path":"vendors/x","field":"k"},"pools":["pool-a"]}]}`
	if _, err := Parse([]byte(mixed)); err == nil {
		t.Error("a graph host was shared with an HTTP entry")
	}
}

func TestMemgraphEntryTiers(t *testing.T) {
	// A graph above T0 follows the tier rules every entry does: it names
	// its groups, and only a pool that can carry it may hold it.
	t1 := strings.Replace(graphEntry, `"pools"`, `"tier":"T1","pools"`, 1)
	if _, err := Parse([]byte(`{"entries":[` + t1 + `]}`)); err == nil {
		t.Fatal("a T1 graph without required groups was accepted")
	}
	t1 = strings.Replace(graphEntry, `"pools"`, `"tier":"T1","requires":["00000000-0000-0000-0000-000000000001"],"pools"`, 1)
	if _, err := Parse([]byte(`{"entries":[` + t1 + `]}`)); err == nil || !strings.Contains(err.Error(), "T1 entries need defined pools") {
		t.Fatalf("T1 graph on an undefined pool: %v", err)
	}
}
