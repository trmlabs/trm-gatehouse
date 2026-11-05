package httpcatalog

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

// MemgraphBinding is a graph database reached over Bolt. The broker signs in with one Vault login (username and password at Login) that never reaches a worker, and enforces the entry's access itself since Community edition has no roles. See docs/gatehouse/graph-databases.md.
type MemgraphBinding struct {
	Login KVRef `json:"login"`
	// Access is "read" (default: read-only queries in rolled-back transactions) or "write" (graph writes commit). File loads, own commits, unlisted procedures and functions, and system queries stay refused.
	Access string `json:"access,omitempty"`
	// SSLMode is verify-full, the only mode outside a test deployment, which may use disable for a cluster-local host.
	SSLMode string `json:"sslmode,omitempty"`
	// CA and ServerName are as for a postgres entry.
	CA         string `json:"ca,omitempty"`
	ServerName string `json:"serverName,omitempty"`
	MaxConns   int    `json:"maxConns,omitempty"` // 0: the broker's default budget
	// Procedures and Functions name the procedures and module functions a query may use; every other one is refused since it can write, read server files or reach the network.
	Procedures []string `json:"procedures,omitempty"`
	Functions  []string `json:"functions,omitempty"`
}

var moduleName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)+$`)

func databaseKind(kind string) bool { return kind == "postgres" || kind == "memgraph" }

func (e *Entry) normalizeMemgraph() error {
	if len(e.PathPrefixes) > 0 || len(e.Methods) > 0 || e.Header != "" || e.Scheme != "" || e.BasicUser || e.BasicPair || e.PairUserHeader != "" || e.Placeholder != "" || e.Key != (KeyRef{}) ||
		len(e.ForwardHeaders) > 0 || e.Git != nil || e.Postgres != nil || e.BrowserSession != nil || e.GCP != nil || e.MaxRequestBytes != 0 || e.MaxResponseBytes != 0 {
		return errors.New("memgraph entries take only host, port, pools, tier and memgraph settings")
	}
	m := e.Memgraph
	if m == nil {
		return errors.New("memgraph entries need memgraph settings")
	}
	if !kvPattern.MatchString(m.Login.Mount) || !ValidMount(m.Login.Mount) || !kvPattern.MatchString(m.Login.Path) || strings.Contains(m.Login.Path, "..") {
		return errors.New("memgraph entries need a login: a KV mount and path")
	}
	switch m.Access {
	case "":
		m.Access = "read"
	case "read", "write":
	default:
		return fmt.Errorf("access %q: read or write", m.Access)
	}
	switch {
	case m.SSLMode == "":
		m.SSLMode = "verify-full"
	case m.SSLMode == "verify-full":
	case m.SSLMode == "disable" && plaintextDatabases.Load() && clusterLocal(e.Host):
	default:
		return fmt.Errorf("sslmode %q: catalog databases use verify-full", m.SSLMode)
	}
	if (m.CA != "" || m.ServerName != "") && m.SSLMode != "verify-full" {
		return errors.New("ca and serverName need sslmode verify-full")
	}
	if m.CA != "" {
		if err := validPinnedCA(m.CA); err != nil {
			return err
		}
	}
	if m.ServerName != "" && !hostPattern.MatchString(m.ServerName) {
		if _, err := netip.ParseAddr(m.ServerName); err != nil {
			return fmt.Errorf("serverName %q: a lowercase DNS name or an IP address", m.ServerName)
		}
	}
	if m.MaxConns < 0 || m.MaxConns > 100000 {
		return errors.New("maxConns out of range")
	}
	for _, list := range [][]string{m.Procedures, m.Functions} {
		for _, name := range list {
			if !moduleName.MatchString(name) {
				return fmt.Errorf("procedure or function %q: a module name such as schema.node_type_properties", name)
			}
		}
	}
	if len(e.Pools) == 0 {
		return errors.New("at least one pool is required")
	}
	for _, pool := range e.Pools {
		if !idPattern.MatchString(pool) {
			return fmt.Errorf("invalid pool %q", pool)
		}
	}
	return nil
}

func (c Catalog) Graph(name, pool string) (*Entry, error) {
	for i := range c.entries {
		e := &c.entries[i]
		if e.Kind != "memgraph" || e.Name != name {
			continue
		}
		if !contains(e.Pools, pool) {
			return e, ErrPool
		}
		return e, nil
	}
	return nil, ErrUnlisted
}
