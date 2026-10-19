package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"

	"github.com/Infisical/agent-vault/internal/authorize"
	"github.com/Infisical/agent-vault/internal/entitlement"
	"github.com/Infisical/agent-vault/internal/httpcatalog"
	"github.com/Infisical/agent-vault/internal/pgproxy"
)

// NewCatalogGraphResolver resolves graph databases (kind memgraph) from a live
// catalog on every Bolt connection and at every recheck, with the same grant,
// tier and entitlement decision as a PostgreSQL database.
func NewCatalogGraphResolver(catalog interface{ Current() httpcatalog.Catalog }, runner authorize.Verifier, entitlements *entitlement.Cache, sessions authorize.Binder) pgproxy.GraphResolver {
	return catalogGraphResolver{catalogDatabaseResolver{catalog: catalog, runner: runner, entitlements: entitlements, sessions: sessions}}
}

type catalogGraphResolver struct{ databases catalogDatabaseResolver }

func (r catalogGraphResolver) ResolveGraph(ctx context.Context, scope pgproxy.AgentScope, name string) (*pgproxy.GraphService, error) {
	catalog := r.databases.catalog.Current()
	entry, err := catalog.Graph(name, scope.Pool)
	switch {
	case errors.Is(err, httpcatalog.ErrPool):
		return nil, fmt.Errorf("graph database %q is not granted to this pool", name)
	case err != nil:
		return nil, fmt.Errorf("no graph database %q in the catalog", name)
	}
	if err := r.databases.authorize(ctx, catalog, entry, scope); err != nil {
		return nil, err
	}
	m := entry.Memgraph
	return &pgproxy.GraphService{Name: entry.Name, Addr: net.JoinHostPort(entry.Host, strconv.Itoa(entry.Port)),
		ServerName: m.ServerName, CA: m.CA, Plaintext: m.SSLMode == "disable", MaxConns: m.MaxConns,
		KeyMount: m.Login.Mount, KeyPath: m.Login.Path,
		Procedures: append([]string(nil), m.Procedures...), Functions: append([]string(nil), m.Functions...)}, nil
}

// NewVaultGraphLogins reads graph database logins through the catalog's key
// cache: fields username and password of the entry's login secret, each read
// from Vault about once a minute.
func NewVaultGraphLogins(keys *httpcatalog.Keys) pgproxy.GraphLogins {
	return vaultGraphLogins{keys: keys}
}

type vaultGraphLogins struct{ keys *httpcatalog.Keys }

func (l vaultGraphLogins) GraphLogin(ctx context.Context, svc *pgproxy.GraphService) (*pgproxy.GraphLogin, error) {
	ref := httpcatalog.KVRef{Mount: svc.KeyMount, Path: svc.KeyPath}
	user, err := l.keys.Get(ctx, ref.Field("username"))
	if err != nil {
		return nil, fmt.Errorf("graph login username: %w", err)
	}
	password, err := l.keys.Get(ctx, ref.Field("password"))
	if err != nil {
		return nil, fmt.Errorf("graph login password: %w", err)
	}
	return &pgproxy.GraphLogin{Username: user.Value(), Password: password.Value()}, nil
}
