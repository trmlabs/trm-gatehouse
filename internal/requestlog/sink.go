// Package requestlog persists per-request broker metadata (never bodies, headers or query strings) through a pluggable Sink.
package requestlog

import (
	"context"

	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/store"
)

// Record is the in-memory shape handed to sinks: brokercore.ProxyEvent plus actor and vault context.
type Record struct {
	VaultID        string
	ActorType      string
	ActorID        string
	Ingress        string
	Method         string
	Host           string
	Path           string
	MatchedService string // canonical service name (slug); persisted.
	MatchedHost    string // host pattern; not persisted by the SQLite sink (no schema change).
	MatchedPath    string // path pattern, or empty for catch-all; not persisted by the SQLite sink.
	MatchedPort    *int   // not persisted by the SQLite sink (no schema change).
	CredentialKeys []string
	Status         int
	LatencyMs      int64
	ErrorCode      string
	AuthScheme     string
	AuthHeader     string
}

// Sink accepts records on the hot proxy path; implementations MUST NOT block meaningfully.
type Sink interface {
	Record(ctx context.Context, r Record)
}

// Nop is a Sink that discards records. Safe default when the server
// is constructed without a configured sink (tests, tooling).
type Nop struct{}

// Record implements Sink.
func (Nop) Record(context.Context, Record) {}

// MultiSink fans each record out to every wrapped sink. Later sinks
// (HTTP webhook, stdout JSONL) stack here without touching the proxy.
type MultiSink []Sink

// Record implements Sink by forwarding to each wrapped sink in order.
func (m MultiSink) Record(ctx context.Context, r Record) {
	for _, s := range m {
		if s == nil {
			continue
		}
		s.Record(ctx, r)
	}
}

// FromEvent builds a Record from a terminal brokercore.ProxyEvent plus actor and vault context.
func FromEvent(ev brokercore.ProxyEvent, vaultID, actorType, actorID string) Record {
	return Record{
		VaultID:        vaultID,
		ActorType:      actorType,
		ActorID:        actorID,
		Ingress:        ev.Ingress,
		Method:         ev.Method,
		Host:           ev.Host,
		Path:           ev.Path,
		MatchedService: ev.MatchedService,
		MatchedHost:    ev.MatchedHost,
		MatchedPath:    ev.MatchedPath,
		MatchedPort:    ev.MatchedPort,
		CredentialKeys: ev.CredentialKeys,
		Status:         ev.Status,
		LatencyMs:      ev.TotalMs,
		ErrorCode:      ev.Err,
		AuthScheme:     ev.AuthScheme,
		AuthHeader:     ev.AuthHeader,
	}
}

// toStoreRow converts a Record to the persisted shape, keeping store free of requestlog imports.
func toStoreRow(r Record) store.RequestLog {
	return store.RequestLog{
		VaultID:        r.VaultID,
		ActorType:      r.ActorType,
		ActorID:        r.ActorID,
		Ingress:        r.Ingress,
		Method:         r.Method,
		Host:           r.Host,
		Path:           r.Path,
		MatchedService: r.MatchedService,
		CredentialKeys: r.CredentialKeys,
		Status:         r.Status,
		LatencyMs:      r.LatencyMs,
		ErrorCode:      r.ErrorCode,
		AuthScheme:     r.AuthScheme,
		AuthHeader:     r.AuthHeader,
	}
}
