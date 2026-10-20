package httpcatalog

import (
	"strings"
	"testing"
)

// http2 is a property of a header or gcp entry's host: the tunnel offers h2
// to that host only, every entry on it agrees, and the gRPC deadline header
// passes on those entries alone.
func TestHTTP2IsPerHostAndHeaderOrGCPOnly(t *testing.T) {
	rpc := strings.Replace(validEntry, `"serpapi.com"`, `"rpc.example.com"`, 1)
	rpc = strings.Replace(rpc, `"pools":["pool-a"]`, `"pools":["pool-a"],"http2":true`, 1)
	c, err := Parse([]byte(`{"entries":[` + validEntry + `,` + strings.Replace(rpc, `"serpapi"`, `"rpc"`, 1) + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	if !c.HTTP2Host("RPC.example.com", 443) || c.HTTP2Host("rpc.example.com", 8443) || c.HTTP2Host("serpapi.com", 443) {
		t.Fatal("HTTP2Host does not follow the entries")
	}
	for _, e := range c.Entries() {
		if got := e.ForwardsHeader("grpc-timeout"); got != e.HTTP2 {
			t.Errorf("%s forwards grpc-timeout: %v", e.Name, got)
		}
	}
	storage := strings.Replace(bqEntry, `"bigquery.googleapis.com"`, `"bigquerystorage.googleapis.com"`, 1)
	storage = strings.Replace(storage, `"/bigquery/v2/projects/example-analytics/"`, `"/google.cloud.bigquery.storage.v1.BigQueryRead/"`, 1)
	storage = strings.Replace(storage, `"kind":"gcp",`, `"kind":"gcp","http2":true,`, 1)
	g := gcpCatalog(t, storage)
	entry := g.Entries()[0]
	if !g.HTTP2Host("bigquerystorage.googleapis.com", 443) || !entry.GCPForwardsHeader("Grpc-Timeout") || !entry.GCPForwardsHeader("x-goog-request-params") {
		t.Fatal("a gcp entry with http2 does not take gRPC")
	}

	disagree := strings.Replace(strings.Replace(rpc, `"serpapi"`, `"rpc2"`, 1), `,"http2":true`, ``, 1)
	disagree = strings.Replace(disagree, `"/search","/account/"`, `"/other/"`, 1)
	for name, doc := range map[string]string{
		"git entry":       `{"entries":[` + strings.Replace(gitEntry, `"kind":"git",`, `"kind":"git","http2":true,`, 1) + `]}`,
		"hosts disagree":  `{"entries":[` + strings.Replace(rpc, `"serpapi"`, `"rpc"`, 1) + `,` + disagree + `]}`,
		"browser session": `{"entries":[` + browserEntryJSON(`,"http2":true`) + `]}`,
	} {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
