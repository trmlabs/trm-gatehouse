package httpcatalog

import (
	"errors"
	"strings"
	"testing"
)

const groundcoverEntry = `{"name":"groundcover","host":"mcp.groundcover.com","pathPrefixes":["/api/mcp"],"methods":["DELETE","GET","POST"],
	"header":"Authorization","scheme":"Bearer","placeholder":"__vault_GROUNDCOVER__","key":{"mount":"gatehouse","path":"vendors/groundcover","field":"key"},
	"pools":["pool-a"]}`

func groundcoverCatalog(t *testing.T) *Entry {
	t.Helper()
	c, err := Parse([]byte(`{"entries":[` + groundcoverEntry + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	e := c.Entries()[0]
	return &e
}

// The messages a query client sends to run a log or metric query: initialize,
// the initialized notification and the tool call, each as one JSON object.
const (
	mcpInitialize  = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"query-client","version":"1.0"}}}`
	mcpInitialized = `{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}`
	mcpQueryLogs   = `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"query_logs","arguments":{"query":"level:error | limit 10","period":"PT1H"}}}`
	mcpQueryMetric = `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"query_metrics","arguments":{"mode":"query_instant","promql":"up","end":"2026-01-01T00:00:00Z"}}}`
)

func mcpCall(tool string) string {
	return strings.Replace(mcpQueryLogs, `"query_logs"`, `"`+tool+`"`, 1)
}

func TestMCPForwardsTheQueryClientsMessages(t *testing.T) {
	e := groundcoverCatalog(t)
	for name, tc := range map[string]struct {
		method, contentType, body, operation string
	}{
		"initialize":         {"POST", "application/json", mcpInitialize, "groundcover.initialize"},
		"initialized":        {"POST", "application/json", mcpInitialized, "groundcover.initialized"},
		"query_logs":         {"POST", "application/json", mcpQueryLogs, "groundcover.query_logs"},
		"query_metrics":      {"POST", "application/json", mcpQueryMetric, "groundcover.query_metrics"},
		"a charset":          {"POST", "application/json; charset=utf-8", mcpQueryLogs, "groundcover.query_logs"},
		"a string id":        {"POST", "application/json", strings.Replace(mcpQueryLogs, `"id":2`, `"id":"a2"`, 1), "groundcover.query_logs"},
		"no arguments":       {"POST", "application/json", `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"query_metrics"}}`, "groundcover.query_metrics"},
		"an escaped name":    {"POST", "application/json", strings.Replace(mcpQueryLogs, `"query_logs"`, `"query_logs"`, 1), "groundcover.query_logs"},
		"spaces around it":   {"POST", "application/json", " \n" + mcpQueryLogs + "\n ", "groundcover.query_logs"},
		"the event stream":   {"GET", "", "", ""},
		"ending the session": {"DELETE", "", "", ""},
	} {
		var contentTypes []string
		if tc.contentType != "" {
			contentTypes = []string{tc.contentType}
		}
		operation, err := e.CheckMCP(tc.method, "/api/mcp", "", contentTypes, []byte(tc.body))
		if err != nil || operation != tc.operation {
			t.Errorf("%s: operation %q, %v", name, operation, err)
		}
	}
}

// Every other method and tool is refused as one the broker does not forward:
// issues and monitors, which groundcover does not hold to a key's data scope,
// the agent tools that can read them, the tool list and any name it does not
// know, spelled however the client likes.
func TestMCPRefusesOtherMethodsAndTools(t *testing.T) {
	e := groundcoverCatalog(t)
	for name, body := range map[string]string{
		"query_issues":           mcpCall("query_issues"),
		"query_monitors":         mcpCall("query_monitors"),
		"query_traces":           mcpCall("query_traces"),
		"async_explore_data":     mcpCall("async_explore_data"),
		"search_logs_metadata":   mcpCall("search_logs_metadata"),
		"an unknown tool":        mcpCall("not_a_tool"),
		"an empty tool name":     mcpCall(""),
		"another case":           mcpCall("Query_Logs"),
		"a trailing space":       mcpCall("query_logs "),
		"an escaped issues name": strings.Replace(mcpQueryLogs, `"query_logs"`, `"query_issues"`, 1),
		"tools/list":             `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`,
		"ping":                   `{"jsonrpc":"2.0","id":2,"method":"ping"}`,
		"resources/read":         `{"jsonrpc":"2.0","id":2,"method":"resources/read","params":{"uri":"x"}}`,
		"another notification":   `{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}}`,
		"another case of method": strings.Replace(mcpQueryLogs, `"tools/call"`, `"Tools/Call"`, 1),
	} {
		if operation, err := e.CheckMCP("POST", "/api/mcp", "", []string{"application/json"}, []byte(body)); !errors.Is(err, ErrMCPTool) || operation != "" {
			t.Errorf("%s: operation %q, %v", name, operation, err)
		}
	}
}

// A request that could carry a second call, or that another parser could
// read as a different message, is refused before its method is looked at: a
// batch, a repeated key at any depth (escaped or not), a key that differs
// only in case, a key the client does not send, and bytes or nesting a
// parser could cut, drop or give up on.
func TestMCPRefusesShapesThatCouldSmuggleACall(t *testing.T) {
	e := groundcoverCatalog(t)
	deep := strings.Repeat(`{"a":`, 40) + `1` + strings.Repeat(`}`, 40)
	for name, tc := range map[string]struct {
		method, path, query, body string
		contentTypes              []string
	}{
		"a batch":                       {body: `[` + mcpQueryLogs + `,` + mcpCall("query_issues") + `]`},
		"a batch of one allowed call":   {body: `[` + mcpQueryLogs + `]`},
		"two messages":                  {body: mcpQueryLogs + mcpCall("query_issues")},
		"a repeated method":             {body: `{"jsonrpc":"2.0","id":2,"method":"initialize","method":"tools/call","params":{"name":"query_issues"}}`},
		"a repeated method escaped":     {body: `{"jsonrpc":"2.0","id":2,"method":"initialize","method":"tools/call","params":{"name":"query_issues"}}`},
		"a method in another case":      {body: `{"jsonrpc":"2.0","id":2,"method":"initialize","Method":"tools/call","params":{"name":"query_issues"}}`},
		"a repeated params":             {body: `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"query_logs"},"params":{"name":"query_issues"}}`},
		"a repeated tool name":          {body: `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"query_logs","name":"query_issues"}}`},
		"a tool name in another case":   {body: `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"query_logs","Name":"query_issues"}}`},
		"a repeated argument":           {body: strings.Replace(mcpQueryLogs, `"period":"PT1H"`, `"period":"PT1H","period":"P1D"`, 1)},
		"meta in params":                {body: strings.Replace(mcpQueryLogs, `"params":{`, `"params":{"_meta":{"progressToken":1},`, 1)},
		"a response, not a request":     {body: `{"jsonrpc":"2.0","id":2,"result":{}}`},
		"an unknown top-level key":      {body: strings.Replace(mcpQueryLogs, `"id":2`, `"id":2,"tool":"query_issues"`, 1)},
		"no jsonrpc":                    {body: strings.Replace(mcpQueryLogs, `"jsonrpc":"2.0",`, ``, 1)},
		"another jsonrpc":               {body: strings.Replace(mcpQueryLogs, `"2.0"`, `"1.0"`, 1)},
		"an object id":                  {body: strings.Replace(mcpQueryLogs, `"id":2`, `"id":{"a":1}`, 1)},
		"no method":                     {body: `{"jsonrpc":"2.0","id":2,"params":{"name":"query_logs"}}`},
		"a method that is not a string": {body: `{"jsonrpc":"2.0","id":2,"method":["tools/call"],"params":{"name":"query_logs"}}`},
		"params in a list":              {body: `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":["query_issues"]}`},
		"no params on a call":           {body: `{"jsonrpc":"2.0","id":2,"method":"tools/call"}`},
		"a tool name that is a list":    {body: `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":["query_logs","query_issues"]}}`},
		"arguments in a list":           {body: `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"query_logs","arguments":["x"]}}`},
		"a NUL in a key":                {body: strings.Replace(mcpQueryLogs, `"name"`, `"name\u0000"`, 1)},
		"a NUL in the tool name":        {body: strings.Replace(mcpQueryLogs, `"query_logs"`, `"query_logs\u0000issues"`, 1)},
		"a lone surrogate":              {body: strings.Replace(mcpQueryLogs, `"query_logs"`, `"query_logs\ud800"`, 1)},
		"invalid UTF-8":                 {body: strings.Replace(mcpQueryLogs, `level:error`, "level:\xff", 1)},
		"a byte order mark":             {body: "\xef\xbb\xbf" + mcpQueryLogs},
		"a trailing comma":              {body: strings.Replace(mcpQueryLogs, `}}}`, `},}}`, 1)},
		"not JSON":                      {body: `method=tools/call&name=query_logs`},
		"empty":                         {body: ``},
		"only spaces":                   {body: "  \n"},
		"too deep":                      {body: strings.Replace(mcpQueryLogs, `"period":"PT1H"`, `"period":`+deep, 1)},
		"a query string":                {query: "method=tools/call", body: mcpQueryLogs},
		"another path":                  {path: "/api/mcp/", body: mcpQueryLogs},
		"a longer path":                 {path: "/api/mcp/messages", body: mcpQueryLogs},
		"another method":                {method: "PUT", body: mcpQueryLogs},
		"a body on DELETE":              {method: "DELETE", body: mcpQueryLogs},
		"no content type":               {body: mcpQueryLogs, contentTypes: []string{}},
		"another content type":          {body: mcpQueryLogs, contentTypes: []string{"text/plain"}},
		"two content types":             {body: mcpQueryLogs, contentTypes: []string{"application/json", "application/json"}},
	} {
		if tc.method == "" {
			tc.method = "POST"
		}
		if tc.path == "" {
			tc.path = "/api/mcp"
		}
		if tc.contentTypes == nil {
			tc.contentTypes = []string{"application/json"}
		}
		if operation, err := e.CheckMCP(tc.method, tc.path, tc.query, tc.contentTypes, []byte(tc.body)); !errors.Is(err, ErrMCPShape) || operation != "" {
			t.Errorf("%s: operation %q, %v", name, operation, err)
		}
	}
}

// The rule is keyed on groundcover's MCP host alone: another host's entry,
// with the same paths and bodies, is not read as MCP.
func TestMCPAppliesOnlyToGroundcoversHost(t *testing.T) {
	for _, host := range []string{"groundcover.com", "api.groundcover.com", "example.com"} {
		c, err := Parse([]byte(`{"entries":[` + strings.Replace(groundcoverEntry, `"mcp.groundcover.com"`, `"`+host+`"`, 1) + `]}`))
		if err != nil {
			t.Fatal(err)
		}
		e := c.Entries()[0]
		if operation, err := e.CheckMCP("POST", "/api/mcp", "", []string{"application/json"}, []byte(mcpCall("query_issues"))); err != nil || operation != "" {
			t.Errorf("%s: operation %q, %v", host, operation, err)
		}
	}
	var nilEntry *Entry
	if _, err := nilEntry.CheckMCP("POST", "/api/mcp", "", nil, nil); err != nil {
		t.Errorf("nil entry: %v", err)
	}
}
