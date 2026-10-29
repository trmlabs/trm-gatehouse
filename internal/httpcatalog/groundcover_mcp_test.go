package httpcatalog

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/auditchain"
)

const groundcoverEntry = `{"name":"groundcover","host":"mcp.groundcover.com","pathPrefixes":["/api/mcp"],"methods":["DELETE","GET","POST"],
	"header":"Authorization","scheme":"Bearer","placeholder":"__vault_GROUNDCOVER__","key":{"mount":"gatehouse","path":"vendors/groundcover","field":"key"},
	"forwardHeaders":["Mcp-Session-Id","Mcp-Protocol-Version","Last-Event-Id","X-Backend-Id","X-Tenant-UUID","X-Timezone"],
	"requestHeaders":[{"name":"X-Backend-Id","values":["us-backend"]}],"pools":["pool-a"]}`

func groundcoverCatalog(t *testing.T) *Entry {
	t.Helper()
	c, err := Parse([]byte(`{"entries":[` + groundcoverEntry + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	e := c.Entries()[0]
	return &e
}

// The messages a Python query client sends for one log or metric query,
// byte for byte as it serializes them (json.dumps with compact separators):
// initialize, the initialized notification and the tool call, each its own
// POST with one JSON object. Only the client's name is made up.
const (
	mcpInitialize  = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"example-query","version":"0.1.0"}}}`
	mcpInitialized = `{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}`
	mcpQueryLogs   = `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"query_logs","arguments":{"query":"level:error | limit 10","period":"PT1H"}}}`
	mcpQueryMetric = `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"query_metrics","arguments":{"mode":"query_range","envs":["production"],"start":"2026-01-01T00:00:00Z","end":"2026-01-01T01:00:00Z","promql":"sum(up)","step":"1m"}}}`
)

// mcpNested is k objects nested in initialize's capabilities, the one object
// a forwarded message may fill as it likes. The message, params and
// capabilities take three levels, so the innermost value sits at depth k+3.
func mcpNested(k int) string {
	nested := strings.Repeat(`{"a":`, k) + `1` + strings.Repeat(`}`, k)
	return strings.Replace(mcpInitialize, `"capabilities":{}`, `"capabilities":{"experimental":`+nested+`}`, 1)
}

// mcpLogs and mcpMetrics are the client's calls with one argument's value
// replaced.
func mcpLogs(query string) string {
	return strings.Replace(mcpQueryLogs, `"level:error | limit 10"`, query, 1)
}

func mcpMetrics(promql string) string {
	return strings.Replace(mcpQueryMetric, `"sum(up)"`, promql, 1)
}

// mcpArgs is a call with extra arguments added before the client's own.
func mcpArgs(call, args string) string {
	return strings.Replace(call, `"arguments":{`, `"arguments":{`+args+`,`, 1)
}

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
		"a log query window": {"POST", "application/json", strings.Replace(mcpQueryLogs, `"period":"PT1H"`, `"start":"2026-01-01T00:00:00Z","end":"2026-01-01T01:00:00Z"`, 1), "groundcover.query_logs"},
		"an escaped name":    {"POST", "application/json", strings.Replace(mcpQueryLogs, `"query_logs"`, `"query\u005flogs"`, 1), "groundcover.query_logs"},
		"spaces around it":   {"POST", "application/json", " \n" + mcpQueryLogs + "\n ", "groundcover.query_logs"},
		"as deep as allowed": {"POST", "application/json", mcpNested(groundcoverMCPDepth - 3), "groundcover.initialize"},
		"every metric argument": {"POST", "application/json", mcpArgs(mcpQueryMetric,
			`"period":"PT1H","clusters":["c"],"required":["up"],"filter":"up","metricName":"up","limit":4294967295,"skip":0`), "groundcover.query_metrics"},
		"the client's memory query":    {"POST", "application/json", mcpMetrics(`"max by (workload, pod) (\n  groundcover_container_memory_working_set_bytes{\n    cluster=\"c\",\n    workload=~\"api-server|queue-worker\",\n    container=\"app\"\n  }\n)"`), "groundcover.query_metrics"},
		"the client's discovery query": {"POST", "application/json", mcpLogs(`"workload:api-server env:staging | stats by (workload, pod_name) count(), min(timestamp) as first | limit 20"`), "groundcover.query_logs"},
		"the event stream":             {"GET", "", "", ""},
		"ending the session":           {"DELETE", "", "", ""},
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

// Every operation a forwarded message names is in the audit chain's
// vocabulary, so its row is accepted without a new row version.
func TestMCPOperationsAreAuditable(t *testing.T) {
	ops := []string{}
	for _, op := range groundcoverMCPMethods {
		if op != "" {
			ops = append(ops, op)
		}
	}
	for _, op := range groundcoverMCPTools {
		ops = append(ops, op)
	}
	if len(ops) != 4 {
		t.Fatalf("operations %v", ops)
	}
	for _, op := range ops {
		if err := (auditchain.Event{Event: auditchain.EventHTTPResponse, Operation: op}).Validate(); err != nil {
			t.Errorf("%s: %v", op, err)
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
		"an escaped issues name": strings.Replace(mcpQueryLogs, `"query_logs"`, `"query\u005fissues"`, 1),
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
	for name, tc := range map[string]struct {
		method, path, query, body string
		contentTypes              []string
	}{
		"a batch":                       {body: `[` + mcpQueryLogs + `,` + mcpCall("query_issues") + `]`},
		"a batch of one allowed call":   {body: `[` + mcpQueryLogs + `]`},
		"two messages":                  {body: mcpQueryLogs + mcpCall("query_issues")},
		"a repeated method":             {body: `{"jsonrpc":"2.0","id":2,"method":"initialize","method":"tools/call","params":{"name":"query_issues"}}`},
		"a repeated method escaped":     {body: `{"jsonrpc":"2.0","id":2,"method":"initialize","\u006dethod":"tools/call","params":{"name":"query_issues"}}`},
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
		"one level too deep":            {body: mcpNested(groundcoverMCPDepth - 2)},
		"far too deep":                  {body: mcpNested(40)},
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

// A tool call may not pick its own backend or tenant, however the argument is
// spelled: neither tool lists it, and the entry's X-Backend-Id pins the
// backend.
func TestMCPRefusesRoutingArguments(t *testing.T) {
	e := groundcoverCatalog(t)
	for _, arg := range []string{
		`"backend_id":"us-backend"`, `"backend_id":"eu-backend"`, `"tenant_uuid":"00000000-0000-0000-0000-000000000000"`,
		`"Backend_Id":"eu-backend"`, `"backendId":"eu-backend"`, `"backend-id":"eu-backend"`, `"TENANT_UUID":"x"`, `"tenantUuid":"x"`,
	} {
		for _, call := range []string{mcpQueryLogs, mcpQueryMetric} {
			if operation, err := e.CheckMCP("POST", "/api/mcp", "", []string{"application/json"}, []byte(mcpArgs(call, arg))); !errors.Is(err, ErrMCPArgument) || operation != "" {
				t.Errorf("%s: operation %q, %v", arg, operation, err)
			}
		}
	}
}

// A tool call carries only the arguments its tool lists, each with its own
// type: an unknown name, one only the other tool takes, another case, and an
// object, list, number, null or boolean where a string belongs are refused,
// so nothing can hide a backend_id below an argument.
func TestMCPRefusesUnlistedArguments(t *testing.T) {
	e := groundcoverCatalog(t)
	for name, body := range map[string]string{
		"an unknown name":           mcpArgs(mcpQueryLogs, `"source":"logs"`),
		"a metric argument on logs": mcpArgs(mcpQueryLogs, `"promql":"sum(up)"`),
		"a log argument on metrics": mcpArgs(mcpQueryMetric, `"query":"*"`),
		"another case":              mcpArgs(mcpQueryLogs, `"Period":"PT1H"`),
		"a nested backend":          strings.Replace(mcpQueryLogs, `"period":"PT1H"`, `"period":{"backend_id":"eu-backend"}`, 1),
		"a list for the query":      mcpLogs(`["*"]`),
		"a number for the query":    mcpLogs(`1`),
		"null for the query":        mcpLogs(`null`),
		"true for the query":        mcpLogs(`true`),
		"an object in envs":         strings.Replace(mcpQueryMetric, `["production"]`, `["production",{"backend_id":"eu-backend"}]`, 1),
		"a number in envs":          strings.Replace(mcpQueryMetric, `["production"]`, `[1]`, 1),
		"a nested list in envs":     strings.Replace(mcpQueryMetric, `["production"]`, `[["production"]]`, 1),
		"a string for envs":         strings.Replace(mcpQueryMetric, `["production"]`, `"production"`, 1),
		"a string for the limit":    mcpArgs(mcpQueryMetric, `"limit":"10"`),
		"a negative limit":          mcpArgs(mcpQueryMetric, `"limit":-1`),
		"a fractional limit":        mcpArgs(mcpQueryMetric, `"limit":1.5`),
		"an exponent limit":         mcpArgs(mcpQueryMetric, `"limit":1e3`),
		"a limit past 2^32-1":       mcpArgs(mcpQueryMetric, `"limit":4294967296`),
		"a number for the step":     strings.Replace(mcpQueryMetric, `"step":"1m"`, `"step":60`, 1),
		"an object for the promql":  mcpMetrics(`{"promql":"sum(up)"}`),
	} {
		if operation, err := e.CheckMCP("POST", "/api/mcp", "", []string{"application/json"}, []byte(body)); !errors.Is(err, ErrMCPArgument) || operation != "" {
			t.Errorf("%s: operation %q, %v", name, operation, err)
		}
	}
}

// A call that names gcQL's _from, which reads another signal (monitor
// issues among them) inside a subquery, or a wildcard prefix of it, is
// refused in any argument that carries a string, while a longer name that
// only contains it passes.
func TestMCPRefusesCrossSignalArguments(t *testing.T) {
	e := groundcoverCatalog(t)
	for name, body := range map[string]string{
		"a filter":         mcpLogs(`"_from:issues | limit 10"`),
		"another case":     mcpLogs(`"* | filter _FROM:issues | limit 10"`),
		"after a quote":    mcpLogs(`"\"_from\":issues | limit 10"`),
		"escaped":          mcpLogs(`"\u005ffrom:issues | limit 10"`),
		"at the start":     mcpLogs(`"_from issues | limit 10"`),
		"_fr*":             mcpLogs(`"_fr*:issues | limit 10"`),
		"_FRO*":            mcpLogs(`"_FRO*:issues | limit 10"`),
		"_f*":              mcpLogs(`"* | filter _f*:issues | limit 10"`),
		"_*":               mcpLogs(`"_*:issues | limit 10"`),
		"the period":       strings.Replace(mcpQueryLogs, `"PT1H"`, `"_from"`, 1),
		"in query_metrics": mcpMetrics(`"_from"`),
		"in a metric list": strings.Replace(mcpQueryMetric, `["production"]`, `["production","_from"]`, 1),
	} {
		if operation, err := e.CheckMCP("POST", "/api/mcp", "", []string{"application/json"}, []byte(body)); !errors.Is(err, ErrMCPArgument) || operation != "" {
			t.Errorf("%s: operation %q, %v", name, operation, err)
		}
	}
	for name, q := range map[string]string{
		"a longer name":    `"transfer_from:x | limit 10"`,
		"a field suffix":   `"* | fields data_from_cache | limit 10"`,
		"plain from":       `"from:issues | limit 10"`,
		"a word inside it": `"\"rows_fromage\" | limit 10"`,
		"a value prefix":   `"content:pre_fr* | limit 10"`,
	} {
		if operation, err := e.CheckMCP("POST", "/api/mcp", "", []string{"application/json"}, []byte(mcpLogs(q))); err != nil || operation != "groundcover.query_logs" {
			t.Errorf("%s: operation %q, %v", name, operation, err)
		}
	}
}

// A log query may not run a subquery, through which it could read another
// signal: no join or union pipe, no pipe inside the list of in(),
// contains_any() or contains_all() wherever a quote ends it, and no
// backslash, which could spell any of these escaped. The client's own
// queries, an in() list, a regex alternative and a pipe after a list pass,
// and the log rules do not apply to query_metrics.
func TestMCPRefusesLogSubqueries(t *testing.T) {
	e := groundcoverCatalog(t)
	for name, q := range map[string]string{
		"join":                    `"* | join by (namespace) (* | fields namespace) | limit 10"`,
		"union":                   `"* | union (* | limit 5) | limit 10"`,
		"JOIN":                    `"* | JOIN by (x) (*) | limit 10"`,
		"an in() subquery":        `"workload:in(* | fields workload) | limit 10"`,
		"in with a space":         `"workload:in (* | fields workload) | limit 10"`,
		"IN":                      `"workload:IN(* | fields workload) | limit 10"`,
		"contains_any":            `"x:contains_any(* | fields x) | limit 10"`,
		"contains_all":            `"x:contains_all(* | fields x) | limit 10"`,
		"a quoted parenthesis":    `"workload:in(\")\" | fields workload) | limit 10"`,
		"a quote gcQL might skip": `"workload:in(a '(' b) | fields workload) | limit 10"`,
		"an unclosed list":        `"workload:in(a, b | fields workload"`,
		"the second of two lists": `"x:in(a, b) y:in(* | fields y) | limit 10"`,
		"a backslash":             `"content:\"a\\\" | limit 10"`,
		"an escaped _from":        `"\\x5ffrom:issues | limit 10"`,
	} {
		if operation, err := e.CheckMCP("POST", "/api/mcp", "", []string{"application/json"}, []byte(mcpLogs(q))); !errors.Is(err, ErrMCPArgument) || operation != "" {
			t.Errorf("%s: operation %q, %v", name, operation, err)
		}
	}
	for name, body := range map[string]string{
		"an in() list":          mcpLogs(`"workload:in(api-server, queue-worker) env:production | limit 50"`),
		"a regex alternative":   mcpLogs(`"content:~\"timeout|refused\" | limit 50"`),
		"longer words":          mcpLogs(`"rejoin:x unions:y joined | limit 10"`),
		"a word ending in in":   mcpLogs(`"x:main(a | b) | limit 10"`),
		"join in query_metrics": strings.Replace(mcpQueryMetric, `"step":"1m"`, `"step":"1m","filter":"join union in(a|b)"`, 1),
	} {
		if operation, err := e.CheckMCP("POST", "/api/mcp", "", []string{"application/json"}, []byte(body)); err != nil || operation == "" {
			t.Errorf("%s: operation %q, %v", name, operation, err)
		}
	}
}

// A metric call may not reach the ALERTS series, which holds what monitors
// found, by its name in any case or by the names a selector could use for it
// instead; a longer name passes, and the rule does not apply to query_logs.
func TestMCPRefusesMetricAlerts(t *testing.T) {
	e := groundcoverCatalog(t)
	for name, body := range map[string]string{
		"ALERTS":           mcpMetrics(`"ALERTS"`),
		"a selector":       mcpMetrics(`"sum(ALERTS{alertstate=\"firing\"})"`),
		"another case":     mcpMetrics(`"alerts"`),
		"ALERTS_FOR_STATE": mcpMetrics(`"ALERTS_FOR_STATE"`),
		"__name__":         mcpMetrics(`"{__name__=~\"ALERT.+\"}"`),
		"alertname":        mcpMetrics(`"count({alertname!=\"\"})"`),
		"alertstate":       mcpMetrics(`"{alertstate=\"firing\"}"`),
		"a quoted name":    mcpMetrics(`"{\"ALERTS\"}"`),
		"an escaped name":  mcpMetrics(`"{\"\\x41LERTS\"}"`),
		"the metric name":  mcpArgs(mcpQueryMetric, `"metricName":"ALERTS"`),
		"a required name":  mcpArgs(mcpQueryMetric, `"required":["up","ALERTS"]`),
		"the filter":       mcpArgs(mcpQueryMetric, `"filter":"ALERTS"`),
	} {
		if operation, err := e.CheckMCP("POST", "/api/mcp", "", []string{"application/json"}, []byte(body)); !errors.Is(err, ErrMCPArgument) || operation != "" {
			t.Errorf("%s: operation %q, %v", name, operation, err)
		}
	}
	for name, body := range map[string]string{
		"a longer name":   mcpMetrics(`"sum(rate(my_alerts_total[5m]))"`),
		"alerts in a log": mcpLogs(`"ALERTS firing | limit 10"`),
	} {
		if operation, err := e.CheckMCP("POST", "/api/mcp", "", []string{"application/json"}, []byte(body)); err != nil || operation == "" {
			t.Errorf("%s: operation %q, %v", name, operation, err)
		}
	}
}

// An entry with no X-Backend-Id pin, as a catalog written before
// requestHeaders has, loads from a file and from Vault and keeps every
// message rule: the client's calls pass with any backend header, and another
// tool, a backend argument and _from are refused.
func TestMCPRulesApplyWithoutAPin(t *testing.T) {
	doc := []byte(`{"entries":[` + strings.Replace(groundcoverEntry, `"requestHeaders":[{"name":"X-Backend-Id","values":["us-backend"]}],`, ``, 1) + `]}`)
	c, err := Parse(doc)
	if err != nil {
		t.Fatal(err)
	}
	if tolerant, dropped, err := ParseTolerant(doc); err != nil || len(dropped) != 0 || len(tolerant.Entries()) != 1 {
		t.Fatalf("tolerant: %v, dropped %v", err, dropped)
	}
	e := c.Entries()[0]
	if len(e.RequestHeaders) != 0 || e.CheckRequestHeaders(http.Header{}) != nil {
		t.Fatalf("pin %v", e.RequestHeaders)
	}
	for _, body := range []string{mcpInitialize, mcpInitialized, mcpQueryLogs, mcpQueryMetric} {
		if _, err := e.CheckMCP("POST", "/api/mcp", "", []string{"application/json"}, []byte(body)); err != nil {
			t.Errorf("%s: %v", body, err)
		}
	}
	for name, tc := range map[string]struct {
		body string
		want error
	}{
		"query_issues": {mcpCall("query_issues"), ErrMCPTool},
		"tools/list":   {`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`, ErrMCPTool},
		"backend_id":   {mcpArgs(mcpQueryLogs, `"backend_id":"eu-backend"`), ErrMCPArgument},
		"tenant_uuid":  {mcpArgs(mcpQueryMetric, `"tenant_uuid":"x"`), ErrMCPArgument},
		"_from":        {mcpLogs(`"_from:issues | limit 10"`), ErrMCPArgument},
		"a join":       {mcpLogs(`"* | join by (x) (*) | limit 10"`), ErrMCPArgument},
		"a batch":      {`[` + mcpQueryLogs + `]`, ErrMCPShape},
	} {
		if operation, err := e.CheckMCP("POST", "/api/mcp", "", []string{"application/json"}, []byte(tc.body)); !errors.Is(err, tc.want) || operation != "" {
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
