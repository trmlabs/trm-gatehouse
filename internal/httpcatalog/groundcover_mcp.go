package httpcatalog

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// groundcover's MCP server answers every tool on one path, and its data scope is not applied to every tool (monitor issues span every cluster and backend). So the broker forwards only initialize, the initialized notification, and tools/call for query_logs or query_metrics.
// Every other method or tool, a batch, a repeated or unknown key, an unreadable body, and an argument that could reach another signal are refused (groundcoverMCPArguments); GET and DELETE carry no message and pass.
const (
	groundcoverMCPHost = "mcp.groundcover.com"
	groundcoverMCPPath = "/api/mcp"
	// groundcoverMCPDepth bounds how deep a value may sit below the message.
	groundcoverMCPDepth = 32
)

// groundcoverMCPMethods maps each forwarded JSON-RPC method to the operation its audit row names; a tools/call row names its tool.
var groundcoverMCPMethods = map[string]string{
	"initialize":                "groundcover.initialize",
	"notifications/initialized": "groundcover.initialized",
	"tools/call":                "",
}

var groundcoverMCPTools = map[string]string{
	"query_logs":    "groundcover.query_logs",
	"query_metrics": "groundcover.query_metrics",
}

type mcpKind int

const (
	mcpText  mcpKind = iota // a string
	mcpCount                // a whole number from 0 to 2^32-1
	mcpTexts                // a list of strings
)

// groundcoverMCPArguments lists the arguments each tool may carry, less backend_id and tenant_uuid, which would pick another backend than the entry's X-Backend-Id. Any other argument or type is refused so no object or list hides a key groundcover reads.
var groundcoverMCPArguments = map[string]map[string]mcpKind{
	"query_logs": {"query": mcpText, "period": mcpText, "start": mcpText, "end": mcpText},
	"query_metrics": {
		"mode": mcpText, "promql": mcpText, "start": mcpText, "end": mcpText, "step": mcpText, "period": mcpText,
		"envs": mcpTexts, "clusters": mcpTexts, "required": mcpTexts,
		"filter": mcpText, "metricName": mcpText, "limit": mcpCount, "skip": mcpCount,
	},
}

// groundcoverCrossSignal matches gcQL's _from (any case, or a wildcard prefix such as _fr*), through which a query_logs subquery reads another signal outside the key's data scope.
var groundcoverCrossSignal = regexp.MustCompile(`(?i)(?:^|[^a-z0-9_])(?:_from(?:[^a-z0-9_]|$)|_(?:f(?:r(?:o)?)?)?\*)`)

var groundcoverSubqueryPipe = regexp.MustCompile(`(?i)(?:^|[^a-z0-9_])(?:join|union)(?:[^a-z0-9_]|$)`)

var groundcoverSubqueryFilter = regexp.MustCompile(`(?i)(?:^|[^a-z0-9_])(?:in|contains_any|contains_all)\s*\(`)

// groundcoverAlerts matches the ALERTS series in any case and the PromQL names that could reach it (__name__, alertname, alertstate).
var groundcoverAlerts = regexp.MustCompile(`(?i)(?:^|[^a-z0-9_:])(?:alerts|(?:__name__|alertname|alertstate)(?:[^a-z0-9_:]|$))`)

// CheckMCP errors: ErrMCPShape (unreadable message or path), ErrMCPTool (method or tool not forwarded), ErrMCPArgument (unlisted, wrong type, or could reach another signal).
var (
	ErrMCPShape    = errors.New("not one MCP message the broker reads")
	ErrMCPTool     = errors.New("MCP method or tool not forwarded")
	ErrMCPArgument = errors.New("MCP tool argument not forwarded")
)

// CheckMCP holds a request to groundcover's MCP server to the messages the broker forwards and returns the operation its audit row names; every other host is allowed.
func (e *Entry) CheckMCP(method, path, rawQuery string, contentTypes []string, body []byte) (string, error) {
	if e == nil || e.Host != groundcoverMCPHost {
		return "", nil
	}
	if path != groundcoverMCPPath || rawQuery != "" {
		return "", ErrMCPShape
	}
	switch method {
	case http.MethodGet, http.MethodDelete:
		if len(body) > 0 {
			return "", ErrMCPShape
		}
		return "", nil
	case http.MethodPost:
	default:
		return "", ErrMCPShape
	}
	if len(contentTypes) != 1 {
		return "", ErrMCPShape
	}
	if media, _, err := mime.ParseMediaType(contentTypes[0]); err != nil || media != "application/json" {
		return "", ErrMCPShape
	}
	msg, err := mcpMessage(body)
	if err != nil {
		return "", ErrMCPShape
	}
	for key := range msg {
		switch key {
		case "jsonrpc", "id", "method", "params":
		default:
			return "", ErrMCPShape
		}
	}
	if msg["jsonrpc"] != "2.0" {
		return "", ErrMCPShape
	}
	if id, ok := msg["id"]; ok {
		switch id.(type) {
		case string, json.Number:
		default:
			return "", ErrMCPShape
		}
	}
	name, ok := msg["method"].(string)
	if !ok {
		return "", ErrMCPShape
	}
	operation, ok := groundcoverMCPMethods[name]
	if !ok {
		return "", ErrMCPTool
	}
	params, hasParams := msg["params"]
	if hasParams {
		if _, ok := params.(map[string]any); !ok {
			return "", ErrMCPShape
		}
	}
	if name != "tools/call" {
		return operation, nil
	}
	call, _ := params.(map[string]any)
	for key := range call {
		switch key {
		case "name", "arguments":
		default:
			return "", ErrMCPShape
		}
	}
	if args, ok := call["arguments"]; ok {
		if _, ok := args.(map[string]any); !ok {
			return "", ErrMCPShape
		}
	}
	tool, ok := call["name"].(string)
	if !ok {
		return "", ErrMCPShape
	}
	if operation, ok = groundcoverMCPTools[tool]; !ok {
		return "", ErrMCPTool
	}
	args, _ := call["arguments"].(map[string]any)
	for key, value := range args {
		kind, ok := groundcoverMCPArguments[tool][key]
		if !ok || !mcpArgument(tool, kind, value) {
			return "", ErrMCPArgument
		}
	}
	return operation, nil
}

// mcpArgument checks the type and that no string could reach another signal: no backslash, no _from, in query_logs no join or union pipe or pipe inside a subquery filter, in query_metrics no way to ALERTS.
func mcpArgument(tool string, kind mcpKind, value any) bool {
	var texts []string
	switch v := value.(type) {
	case string:
		if kind != mcpText {
			return false
		}
		texts = []string{v}
	case json.Number:
		_, err := strconv.ParseUint(string(v), 10, 32)
		return kind == mcpCount && err == nil
	case []any:
		if kind != mcpTexts {
			return false
		}
		for _, item := range v {
			text, ok := item.(string)
			if !ok {
				return false
			}
			texts = append(texts, text)
		}
	default:
		return false
	}
	for _, text := range texts {
		if strings.Contains(text, `\`) || groundcoverCrossSignal.MatchString(text) {
			return false
		}
		switch tool {
		case "query_logs":
			if groundcoverSubqueryPipe.MatchString(text) || mcpPipedFilter(text) {
				return false
			}
		case "query_metrics":
			if groundcoverAlerts.MatchString(text) {
				return false
			}
		}
	}
	return true
}

// mcpMessage decodes one JSON object with no repeated key, bounded depth and no control byte or U+FFFD in strings, so another parser cannot read the message differently from this one. Numbers stay json.Number.
func mcpMessage(body []byte) (map[string]any, error) {
	if !utf8.Valid(body) {
		return nil, ErrMCPShape
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	v, err := mcpValue(dec, 0)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, ErrMCPShape
	}
	msg, ok := v.(map[string]any)
	if !ok {
		return nil, ErrMCPShape
	}
	return msg, nil
}

func mcpValue(dec *json.Decoder, depth int) (any, error) {
	if depth > groundcoverMCPDepth {
		return nil, ErrMCPShape
	}
	tok, err := dec.Token()
	if err != nil {
		return nil, ErrMCPShape
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			obj := map[string]any{}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, ErrMCPShape
				}
				key, ok := kt.(string)
				if !ok || !mcpPlainString(key) {
					return nil, ErrMCPShape
				}
				if _, dup := obj[key]; dup {
					return nil, ErrMCPShape
				}
				if obj[key], err = mcpValue(dec, depth+1); err != nil {
					return nil, err
				}
			}
			if end, err := dec.Token(); err != nil || end != json.Delim('}') {
				return nil, ErrMCPShape
			}
			return obj, nil
		case '[':
			list := []any{}
			for dec.More() {
				v, err := mcpValue(dec, depth+1)
				if err != nil {
					return nil, err
				}
				list = append(list, v)
			}
			if end, err := dec.Token(); err != nil || end != json.Delim(']') {
				return nil, ErrMCPShape
			}
			return list, nil
		}
		return nil, ErrMCPShape
	case string:
		if !mcpPlainString(t) {
			return nil, ErrMCPShape
		}
		return t, nil
	}
	return tok, nil
}

func mcpPlainString(s string) bool {
	for _, r := range s {
		if (r < 0x20 && r != '\t' && r != '\n' && r != '\r') || r == 0x7f || r == utf8.RuneError {
			return false
		}
	}
	return true
}

// mcpPipedFilter reports a pipe inside a subquery-capable filter list; the later of two ends (skipping quotes or not) counts, so a quote read differently from gcQL cannot close the list early.
func mcpPipedFilter(s string) bool {
	for _, loc := range groundcoverSubqueryFilter.FindAllStringIndex(s, -1) {
		open := loc[1] - 1
		end := max(mcpListEnd(s, open, true), mcpListEnd(s, open, false))
		if strings.Contains(s[open:end], "|") {
			return true
		}
	}
	return false
}

func mcpListEnd(s string, open int, quotes bool) int {
	depth := 0
	var quote byte
	for i := open; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case quotes && (c == '"' || c == '\'' || c == '`'):
			quote = c
		case c == '(':
			depth++
		case c == ')':
			depth--
			if depth == 0 {
				return i + 1
			}
		}
	}
	return len(s)
}
