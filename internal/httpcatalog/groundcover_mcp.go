package httpcatalog

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"regexp"
	"unicode/utf8"
)

// groundcover's hosted MCP server answers every tool on one path, so an
// entry's paths and methods cannot tell one tool from another. A groundcover
// key's data scope limits what most tools read, but groundcover does not
// apply it to every tool: monitor issues, for one, come back for every
// cluster and backend the tenant has. So for this host the broker reads each
// request's JSON-RPC message and forwards only the ones a query client sends
// to run the log and metric tools: initialize, the initialized notification
// and a tools/call naming query_logs or query_metrics. Every other method or
// tool is refused, tools/list included, as are a batch, a repeated or
// unknown key, a body it cannot read as one message, and an argument naming
// gcQL's _from, through which a log query reads another signal. A GET (the
// server's event stream) and a DELETE (ending the session) carry no message
// and pass with no body.
const (
	groundcoverMCPHost = "mcp.groundcover.com"
	groundcoverMCPPath = "/api/mcp"
	// groundcoverMCPDepth bounds how deeply a message nests, far above what
	// a tool call's arguments need.
	groundcoverMCPDepth = 32
)

// groundcoverMCPMethods maps each JSON-RPC method the broker forwards to the
// operation its audit row names; a tools/call row names its tool instead.
var groundcoverMCPMethods = map[string]string{
	"initialize":                "groundcover.initialize",
	"notifications/initialized": "groundcover.initialized",
	"tools/call":                "",
}

// groundcoverMCPTools maps each tool a tools/call may name to its operation.
var groundcoverMCPTools = map[string]string{
	"query_logs":    "groundcover.query_logs",
	"query_metrics": "groundcover.query_metrics",
}

// groundcoverCrossSignal matches gcQL's _from, in any case and not as part
// of a longer name. A query_logs subquery (in join, union or in()) reads
// another signal through it, monitor issues among them, which the key's data
// scope does not hold. A client that never correlates signals never sends it.
var groundcoverCrossSignal = regexp.MustCompile(`(?i)(?:^|[^a-z0-9_])_from(?:[^a-z0-9_]|$)`)

// The refusals CheckMCP returns: ErrMCPShape for a request it cannot read as
// one message on the server's path, ErrMCPTool for a method or tool it does
// not forward, ErrMCPArgument for a tool argument naming _from.
var (
	ErrMCPShape    = errors.New("not one MCP message the broker reads")
	ErrMCPTool     = errors.New("MCP method or tool not forwarded")
	ErrMCPArgument = errors.New("MCP tool argument not forwarded")
)

// CheckMCP holds a request to groundcover's MCP server to the messages the
// broker forwards, and returns the operation its audit row names. It allows
// every request to any other host. method is the HTTP method, path and
// rawQuery the request's, contentTypes every Content-Type value and body the
// whole request body.
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
	if mcpMentions(call["arguments"], groundcoverCrossSignal) {
		return "", ErrMCPArgument
	}
	return operation, nil
}

// mcpMentions reports whether any key or string anywhere in v matches re.
func mcpMentions(v any, re *regexp.Regexp) bool {
	switch t := v.(type) {
	case string:
		return re.MatchString(t)
	case map[string]any:
		for key, value := range t {
			if re.MatchString(key) || mcpMentions(value, re) {
				return true
			}
		}
	case []any:
		for _, value := range t {
			if mcpMentions(value, re) {
				return true
			}
		}
	}
	return false
}

// mcpMessage decodes body as one JSON object in valid UTF-8 with no key
// repeated at any depth, nested at most groundcoverMCPDepth deep, and no
// string holding a control byte other than tab, newline and carriage return
// or U+FFFD (which a lone surrogate escape decodes to). Another parser could
// read a repeated key, a cut string or a dropped byte differently from this
// one, so the broker would check one message and the server act on another.
// Numbers stay json.Number.
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

// mcpPlainString reports whether s holds no control byte other than tab,
// newline and carriage return, and no U+FFFD.
func mcpPlainString(s string) bool {
	for _, r := range s {
		if (r < 0x20 && r != '\t' && r != '\n' && r != '\r') || r == 0x7f || r == utf8.RuneError {
			return false
		}
	}
	return true
}
