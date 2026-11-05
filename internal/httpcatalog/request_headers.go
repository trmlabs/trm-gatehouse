package httpcatalog

import (
	"errors"
	"fmt"
	"net/http"
)

// RequestHeader limits one request header of a header entry to listed values: exactly once on every request, and one the entry forwards. A groundcover MCP entry should limit X-Backend-Id, since the key alone may reach every backend; the broker still serves one without the limit, and the catalog's own checks require it.
type RequestHeader struct {
	Name   string   `json:"name"`
	Values []string `json:"values"`
}

var ErrRequestHeader = errors.New("request header not allowed")

func (e *Entry) normalizeRequestHeaders() error {
	seen := map[string]bool{}
	for i, h := range e.RequestHeaders {
		name := http.CanonicalHeaderKey(h.Name)
		if !tokenPattern.MatchString(h.Name) || seen[name] || name == e.Header || !e.ForwardsHeader(name) {
			return fmt.Errorf("request header %q must be a distinct header the entry forwards, not its credential header", h.Name)
		}
		seen[name] = true
		e.RequestHeaders[i].Name = name
		if len(h.Values) == 0 {
			return fmt.Errorf("request header %q lists no values", name)
		}
		values := map[string]bool{}
		for _, v := range h.Values {
			if !requestFieldValue.MatchString(v) || values[v] {
				return fmt.Errorf("request header %q value %q must be distinct and plain", name, v)
			}
			values[v] = true
		}
	}
	return nil
}

func (e *Entry) CheckRequestHeaders(h http.Header) error {
	for _, rh := range e.RequestHeaders {
		values := h.Values(rh.Name)
		if len(values) != 1 || !contains(rh.Values, values[0]) {
			return ErrRequestHeader
		}
	}
	return nil
}
