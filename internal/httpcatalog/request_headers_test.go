package httpcatalog

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

func TestRequestHeadersLoadRules(t *testing.T) {
	groundcoverCatalog(t)
	pin := `"requestHeaders":[{"name":"X-Backend-Id","values":["us-backend"]}]`
	for name, doc := range map[string]string{
		"groundcover without a pin":       strings.Replace(groundcoverEntry, pin+`,`, ``, 1),
		"groundcover pinning another one": strings.Replace(groundcoverEntry, `"name":"X-Backend-Id"`, `"name":"X-Tenant-UUID"`, 1),
		"a header the entry drops":        strings.Replace(groundcoverEntry, `"X-Backend-Id","X-Tenant-UUID"`, `"X-Tenant-UUID"`, 1),
		"the credential header":           strings.Replace(groundcoverEntry, pin, pin[:len(pin)-1]+`,{"name":"Authorization","values":["x"]}]`, 1),
		"a repeated header":               strings.Replace(groundcoverEntry, pin, pin[:len(pin)-1]+`,{"name":"x-backend-id","values":["eu-backend"]}]`, 1),
		"not a header name":               strings.Replace(groundcoverEntry, pin, pin[:len(pin)-1]+`,{"name":"X_Tenant_UUID","values":["x"]}]`, 1),
		"no values":                       strings.Replace(groundcoverEntry, `"values":["us-backend"]`, `"values":[]`, 1),
		"a repeated value":                strings.Replace(groundcoverEntry, `"values":["us-backend"]`, `"values":["us-backend","us-backend"]`, 1),
		"a value with a comma":            strings.Replace(groundcoverEntry, `"values":["us-backend"]`, `"values":["us-backend,eu-backend"]`, 1),
		"a value with a space":            strings.Replace(groundcoverEntry, `"values":["us-backend"]`, `"values":["us backend"]`, 1),
		"on a non-header entry": `{"name":"g","kind":"git","host":"github.com","pools":["pool-a"],"requestHeaders":[{"name":"X-A","values":["y"]}],
			"git":{"appID":1,"installationID":2,"repos":[{"repo":"example-org/example-app","access":"read"}]}}`,
	} {
		if _, err := Parse([]byte(`{"entries":[` + doc + `]}`)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// Another host may pin any header it forwards, or none.
	other := strings.Replace(groundcoverEntry, `"mcp.groundcover.com"`, `"api.example.com"`, 1)
	for name, doc := range map[string]string{
		"a pin":       other,
		"no pin":      strings.Replace(other, pin+`,`, ``, 1),
		"Accept":      strings.Replace(other, `"name":"X-Backend-Id"`, `"name":"Accept"`, 1),
		"two of them": strings.Replace(other, pin, pin[:len(pin)-1]+`,{"name":"X-Tenant-UUID","values":["00000000-0000-0000-0000-000000000000"]}]`, 1),
	} {
		if _, err := Parse([]byte(`{"entries":[` + doc + `]}`)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	// The name is stored canonical, so a lower-case spelling pins the same header.
	c, err := Parse([]byte(`{"entries":[` + strings.Replace(groundcoverEntry, `"name":"X-Backend-Id"`, `"name":"x-backend-id"`, 1) + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Entries()[0].RequestHeaders[0].Name; got != "X-Backend-Id" {
		t.Errorf("name %q", got)
	}
}

// Every request needs each limited header exactly once, with a listed value:
// one missing, repeated, joined with another or naming another backend is
// refused, whatever its method.
func TestRequestHeadersCheckRequests(t *testing.T) {
	e := groundcoverCatalog(t)
	header := func(values ...string) http.Header {
		h := http.Header{"Content-Type": {"application/json"}}
		for _, v := range values {
			h.Add("x-backend-id", v)
		}
		return h
	}
	if err := e.CheckRequestHeaders(header("us-backend")); err != nil {
		t.Errorf("the listed backend: %v", err)
	}
	for name, h := range map[string]http.Header{
		"missing":             header(),
		"empty":               header(""),
		"another backend":     header("eu-backend"),
		"repeated":            header("us-backend", "us-backend"),
		"listed then another": header("us-backend", "eu-backend"),
		"joined":              header("us-backend,eu-backend"),
		"another case":        header("US-BACKEND"),
		"a space around it":   header(" us-backend"),
	} {
		if err := e.CheckRequestHeaders(h); !errors.Is(err, ErrRequestHeader) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// An entry that limits no header takes any.
	other, err := Parse([]byte(`{"entries":[` + strings.Replace(strings.Replace(groundcoverEntry, `"mcp.groundcover.com"`, `"api.example.com"`, 1),
		`"requestHeaders":[{"name":"X-Backend-Id","values":["us-backend"]}],`, ``, 1) + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := other.Entries()[0].CheckRequestHeaders(header()); err != nil {
		t.Errorf("no limit: %v", err)
	}
}
