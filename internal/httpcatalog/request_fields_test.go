package httpcatalog

import (
	"errors"
	"strings"
	"testing"
)

const slackEntry = `{"name":"slack","host":"slack.com","pathPrefixes":["/api/chat.postMessage","/api/chat.update"],"methods":["POST"],
	"header":"Authorization","scheme":"Bearer","placeholder":"__vault_SLACK__","key":{"mount":"gatehouse","path":"vendors/slack","field":"key"},
	"pools":["pool-a"],"requestFields":[{"name":"channel","values":["C0123456789","C0987654321"]}]}`

func slackCatalog(t *testing.T) *Entry {
	t.Helper()
	c, err := Parse([]byte(`{"entries":[` + slackEntry + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	e := c.Entries()[0]
	return &e
}

func TestRequestFieldsLoadRules(t *testing.T) {
	slackCatalog(t)
	for name, doc := range map[string]string{
		"slack without a channel rule": strings.Replace(slackEntry, `,"requestFields":[{"name":"channel","values":["C0123456789","C0987654321"]}]`, ``, 1),
		"slack with another rule only": strings.Replace(slackEntry, `"name":"channel"`, `"name":"thread_ts"`, 1),
		"a direct message":             strings.Replace(slackEntry, `"C0987654321"`, `"D0987654321"`, 1),
		"a group conversation":         strings.Replace(slackEntry, `"C0987654321"`, `"G0987654321"`, 1),
		"a person":                     strings.Replace(slackEntry, `"C0987654321"`, `"U0987654321"`, 1),
		"a channel name":               strings.Replace(slackEntry, `"C0987654321"`, `"#general"`, 1),
		"no values":                    strings.Replace(slackEntry, `"values":["C0123456789","C0987654321"]`, `"values":[]`, 1),
		"a repeated value":             strings.Replace(slackEntry, `"C0987654321"`, `"C0123456789"`, 1),
		"a repeated field":             strings.Replace(slackEntry, `}]}`, `},{"name":"channel","values":["C0123456789"]}]}`, 1),
		"on a non-header entry": `{"name":"g","kind":"git","host":"github.com","pools":["pool-a"],"requestFields":[{"name":"x","values":["y"]}],
			"git":{"appID":1,"installationID":2,"repos":[{"repo":"example-org/example-app","access":"read"}]}}`,
	} {
		if _, err := Parse([]byte(`{"entries":[` + doc + `]}`)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// Another vendor may limit any field, or none.
	other := strings.NewReplacer(`"host":"slack.com"`, `"host":"api.linear.app"`, `"name":"channel"`, `"name":"teamId"`).Replace(slackEntry)
	if _, err := Parse([]byte(`{"entries":[` + other + `]}`)); err != nil {
		t.Errorf("non-Slack entry: %v", err)
	}
}

func TestRequestFieldsCheckRequests(t *testing.T) {
	e := slackCatalog(t)
	json := []string{"application/json; charset=utf-8"}
	form := []string{"application/x-www-form-urlencoded"}
	for _, tc := range []struct {
		name, query string
		types       []string
		body        string
		ok          bool
	}{
		{"listed channel in JSON", "", json, `{"channel":"C0123456789","text":"run done"}`, true},
		{"second listed channel", "", json, `{"text":"x","channel":"C0987654321","blocks":[{"channel":"D1"}]}`, true},
		{"escaped key and value", "", json, `{"channel":"C0123456789"}`, true},
		{"listed channel in a form", "", form, "channel=C0123456789&text=hi", true},
		{"listed channel in the query", "channel=C0123456789", nil, "", true},
		{"unlisted channel", "", json, `{"channel":"C1111111111"}`, false},
		{"a person", "", json, `{"channel":"U0123456789"}`, false},
		{"no channel", "", json, `{"text":"x"}`, false},
		{"duplicate JSON key", "", json, `{"channel":"C0123456789","channel":"D0123456789"}`, false},
		{"query and body", "channel=C0123456789", json, `{"channel":"C0123456789"}`, false},
		{"twice in a form", "", form, "channel=C0123456789&channel=D1", false},
		{"twice in the query", "channel=C0123456789&channel=C0123456789", nil, "", false},
		{"not a string", "", json, `{"channel":["C0123456789"]}`, false},
		{"not an object", "", json, `[{"channel":"C0123456789"}]`, false},
		{"trailing data", "", json, `{"channel":"C0123456789"}{"channel":"D1"}`, false},
		{"multipart", "", []string{"multipart/form-data; boundary=x"}, "--x\r\n", false},
		{"no content type", "", nil, `{"channel":"C0123456789"}`, false},
		{"two content types", "", []string{"application/json", "application/x-www-form-urlencoded"}, `{"channel":"C0123456789"}`, false},
		{"semicolon query", "channel=C0123456789;channel=D1", nil, "", false},
	} {
		err := e.CheckRequestFields(tc.query, tc.types, []byte(tc.body))
		if (err == nil) != tc.ok || (err != nil && !errors.Is(err, ErrRequestField)) {
			t.Errorf("%s: err=%v, want ok=%v", tc.name, err, tc.ok)
		}
	}
	unlimited := Entry{}
	if err := unlimited.CheckRequestFields("a=1;b", []string{"x/y", "z"}, []byte("anything")); err != nil {
		t.Errorf("an entry with no request fields refused: %v", err)
	}
}
