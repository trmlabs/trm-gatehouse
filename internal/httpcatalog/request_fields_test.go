package httpcatalog

import (
	"errors"
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/auditchain"
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
		"slack without a channel rule":  strings.Replace(slackEntry, `,"requestFields":[{"name":"channel","values":["C0123456789","C0987654321"]}]`, ``, 1),
		"slack with another rule only":  strings.Replace(slackEntry, `"name":"channel"`, `"name":"thread_ts"`, 1),
		"a direct message":              strings.Replace(slackEntry, `"C0987654321"`, `"D0987654321"`, 1),
		"a group conversation":          strings.Replace(slackEntry, `"C0987654321"`, `"G0987654321"`, 1),
		"a person":                      strings.Replace(slackEntry, `"C0987654321"`, `"U0987654321"`, 1),
		"a channel name":                strings.Replace(slackEntry, `"C0987654321"`, `"general"`, 1),
		"all of the Web API":            strings.Replace(slackEntry, `"/api/chat.postMessage","/api/chat.update"`, `"/api"`, 1),
		"the whole host":                strings.Replace(slackEntry, `"/api/chat.postMessage","/api/chat.update"`, `"/"`, 1),
		"a file upload":                 strings.Replace(slackEntry, `"/api/chat.update"`, `"/api/files.completeUploadExternal"`, 1),
		"an invite":                     strings.Replace(slackEntry, `"/api/chat.update"`, `"/api/conversations.invite"`, 1),
		"an ephemeral message":          strings.Replace(slackEntry, `"/api/chat.update"`, `"/api/chat.postEphemeral"`, 1),
		"a subdomain without the rule":  strings.Replace(strings.Replace(slackEntry, `"host":"slack.com"`, `"host":"api.slack.com"`, 1), `,"requestFields":[{"name":"channel","values":["C0123456789","C0987654321"]}]`, ``, 1),
		"a subdomain with another path": strings.Replace(strings.Replace(slackEntry, `"host":"slack.com"`, `"host":"api.slack.com"`, 1), `"/api/chat.update"`, `"/api/chat.postEphemeral"`, 1),
		"no values":                     strings.Replace(slackEntry, `"values":["C0123456789","C0987654321"]`, `"values":[]`, 1),
		"a repeated value":              strings.Replace(slackEntry, `"C0987654321"`, `"C0123456789"`, 1),
		"a repeated field":              strings.Replace(slackEntry, `}]}`, `},{"name":"channel","values":["C0123456789"]}]}`, 1),
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

// A Slack entry reaches only the listed message methods. A method that names
// a person or another conversation outside channel is never matched.
func TestRequestFieldsSlackMethodsOnly(t *testing.T) {
	c, err := Parse([]byte(`{"entries":[` + slackEntry + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/api/chat.postMessage", "/api/chat.update"} {
		if _, err := c.Match("slack.com", 443, "POST", path, "pool-a"); err != nil {
			t.Errorf("%s: %v", path, err)
		}
	}
	// A reaction and the two channel reads also name their one conversation in
	// channel, so an entry may list them.
	read := strings.Replace(slackEntry, `"/api/chat.postMessage","/api/chat.update"`,
		`"/api/reactions.add","/api/conversations.history","/api/conversations.replies"`, 1)
	rc, err := Parse([]byte(`{"entries":[` + strings.Replace(read, `"methods":["POST"]`, `"methods":["GET","POST"]`, 1) + `]}`))
	if err != nil {
		t.Fatalf("reaction and read methods: %v", err)
	}
	for _, path := range []string{"/api/reactions.add", "/api/conversations.history", "/api/conversations.replies"} {
		if _, err := rc.Match("slack.com", 443, "GET", path, "pool-a"); err != nil {
			t.Errorf("%s: %v", path, err)
		}
	}
	for _, path := range []string{"/api/files.completeUploadExternal", "/api/conversations.invite", "/api/chat.postEphemeral", "/api/chat.postMessageX", "/api"} {
		if _, err := c.Match("slack.com", 443, "POST", path, "pool-a"); !errors.Is(err, ErrUnlisted) {
			t.Errorf("%s: err=%v, want unlisted", path, err)
		}
	}
	sub := strings.Replace(slackEntry, `"host":"slack.com"`, `"host":"api.slack.com"`, 1)
	if _, err := Parse([]byte(`{"entries":[` + sub + `]}`)); err != nil {
		t.Errorf("subdomain with the rule and listed methods: %v", err)
	}
}

// A Slack entry names each listed method as its audit operation, one the
// audit chain accepts (a name it refuses would fail every call to that method
// as audit_unavailable); any other path or entry names none.
func TestSlackOperationNamesTheMethod(t *testing.T) {
	want := map[string]string{
		"/api/chat.postMessage":      "slack.chat_post_message",
		"/api/chat.update":           "slack.chat_update",
		"/api/reactions.add":         "slack.reactions_add",
		"/api/conversations.history": "slack.conversations_history",
		"/api/conversations.replies": "slack.conversations_replies",
	}
	if len(want) != len(slackMethods) {
		t.Fatalf("%d Slack methods, %d names checked", len(slackMethods), len(want))
	}
	slack := &Entry{Host: "slack.com"}
	for path := range slackMethods {
		got := slack.Operation(path)
		if err := (auditchain.Event{Event: auditchain.EventHTTPResponse, Operation: got}).Validate(); got != want[path] || err != nil {
			t.Errorf("%s: %q (%v), want %q", path, got, err, want[path])
		}
	}
	for name, got := range map[string]string{
		"unlisted method":  slack.Operation("/api/conversations.invite"),
		"below a method":   slack.Operation("/api/chat.postMessage/x"),
		"another host":     (&Entry{Host: "api.linear.app"}).Operation("/api/chat.postMessage"),
		"no entry matched": (*Entry)(nil).Operation("/api/chat.postMessage"),
	} {
		if got != "" {
			t.Errorf("%s: %q", name, got)
		}
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
		{"escaped key and value", "", json, `{"\u0063hannel":"\u0043\u0030123456789"}`, true},
		{"escaped unlisted value", "", json, `{"channel":"\u0044\u0030123456789"}`, false},
		{"escaped duplicate key", "", json, `{"channel":"C0123456789","\u0063hannel":"D0123456789"}`, false},
		{"listed channel in a form", "", form, "channel=C0123456789&text=hi", true},
		{"listed channel in the query", "channel=C0123456789", nil, "", true},
		{"other parameters the method takes", "channel=C0123456789&thread_ts=1700000000.000100&unfurl_links=false", nil, "", true},
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
		{"trailing garbage", "", json, `{"channel":"C0123456789"} x`, false},
		{"trailing bracket and object", "", json, `{"channel":"C0123456789"}]{"channel":"D0123456789"}`, false},
		{"trailing comma and object", "", json, `{"channel":"C0123456789"},{"channel":"D0123456789"}`, false},
		{"trailing NUL", "", json, "{\"channel\":\"C0123456789\"}\x00", false},
		{"trailing whitespace", "", json, "{\"channel\":\"C0123456789\"}\r\n\t ", true},
		{"multipart", "", []string{"multipart/form-data; boundary=x"}, "--x\r\n", false},
		{"no content type", "", nil, `{"channel":"C0123456789"}`, false},
		{"two content types", "", []string{"application/json", "application/x-www-form-urlencoded"}, `{"channel":"C0123456789"}`, false},
		{"semicolon query", "channel=C0123456789;channel=D1", nil, "", false},
		{"array key in the query", "channel=C0123456789&channel[]=D0123456789", nil, "", false},
		{"indexed key in a form", "", form, "channel=C0123456789&channel[0]=D0123456789", false},
		{"array key in the query beside a form", "channel[]=D0123456789", form, "channel=C0123456789", false},
		// A PHP-style parser drops leading spaces and cuts a name at NUL, so
		// each of these keys reaches Slack as a second channel.
		{"leading space in the query", "channel=C0123456789&%20channel=D0123456789", nil, "", false},
		{"plus as a leading space in the query", "channel=C0123456789&+channel=D0123456789", nil, "", false},
		{"leading tab in the query", "channel=C0123456789&%09channel=D0123456789", nil, "", false},
		{"trailing space in the query", "channel=C0123456789&channel%20=D0123456789", nil, "", false},
		{"NUL in the query", "channel=C0123456789&channel%00=D0123456789", nil, "", false},
		{"NUL and more in the query", "channel=C0123456789&channel%00x=D0123456789", nil, "", false},
		{"leading space in a form", "", form, "channel=C0123456789&%20channel=D0123456789", false},
		{"NUL in a form", "", form, "channel=C0123456789&channel%00=D0123456789", false},
		{"NUL and more in a form", "", form, "channel=C0123456789&channel%00x=D0123456789", false},
		{"leading space in the query beside JSON", "%20channel=D0123456789", json, `{"channel":"C0123456789"}`, false},
		{"leading space in a JSON key", "", json, `{"channel":"C0123456789"," channel":"D0123456789"}`, false},
		{"NUL in a JSON key", "", json, `{"channel":"C0123456789","channel\u0000":"D0123456789"}`, false},
		// Only the parameters the method takes, spelled exactly.
		{"a parameter the method does not take", "channel_name=x", json, `{"channel":"C0123456789"}`, false},
		{"a dot for an underscore", "channel=C0123456789&thread.ts=1700000000.000100", nil, "", false},
		{"a token parameter", "", form, "channel=C0123456789&token=x", false},
		{"another method's parameter in JSON", "", json, `{"channel":"C0123456789","timestamp":"1700000000.000100"}`, false},
	} {
		err := e.CheckRequestFields("/api/chat.postMessage", tc.query, tc.types, []byte(tc.body))
		if (err == nil) != tc.ok || (err != nil && !errors.Is(err, ErrRequestField)) {
			t.Errorf("%s: err=%v, want ok=%v", tc.name, err, tc.ok)
		}
	}
	unlimited := Entry{}
	if err := unlimited.CheckRequestFields("/", "a=1;b", []string{"x/y", "z"}, []byte("anything")); err != nil {
		t.Errorf("an entry with no request fields refused: %v", err)
	}
}

// Each listed Slack method takes the parameters Slack documents for it and no
// others, and a path that is not exactly a listed method is refused.
func TestRequestFieldsSlackMethodParameters(t *testing.T) {
	all := strings.NewReplacer(`"/api/chat.postMessage","/api/chat.update"`,
		`"/api/chat.postMessage","/api/chat.update","/api/reactions.add","/api/conversations.history","/api/conversations.replies"`,
		`"methods":["POST"]`, `"methods":["GET","POST"]`).Replace(slackEntry)
	c, err := Parse([]byte(`{"entries":[` + all + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	e := c.Entries()[0]
	form := []string{"application/x-www-form-urlencoded"}
	for _, tc := range []struct {
		path, query, body string
		ok                bool
	}{
		{"/api/chat.update", "", "channel=C0123456789&ts=1700000000.000100&text=done", true},
		{"/api/reactions.add", "", "channel=C0123456789&name=white_check_mark&timestamp=1700000000.000100", true},
		{"/api/conversations.history", "channel=C0123456789&limit=20&cursor=dXNlcjpVMDYx&oldest=1700000000", "", true},
		{"/api/conversations.replies", "channel=C0123456789&ts=1700000000.000100&limit=50", "", true},
		{"/api/chat.postMessage", "", "channel=C0123456789&ts=1700000000.000100&text=x", false},
		{"/api/reactions.add", "", "channel=C0123456789&name=eyes&file=F0123456789", false},
		{"/api/conversations.history", "channel=C0123456789&ts=1700000000.000100", "", false},
		{"/api/chat.postMessage/x", "", "channel=C0123456789&text=x", false},
		{"/api/chat.postMessage/", "", "channel=C0123456789&text=x", false},
	} {
		types := form
		if tc.body == "" {
			types = nil
		}
		err := e.CheckRequestFields(tc.path, tc.query, types, []byte(tc.body))
		if (err == nil) != tc.ok || (err != nil && !errors.Is(err, ErrRequestField)) {
			t.Errorf("%s %q %q: err=%v, want ok=%v", tc.path, tc.query, tc.body, err, tc.ok)
		}
	}
}

// Another vendor's entry takes any plain key, but never one with whitespace,
// a control byte or a bracket, which some parser could read as the limited
// name.
func TestRequestFieldsOtherVendorKeys(t *testing.T) {
	other := strings.NewReplacer(`"host":"slack.com"`, `"host":"api.example.com"`, `"pathPrefixes":["/api/chat.postMessage","/api/chat.update"]`,
		`"pathPrefixes":["/v1"]`, `"name":"channel"`, `"name":"teamId"`).Replace(slackEntry)
	c, err := Parse([]byte(`{"entries":[` + other + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	e := c.Entries()[0]
	json := []string{"application/json"}
	form := []string{"application/x-www-form-urlencoded"}
	for _, tc := range []struct {
		name, query string
		types       []string
		body        string
		ok          bool
	}{
		{"plain keys", "teamId=C0123456789&teamId_name=x&first=10", nil, "", true},
		{"plain JSON keys", "", json, `{"teamId":"C0123456789","query":"{ issues { id } }"}`, true},
		{"leading space", "teamId=C0123456789&%20teamId=C0987654321", nil, "", false},
		{"NUL", "", form, "teamId=C0123456789&teamId%00=C0987654321", false},
		{"array key", "teamId=C0123456789&teamId[]=C0987654321", nil, "", false},
		{"bracket in another key", "teamId=C0123456789&filter[state]=open", nil, "", false},
		{"leading space in a JSON key", "", json, `{"teamId":"C0123456789"," teamId":"C0987654321"}`, false},
	} {
		err := e.CheckRequestFields("/v1/graphql", tc.query, tc.types, []byte(tc.body))
		if (err == nil) != tc.ok || (err != nil && !errors.Is(err, ErrRequestField)) {
			t.Errorf("%s: err=%v, want ok=%v", tc.name, err, tc.ok)
		}
	}
}
