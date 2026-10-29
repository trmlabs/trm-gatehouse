package httpcatalog

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
)

// An Automation's plain settings load with its block and come back as given.
func TestAutomationSettingsLoad(t *testing.T) {
	c := automationCatalog()
	settings := map[string]any{"API_BASE": "https://api.example.com/v1", "AGENT_USER_IDS": "agent-1,agent-2", "EMPTY": "", "mode": "staging"}
	c["automations"].([]any)[0].(map[string]any)["settings"] = settings
	catalog, err := parseCatalog(t, c)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := catalog.Automation("auto-1")
	if len(a.Settings) != 4 || a.Settings["API_BASE"] != "https://api.example.com/v1" || a.Settings["EMPTY"] != "" {
		t.Fatalf("%+v", a.Settings)
	}
	if b, _ := catalog.Automation("auto-2"); b.Settings != nil {
		t.Fatalf("a block without settings has %+v", b.Settings)
	}
	if got := strings.Join(SettingNames(a.Settings), ","); got != "AGENT_USER_IDS,API_BASE,EMPTY,mode" {
		t.Fatalf("names %s", got)
	}
}

// Settings are configuration, never secrets or the runtime's own names: each
// refusal drops only that Automation from a tolerant load, and its reason
// never quotes the value.
func TestAutomationSettingsRefused(t *testing.T) {
	ghToken := "gh" + "p_" + strings.Repeat("a", 36)
	for name, settings := range map[string]map[string]any{
		"token in the name":           {"SERVICE_TOKEN": "x"},
		"key in the name":             {"api_key": "x"},
		"key inside a word":           {"MONKEY": "x"},
		"secret in the name":          {"ClientSecret": "x"},
		"password in the name":        {"DB_PASSWORD": "x"},
		"passwd in the name":          {"PASSWD_FILE": "x"},
		"credential in the name":      {"GOOGLE_CREDENTIALS": "x"},
		"private in the name":         {"PRIVATE_URL": "x"},
		"placeholder value":           {"API_BASE": "https://__vault_API_KEY__@api.example.com"},
		"placeholder any case":        {"API_BASE": "__VAULT_API__"},
		"gatehouse name":              {"GATEHOUSE_HTTPS_PROXY": "http://127.0.0.1:1"},
		"vendor runtime name":         {"CURSOR_AGENT": "1"},
		"broker name":                 {"AGENT_VAULT_ADDR": "x"},
		"path":                        {"PATH": "/tmp"},
		"lower-case path":             {"path": "/tmp"},
		"home":                        {"HOME": "/tmp"},
		"bash env":                    {"BASH_ENV": "/tmp/x"},
		"posix env":                   {"ENV": "/tmp/x"},
		"bash function":               {"BASH_FUNC_x%%": "() { :; }"},
		"proxy":                       {"https_proxy": "http://proxy.example.com"},
		"no proxy":                    {"NO_PROXY": "*"},
		"loader":                      {"LD_PRELOAD": "/tmp/x.so"},
		"git":                         {"GIT_SSH_COMMAND": "sh"},
		"trust":                       {"SSL_CERT_FILE": "/tmp/ca"},
		"node options":                {"NODE_OPTIONS": "--require /tmp/x"},
		"cluster":                     {"KUBERNETES_SERVICE_HOST": "10.0.0.1"},
		"mac loader":                  {"DYLD_INSERT_LIBRARIES": "/tmp/x.dylib"},
		"ruby options":                {"RUBYOPT": "-r/tmp/x"},
		"java options":                {"JAVA_TOOL_OPTIONS": "-javaagent:/tmp/x.jar"},
		"requests bundle":             {"REQUESTS_CA_BUNDLE": "/tmp/ca"},
		"curl bundle":                 {"CURL_CA_BUNDLE": "/tmp/ca"},
		"node tls":                    {"NODE_TLS_REJECT_UNAUTHORIZED": "0"},
		"go flags":                    {"GOFLAGS": "-mod=mod"},
		"go proxy":                    {"goproxy": "https://proxy.example.com"},
		"go sum database":             {"GONOSUMDB": "*"},
		"go private":                  {"GOPRIVATE": "example.com"},
		"go no sum check":             {"GONOSUMCHECK": "1"},
		"go insecure":                 {"GOINSECURE": "example.com"},
		"pip index":                   {"PIP_INDEX_URL": "https://pypi.example.com"},
		"uv index":                    {"UV_INDEX_URL": "https://pypi.example.com"},
		"npm registry":                {"NPM_CONFIG_REGISTRY": "https://npm.example.com"},
		"xdg config":                  {"XDG_CONFIG_HOME": "/tmp/x"},
		"perl lib":                    {"PERLLIB": "/tmp/x"},
		"perl5 lib":                   {"PERL5LIB": "/tmp/x"},
		"python warnings":             {"PYTHONWARNINGS": "ignore"},
		"python path":                 {"PYTHONPATH": "/tmp/x"},
		"name with a dash":            {"API-BASE": "x"},
		"name starting with a digit":  {"1API": "x"},
		"long name":                   {strings.Repeat("A", 129): "x"},
		"newline in the value":        {"API_BASE": "a\nb"},
		"nul in the value":            {"API_BASE": "a\x00b"},
		"pem block":                   {"CERT": "-----BEGIN CERTIFICATE-----"},
		"github token value":          {"API_BASE": ghToken},
		"jwt value":                   {"API_BASE": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln"},
		"url with a password":         {"API_BASE": "https://user:hunter2@api.example.com"},
		"aws key value":               {"BUCKET": "AKIA" + strings.Repeat("A", 16)},
		"value over the default size": {"BIG": strings.Repeat("x", DefaultSettingsMaxBytes)},
	} {
		c := automationCatalog()
		c["automations"] = append(c["automations"].([]any), map[string]any{"id": "auto-9", "name": "x", "owner": "platform-team", "entries": []any{"vendor"}, "settings": settings})
		_, err := parseCatalog(t, c)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		for _, value := range settings {
			if v := value.(string); len(v) > 3 && strings.Contains(err.Error(), v) {
				t.Errorf("%s: the error quotes the value: %v", name, err)
			}
		}
		data, _ := json.Marshal(c)
		catalog, dropped, err := ParseTolerant(data)
		if err != nil {
			t.Fatalf("%s: tolerant: %v", name, err)
		}
		if catalog.Automations() != 2 || len(dropped) != 1 || dropped[0].Kind != "automation" || dropped[0].Name != "auto-9" {
			t.Errorf("%s: kept %d, dropped %+v", name, catalog.Automations(), dropped)
		}
	}
}

// A value that is not UTF-8 cannot arrive in JSON, which replaces the bytes,
// but the sidecar checks what the broker sends with the same function.
func TestSettingValueMustBeText(t *testing.T) {
	if err := CheckSetting("API_BASE", "a\xffb"); err == nil {
		t.Fatal("invalid UTF-8: accepted")
	}
	if err := CheckSetting("API_BASE", "a\tb"); err == nil {
		t.Fatal("a tab: accepted")
	}
	if err := CheckSetting("API_BASE", "https://api.example.com/v1?x=1 & y='2'"); err != nil {
		t.Fatalf("plain text: %v", err)
	}
}

// The size limit counts names and values together, is configurable within
// its bounds, and holds a large catalog's worth of plain settings.
func TestAutomationSettingsSizeLimit(t *testing.T) {
	t.Cleanup(func() { _ = SetSettingsMaxBytes("") })
	fill := func(n int) map[string]string {
		s := map[string]string{}
		for i := 0; n > 0; i++ {
			name := "S" + strconv.Itoa(i)
			value := strings.Repeat("v", min(1000, max(0, n-len(name))))
			s[name] = value
			n -= len(name) + len(value)
		}
		return s
	}
	if err := CheckSettings(fill(DefaultSettingsMaxBytes), SettingsMaxBytes()); err != nil {
		t.Fatalf("at the default limit: %v", err)
	}
	if err := CheckSettings(fill(DefaultSettingsMaxBytes+1), SettingsMaxBytes()); err == nil {
		t.Fatal("over the default limit: accepted")
	}
	for _, bad := range []string{"0", "1023", strconv.Itoa(MaxSettingsMaxBytes + 1), "64KiB", "-1"} {
		if err := SetSettingsMaxBytes(bad); err == nil || !strings.Contains(err.Error(), SettingsMaxBytesEnv) {
			t.Errorf("%s: %v", bad, err)
		}
	}
	if err := SetSettingsMaxBytes(strconv.Itoa(MaxSettingsMaxBytes)); err != nil {
		t.Fatal(err)
	}
	if err := CheckSettings(fill(MaxSettingsMaxBytes), SettingsMaxBytes()); err != nil {
		t.Fatalf("at the raised limit: %v", err)
	}
	if err := SetSettingsMaxBytes("2048"); err != nil {
		t.Fatal(err)
	}
	c := automationCatalog()
	c["automations"].([]any)[0].(map[string]any)["settings"] = map[string]any{"API_BASE": strings.Repeat("x", 2048)}
	if _, err := parseCatalog(t, c); err == nil || !strings.Contains(err.Error(), "2048") {
		t.Fatalf("over a lowered limit: %v", err)
	}
}

// 10,000 Automations, each with a few settings, load through the tolerant
// path the broker uses.
func TestTenThousandAutomationsWithSettingsLoad(t *testing.T) {
	c := automationCatalog()
	list := make([]any, 10000)
	for i := range list {
		list[i] = map[string]any{"id": "automation-" + strconv.Itoa(i), "name": "a" + strconv.Itoa(i), "owner": "platform-team", "entries": []any{"tracker"},
			"settings": map[string]any{"API_BASE": "https://api.example.com/" + strconv.Itoa(i), "AGENT_USER_IDS": "agent-" + strconv.Itoa(i), "MODE": "staging"}}
	}
	c["automations"] = list
	data, _ := json.Marshal(c)
	catalog, dropped, err := ParseTolerant(data)
	if err != nil || len(dropped) != 0 || catalog.Automations() != 10000 {
		t.Fatalf("%v, dropped %d, kept %d", err, len(dropped), catalog.Automations())
	}
	if a, _ := catalog.Automation("automation-9999"); a.Settings["API_BASE"] != "https://api.example.com/9999" {
		t.Fatalf("%+v", a.Settings)
	}
}
