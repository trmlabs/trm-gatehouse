package decoy

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// Synthetic decoys; never real credentials.
const (
	decoyToken = "synthetic-decoy-token-4f9c2a7e1b"
	decoyKey   = "synthetic_decoy_key_0d8b3e6a5c27f1"
)

func testSet(t *testing.T) *Set {
	t.Helper()
	set, rejected := NewSet(map[string]string{"pool-a/github_token": decoyToken, "pool-b/litellm_key": decoyKey})
	if len(rejected) > 0 || set.Len() != 2 {
		t.Fatalf("set: %d %+v", set.Len(), rejected)
	}
	return set
}

func request(t *testing.T, target string, header http.Header) *http.Request {
	t.Helper()
	r, err := http.NewRequest(http.MethodPost, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, values := range header {
		r.Header[name] = values
	}
	return r
}

func basic(user, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+password))
}

// Each place a request can carry a credential reports the decoy's label and
// that place.
func TestRequestFindsADecoyOnEverySurface(t *testing.T) {
	set := testSet(t)
	for _, tc := range []struct {
		name, target string
		header       http.Header
		label        string
		surface      string
	}{
		{"bearer", "https://api.example.com/v1", http.Header{"Authorization": {"Bearer " + decoyToken}}, "pool-a/github_token", SurfaceHeader},
		{"token scheme", "https://api.example.com/v1", http.Header{"Authorization": {"token " + decoyToken}}, "pool-a/github_token", SurfaceHeader},
		{"bare header", "https://api.example.com/v1", http.Header{"X-Api-Key": {decoyKey}}, "pool-b/litellm_key", SurfaceHeader},
		{"cookie", "https://api.example.com/v1", http.Header{"Cookie": {"a=1; session=" + decoyKey}}, "pool-b/litellm_key", SurfaceHeader},
		{"basic password, as git sends a token", "https://git.example.com/r.git/info/refs", http.Header{"Authorization": {basic("x-access-token", decoyToken)}}, "pool-a/github_token", SurfaceHeader},
		{"basic user", "https://api.example.com/v1", http.Header{"Authorization": {basic(decoyKey, "")}}, "pool-b/litellm_key", SurfaceHeader},
		{"basic unpadded, lower-case scheme", "https://api.example.com/v1", http.Header{"Authorization": {"basic " + base64.RawStdEncoding.EncodeToString([]byte("u:"+decoyToken))}}, "pool-a/github_token", SurfaceHeader},
		{"proxy password", "https://api.example.com/v1", http.Header{"Proxy-Authorization": {basic(decoyToken, "vault")}}, "pool-a/github_token", SurfaceHeader},
		{"query", "https://api.example.com/v1?a=1&api_key=" + decoyKey, nil, "pool-b/litellm_key", SurfaceQuery},
		{"percent-encoded query", "https://api.example.com/v1?token=%73" + decoyToken[1:], nil, "pool-a/github_token", SurfaceQuery},
		{"path", "https://hooks.example.com/services/" + decoyToken + "/send", nil, "pool-a/github_token", SurfacePath},
		{"user info", "http://x:" + decoyToken + "@api.example.com/v1", nil, "pool-a/github_token", SurfaceUserinfo},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, ok := set.Request(request(t, tc.target, tc.header))
			if !ok || m.Label != tc.label || m.Surface != tc.surface {
				t.Fatalf("got %+v %v, want %s on %s", m, ok, tc.label, tc.surface)
			}
		})
	}
}

func TestBodyAndPasswordFindADecoy(t *testing.T) {
	set := testSet(t)
	for _, body := range []string{
		`{"token":"` + decoyToken + `"}`,
		`a=1&client_secret=` + decoyToken,
		`a=1&client_secret=%73` + decoyToken[1:],
		"export GITHUB=" + decoyToken + "\n",
		"here it is: " + decoyToken + ".",
		`{"token":"\u0073` + decoyToken[1:] + `"}`,
		`{"token":"\u0073\u0079` + decoyToken[2:] + `"}`,
	} {
		if m, ok := set.Body([]byte(body)); !ok || m.Label != "pool-a/github_token" || m.Surface != SurfaceBody {
			t.Fatalf("body %q: %+v %v", body, m, ok)
		}
	}
	if m, ok := set.Password(decoyKey); !ok || m.Label != "pool-b/litellm_key" || m.Surface != SurfacePassword {
		t.Fatalf("password: %+v %v", m, ok)
	}
}

// A JSON control escape ends the text before a decoy: the escape's letter
// would otherwise run into it, as "out:\n<decoy>" did.
func TestJSONControlEscapeBeforeADecoy(t *testing.T) {
	set := testSet(t)
	for _, escape := range []string{`\n`, `\r`, `\t`, `\b`, `\f`} {
		body := `{"text":"out:` + escape + decoyToken + `"}`
		if m, ok := set.Body([]byte(body)); !ok || m.Label != "pool-a/github_token" {
			t.Errorf("body %q: %+v %v", body, m, ok)
		}
	}
	if m, ok := set.Body([]byte(`{"text":"out:\\n` + decoyToken + `"}`)); ok {
		t.Errorf("an escaped backslash then n matched %+v", m)
	}
}

// Only a whole decoy matches: not a part of one, not one inside a longer run
// of the same characters, and not one character off.
func TestOnlyAWholeDecoyMatches(t *testing.T) {
	set := testSet(t)
	near := []byte(decoyToken)
	near[len(near)-1] ^= 1
	for _, body := range []string{
		decoyToken[:len(decoyToken)-1],
		"x" + decoyToken,
		decoyToken + "x",
		decoyToken + "_suffix",
		string(near),
		"__vault_GITHUB_TOKEN__",
		strings.Repeat("a", 4096),
		`\\u0073` + decoyToken[1:],
		`\u00` + decoyToken,
		"",
	} {
		if m, ok := set.Body([]byte(body)); ok {
			t.Fatalf("body %q matched %+v", body, m)
		}
	}
	r := request(t, "https://api.example.com/v1?q=1", http.Header{"Authorization": {"Bearer __vault_GITHUB_TOKEN__"}, "Content-Type": {"application/json"}})
	if m, ok := set.Request(r); ok {
		t.Fatalf("ordinary request matched %+v", m)
	}
}

// A nil or empty set recognizes nothing and costs nothing.
func TestEmptySetMatchesNothing(t *testing.T) {
	var none *Set
	empty, _ := NewSet(nil)
	r := request(t, "https://api.example.com/"+decoyToken, http.Header{"Authorization": {"Bearer " + decoyToken}})
	for _, s := range []*Set{none, empty} {
		if _, ok := s.Request(r); ok {
			t.Fatal("request matched")
		}
		if _, ok := s.Body([]byte(decoyToken)); ok {
			t.Fatal("body matched")
		}
		if _, ok := s.Password(decoyToken); ok {
			t.Fatal("password matched")
		}
	}
	if _, ok := none.Request(nil); ok {
		t.Fatal("nil request matched")
	}
}

// A value that could match ordinary traffic, or that the scanner could not
// see whole, is left out and named by label only.
func TestNewSetRejectsUnsafeValues(t *testing.T) {
	values := map[string]string{
		"p/short":       "abc",
		"p/long":        strings.Repeat("a", MaxLength+1),
		"p/space":       "synthetic decoy with spaces",
		"p/slash":       "synthetic/decoy/with/slashes",
		"p/placeholder": "x__vault_GITHUB_TOKEN__x",
		"p/a_first":     decoyToken,
		"p/b_repeat":    decoyToken,
		"p/min":         strings.Repeat("m", MinLength),
		"p/max":         strings.Repeat("M", MaxLength),
	}
	set, rejected := NewSet(values)
	if set.Len() != 3 {
		t.Fatalf("kept %d", set.Len())
	}
	got := map[string]string{}
	for _, r := range rejected {
		got[r.Label] = r.Reason
		for _, v := range values {
			if len(v) >= 3 && strings.Contains(r.Reason, v) {
				t.Fatalf("reason carries a value: %+v", r)
			}
		}
	}
	for _, label := range []string{"p/short", "p/long", "p/space", "p/slash", "p/placeholder", "p/b_repeat"} {
		if got[label] == "" {
			t.Fatalf("%s not rejected: %+v", label, rejected)
		}
	}
	for _, v := range []string{decoyToken, strings.Repeat("m", MinLength), strings.Repeat("M", MaxLength)} {
		if _, ok := set.Body([]byte(" " + v + " ")); !ok {
			t.Fatalf("kept value of length %d not found", len(v))
		}
	}
}

// The set scales to a fleet's worth of decoys: every one is found, and a body
// scan stays one pass over the bytes.
func TestLargeSet(t *testing.T) {
	const n = 100_000
	values := make(map[string]string, n)
	for i := range n {
		values[fmt.Sprintf("pool-%d/key", i)] = fmt.Sprintf("synthetic-decoy-%08d-%s", i, strings.Repeat("z", i%40))
	}
	set, rejected := NewSet(values)
	if len(rejected) > 0 || set.Len() != n {
		t.Fatalf("set %d rejected %d", set.Len(), len(rejected))
	}
	for _, i := range []int{0, 1, 12345, n - 1} {
		want := fmt.Sprintf("pool-%d/key", i)
		if m, ok := set.Body([]byte("x " + values[want] + " y")); !ok || m.Label != want {
			t.Fatalf("decoy %d: %+v %v", i, m, ok)
		}
	}
	// Runs the length of a decoy are hashed and looked up; none is one.
	body := []byte(strings.Repeat(`{"content":"synthetic-decoy-99999999- plain text"} `, 20_000))
	if m, ok := set.Body(body); ok {
		t.Fatalf("clean body matched %+v", m)
	}
}

func BenchmarkBodyScan(b *testing.B) {
	values := make(map[string]string, 10_000)
	for i := range 10_000 {
		values[fmt.Sprintf("pool-%d/key", i)] = fmt.Sprintf("synthetic-decoy-%08d-abcdefgh", i)
	}
	set, _ := NewSet(values)
	body := []byte(strings.Repeat(`{"role":"user","content":"a message of ordinary words and identifiers_like_these"} `, 12_000))
	b.SetBytes(int64(len(body)))
	for b.Loop() {
		set.Body(body)
	}
}

func TestPercentDecodeKeepsMalformedEscapes(t *testing.T) {
	for in, want := range map[string]string{"a%41b": "aAb", "%": "%", "%4": "%4", "%zz1": "%zz1", "100%": "100%", "%2f%2F": "//"} {
		if got := string(percentDecode([]byte(in))); got != want {
			t.Fatalf("%q: %q, want %q", in, got, want)
		}
	}
}
