package mitm

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/auditchain"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/httpcatalog"
	"github.com/Infisical/agent-vault/internal/ratelimit"
)

type failingAudit struct{}

func (failingAudit) Admit() error                  { return nil }
func (failingAudit) Record(auditchain.Event) error { return auditchain.ErrCheckpointOverdue }

// Every refusal names its reason in a header and the body, a passing one
// answers 503 or 429 with Retry-After, a lasting one keeps its 4xx or answers
// 503 without Retry-After, and the audit row records the status the agent was
// sent. Each lasting cause behind a code that is otherwise passing has its own
// lasting code.
func TestRefusalNamesItsReason(t *testing.T) {
	cases := []struct {
		name, outcome, as string // as: the code given apart from the outcome
		in                int
		wait              time.Duration
		code              string
		status            int
		retryAfter        string
		closes            bool
	}{
		{"no session yet passes on a new connection", "session_missing", "", 403, 0, "session_missing", 503, "5", true},
		{"directory unavailable passes", "entitlement_unavailable", "", 403, 0, "entitlement_unavailable", 503, "5", false},
		{"no directory configured lasts", "entitlement_config", "", 403, 0, "entitlement_config", 403, "", false},
		{"directory budget passes", "entitlement_rate_limited", "", 403, 0, "entitlement_rate_limited", 429, "60", false},
		{"token mint passes", "token_unavailable", "", 503, 0, "token_unavailable", 503, "5", false},
		{"no minter lasts", "token_unavailable", "broker_misconfigured", 503, 0, "broker_misconfigured", 503, "", false},
		{"key read passes", "key_unavailable", "", 503, 0, "key_unavailable", 503, "5", false},
		{"deleted key lasts", "key_deleted", "", 503, 0, "key_deleted", 503, "", false},
		{"unsafe key lasts", "key_not_header_safe", "", 503, 0, "key_not_header_safe", 503, "", false},
		{"a key that is not a Basic pair lasts", "key_not_basic_pair", "", 503, 0, "key_not_basic_pair", 503, "", false},
		{"seed passes", "seed_unavailable", "", 503, 0, "seed_unavailable", 503, "5", false},
		{"seed deadline lasts", "seed_deadline", "", 503, 0, "seed_deadline", 503, "", false},
		{"a misconfigured broker lasts", "broker_misconfigured", "", 503, 0, "broker_misconfigured", 503, "", false},
		{"not entitled lasts", "not_entitled", "", 403, 0, "not_entitled", 403, "", false},
		{"no directory account lasts", "not_in_directory", "", 403, 0, "not_in_directory", 403, "", false},
		{"no person lasts", "no_person", "", 403, 0, "no_person", 403, "", false},
		{"another pool's host reads as unlisted", "pool", "", 403, 0, "unlisted", 403, "", false},
		{"unlisted", "unlisted", "", 403, 0, "unlisted", 403, "", false},
		{"method keeps 405", "method", "", 405, 0, "method", 405, "", false},
		{"rate limit with no limiter wait still sends a second", "rate_limited", "", 429, 0, "rate_limited", 429, "1", false},
		{"rate limit sends the limiter's wait, rounded up", "rate_limited", "", 429, 2500 * time.Millisecond, "rate_limited", 429, "3", false},
		{"an outcome with no entry answers refused", "some_future_check", "", 403, 0, "refused", 403, "", false},
		{"a code with no entry answers refused", "token_unavailable", "some_future_code", 503, 0, "refused", 503, "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			audit := &adapterAudit{}
			p := &Proxy{adapter: &HeaderAdapter{Audit: audit}}
			rec := httptest.NewRecorder()
			code := c.as
			if code == "" {
				code = refusalCode(c.outcome)
			}
			p.adapterDenyAs(rec, auditchain.Event{Pool: "pool-agent"}, "api.vendor.example:443", c.in, c.outcome, code, c.wait)
			if rec.Code != c.status || rec.Header().Get(RefusalHeader) != c.code || rec.Header().Get("Retry-After") != c.retryAfter {
				t.Fatalf("got %d %q Retry-After %q", rec.Code, rec.Header().Get(RefusalHeader), rec.Header().Get("Retry-After"))
			}
			if closes := rec.Header().Get("Connection") == "close"; closes != c.closes {
				t.Fatalf("Connection %q", rec.Header().Get("Connection"))
			}
			body := rec.Body.String()
			if !strings.HasPrefix(body, c.code+": ") || strings.Count(body, "\n") != 1 || !strings.HasSuffix(body, "\n") {
				t.Fatalf("body is not one line naming the code: %q", body)
			}
			if row := audit.last(); row.Outcome != c.outcome || row.Status != c.status || row.Event != auditchain.EventDenied {
				t.Fatalf("audit row: %+v", row)
			}
		})
	}
}

// An outcome a later change builds from an error or a reason, which has no
// entry in the table, never reaches the agent: it sees "refused" and the
// generic next step, by every path a refusal is written, and the audit row
// keeps the specific outcome.
func TestUnknownOutcomeStaysInTheAuditRow(t *testing.T) {
	outcome := "lookup_failed:alice@example.test"
	audit := &adapterAudit{}
	p := &Proxy{adapter: &HeaderAdapter{Audit: audit}}
	written := map[string]*httptest.ResponseRecorder{}
	written["adapterDeny"] = httptest.NewRecorder()
	p.adapterDeny(written["adapterDeny"], auditchain.Event{}, "api.vendor.example:443", http.StatusForbidden, outcome)
	if row := audit.last(); row.Outcome != outcome || row.Status != http.StatusForbidden {
		t.Fatalf("audit row: %+v", row)
	}
	written["adapterDenyAs"] = httptest.NewRecorder()
	p.adapterDenyAs(written["adapterDenyAs"], auditchain.Event{}, "api.vendor.example:443", http.StatusForbidden, "refused", outcome, 0)
	written["refuseWith"] = httptest.NewRecorder()
	refuseWith(written["refuseWith"], http.StatusForbidden, outcome)
	for path, rec := range written {
		body := rec.Body.String()
		if rec.Code != http.StatusForbidden || rec.Header().Get(RefusalHeader) != "refused" || rec.Header().Get("Retry-After") != "" ||
			body != "refused: "+refusals["refused"].next+"\n" || strings.Contains(body, "lookup") || strings.Contains(body, "alice") {
			t.Errorf("%s: got %d %q %q", path, rec.Code, rec.Header().Get(RefusalHeader), body)
		}
	}
}

// The browser seed's deadline refusal is its own lasting code: the deadline
// only gets closer.
func TestSeedDeadlineLasts(t *testing.T) {
	now := time.Now()
	_, err := browserSeed(&httpcatalog.Entry{}, httpcatalog.BrowserToken{}, &brokercore.ProxyScope{NotAfter: now.Add(time.Minute)}, now)
	if seedOutcome(err) != "seed_deadline" || seedOutcome(errors.New("other")) != "seed_unavailable" {
		t.Fatalf("seed outcome: %v", err)
	}
	rec := httptest.NewRecorder()
	refuse(rec, seedOutcome(err))
	if rec.Code != 503 || rec.Header().Get(RefusalHeader) != "seed_deadline" || rec.Header().Get("Retry-After") != "" {
		t.Fatalf("got %d %q %q", rec.Code, rec.Header().Get(RefusalHeader), rec.Header().Get("Retry-After"))
	}
}

// A key read names the cause an operator must fix apart from one that clears.
func TestKeyOutcome(t *testing.T) {
	for err, want := range map[error]string{
		httpcatalog.ErrKeyNotHeaderSafe: "key_not_header_safe",
		httpcatalog.ErrKeyDeleted:       "key_deleted",
		httpcatalog.ErrKeyUnavailable:   "key_unavailable",
		errors.New("anything else"):     "key_unavailable",
	} {
		if got := keyOutcome(err); got != want {
			t.Errorf("%v: %q, want %q", err, got, want)
		}
	}
}

// A refusal whose row cannot be written tells the agent only that the audit
// trail is down, never the refusal it could not record.
func TestRefusalWithoutAuditSaysOnlyAuditUnavailable(t *testing.T) {
	p := &Proxy{adapter: &HeaderAdapter{Audit: failingAudit{}}}
	rec := httptest.NewRecorder()
	p.adapterDeny(rec, auditchain.Event{}, "api.vendor.example:443", http.StatusForbidden, "not_entitled")
	if rec.Code != 503 || rec.Header().Get(RefusalHeader) != "audit_unavailable" || rec.Header().Get("Retry-After") == "" || strings.Contains(rec.Body.String(), "entitled") {
		t.Fatalf("got %d %q %q", rec.Code, rec.Header().Get(RefusalHeader), rec.Body.String())
	}
}

// A refusal made before the request reached the catalog is named by the check
// that made it; its row keeps the outcome "refused".
func TestIdentityRefusalCodes(t *testing.T) {
	for status, code := range map[int]string{400: "request_shape", 403: "identity", 407: "authentication", 429: "busy", 503: "broker_unavailable"} {
		audit := &adapterAudit{}
		p := &Proxy{adapter: &HeaderAdapter{Audit: audit}}
		rec := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "https://api.vendor.example/", nil)
		p.adapterIdentityDeny(rec, r, strictAttempt(nil, nil, r.Method, "", "", "deny"), status, "", nil, 0)
		if rec.Code != status || rec.Header().Get(RefusalHeader) != code || audit.last().Outcome != "refused" {
			t.Errorf("%d: got %d %q, row %q", status, rec.Code, rec.Header().Get(RefusalHeader), audit.last().Outcome)
		}
		if (status == 429 || status == 503) != (rec.Header().Get("Retry-After") != "") {
			t.Errorf("%d: Retry-After %q", status, rec.Header().Get("Retry-After"))
		}
	}
}

// An address over its failed sign-in budget is told the limiter's own wait,
// minutes into a sliding window, not the fixed few seconds of a busy broker.
func TestSignInLimitSendsTheLimitersWait(t *testing.T) {
	audit := &adapterAudit{}
	p := &Proxy{adapter: &HeaderAdapter{Catalog: httpcatalog.Catalog{}, Keys: &adapterKeys{}, Audit: audit}}
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodConnect, "https://api.vendor.example:443", nil)
	p.strictAuthLimitDeny(rec, r, ratelimit.Deny("rate", 4*time.Minute+200*time.Millisecond, 10))
	if rec.Code != 429 || rec.Header().Get(RefusalHeader) != "busy" || rec.Header().Get("Retry-After") != "241" || audit.last().Status != 429 {
		t.Fatalf("got %d %q Retry-After %q", rec.Code, rec.Header().Get(RefusalHeader), rec.Header().Get("Retry-After"))
	}
	rec = httptest.NewRecorder()
	p.strictUnauthenticatedDeny(rec, r, http.StatusTooManyRequests)
	if rec.Header().Get("Retry-After") != "5" {
		t.Fatalf("tunnel cap: Retry-After %q", rec.Header().Get("Retry-After"))
	}
}

// Every next step is one plain line, every passing refusal answers 503 or
// 429, and every fixed outcome the adapters refuse with has its own entry:
// the literals this package refuses with, assigns to an outcome or returns
// from an ...Outcome helper, and every refusal outcome the authorize and
// entitlement packages return, which the adapters pass on as variables. A new
// outcome written in any of those shapes without an entry here fails this
// test instead of reaching the agent only as the generic "refused".
func TestRefusalTableIsComplete(t *testing.T) {
	for code, kind := range refusals {
		if kind.next == "" || strings.ContainsAny(kind.next, "\r\n") || strings.ContainsFunc(kind.next, func(r rune) bool { return r > 0x7e }) {
			t.Errorf("%s: next step %q", code, kind.next)
		}
		if kind.retryAfter > 0 && kind.status != http.StatusServiceUnavailable && kind.status != http.StatusTooManyRequests {
			t.Errorf("%s: Retry-After on status %d", code, kind.status)
		}
	}
	// "pool" answers as "unlisted"; every other outcome needs its own entry.
	check := func(file, outcome string) {
		if _, ok := refusals[outcome]; !ok && outcome != "pool" {
			t.Errorf("%s refuses with %q, which has no next step", file, outcome)
		}
	}
	// In this package: every quoted code on a line that refuses, every code
	// assigned to an outcome, and every code refusal.go's helpers or any
	// ...Outcome helper returns.
	refusing := regexp.MustCompile(`(?m)^.*\b(?:deny|refuse|refuseWith|adapterDeny|adapterDenyAs)\(.*$`)
	quoted := regexp.MustCompile(`"([a-z_]+)"`)
	returned := regexp.MustCompile(`return "([a-z_]+)"`)
	assigned := regexp.MustCompile(`\boutcome :?= "([a-z_]+)"`)
	outcomeFunc := regexp.MustCompile(`(?s)\nfunc (?:\([^)]*\) )?\w*Outcome\([^)]*\) string \{\n(.*?)\n\}\n`)
	files, _ := filepath.Glob("*.go")
	seen, assignedSeen, helperSeen := 0, 0, 0
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range refusing.FindAllString(string(src), -1) {
			for _, m := range quoted.FindAllStringSubmatch(line, -1) {
				check(file, m[1])
				seen++
			}
		}
		for _, m := range assigned.FindAllStringSubmatch(string(src), -1) {
			check(file, m[1])
			assignedSeen++
		}
		bodies := []string{}
		if file == "refusal.go" {
			bodies = append(bodies, string(src))
		} else {
			for _, m := range outcomeFunc.FindAllStringSubmatch(string(src), -1) {
				bodies = append(bodies, m[1])
				helperSeen++
			}
		}
		for _, body := range bodies {
			for _, m := range returned.FindAllStringSubmatch(body, -1) {
				check(file, m[1])
				seen++
			}
		}
	}
	// The outcomes authorize.Resolve, authorize.Decide and entitlement.Decide
	// return, other than the ones that allow the request.
	allows := map[string]bool{"t0": true, "entitled": true, "workload_entitled": true}
	for file, pattern := range map[string]*regexp.Regexp{
		"../authorize/authorize.go":     regexp.MustCompile(`(?:return who, |\.Outcome(?:, [\w.]+)* = )"([a-z_]+)"`),
		"../entitlement/entitlement.go": regexp.MustCompile(`(?m)Outcome = .*"([a-z_]+)"$`),
	} {
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		found := pattern.FindAllStringSubmatch(string(src), -1)
		if len(found) < 5 {
			t.Fatalf("%s: only %d outcomes found; the pattern no longer matches the source", file, len(found))
		}
		for _, m := range found {
			if !allows[m[1]] {
				check(file, m[1])
			}
		}
	}
	// Each pattern finds what it finds today, so none can stop matching unnoticed.
	if seen < 50 || assignedSeen < 2 || helperSeen < 1 {
		t.Fatalf("only %d refusal codes, %d assigned outcomes and %d ...Outcome helpers found in this package; the patterns no longer match the source",
			seen, assignedSeen, helperSeen)
	}
}

// Through the proxy: an agent sees the reason header and next step on a real
// refusal, and a stored key no header may carry is named in the row and the
// header instead of reading as a missing key.
func TestAdapterRefusalReachesTheAgent(t *testing.T) {
	f := newAdapterFixture(t)
	get := func(path string) (int, http.Header, string) {
		t.Helper()
		r, _ := http.NewRequest("POST", f.url(path), strings.NewReader("{}"))
		r.Header.Set("Content-Type", "application/json")
		resp, err := f.client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, resp.Header, string(body)
	}
	if code, h, body := get("/v2/not-listed"); code != 403 || h.Get(RefusalHeader) != "unlisted" || !strings.HasPrefix(body, "unlisted: ") {
		t.Fatalf("unlisted: %d %q %q", code, h.Get(RefusalHeader), body)
	}
	f.keys.mu.Lock()
	f.keys.err = httpcatalog.ErrKeyNotHeaderSafe
	f.keys.mu.Unlock()
	if code, h, _ := get("/v1/chat/completions"); code != 503 || h.Get(RefusalHeader) != "key_not_header_safe" || h.Get("Retry-After") != "" || f.audit.last().Outcome != "key_not_header_safe" {
		t.Fatalf("unsafe key: %d %q row %q", code, h.Get(RefusalHeader), f.audit.last().Outcome)
	}
	f.keys.mu.Lock()
	f.keys.err = httpcatalog.ErrKeyDeleted
	f.keys.mu.Unlock()
	if code, h, _ := get("/v1/chat/completions"); code != 503 || h.Get(RefusalHeader) != "key_deleted" || h.Get("Retry-After") != "" || f.audit.last().Outcome != "key_deleted" {
		t.Fatalf("deleted key: %d %q row %q", code, h.Get(RefusalHeader), f.audit.last().Outcome)
	}
	f.keys.mu.Lock()
	f.keys.err = errors.New("vault sealed")
	f.keys.mu.Unlock()
	if code, h, _ := get("/v1/chat/completions"); code != 503 || h.Get(RefusalHeader) != "key_unavailable" || h.Get("Retry-After") != "5" {
		t.Fatalf("sealed: %d %q", code, h.Get(RefusalHeader))
	}
	if f.calls.Load() != 0 {
		t.Fatal("vendor called while refusing")
	}
}

// The refusal header is the broker's alone. A destination's own 503 that
// carries one reaches the agent with its status and Retry-After but without
// the header, so the agent never reads an answer the destination may already
// have acted on as a refusal the request never left the broker for.
func TestDestinationCannotForgeARefusal(t *testing.T) {
	f := newAdapterFixture(t)
	r, _ := http.NewRequest("POST", f.url("/v1/chat/forged"), strings.NewReader("{}"))
	r.Header.Set("Content-Type", "application/json")
	resp, err := f.client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 503 || resp.Header.Get("Retry-After") != "5" || resp.Header.Values(RefusalHeader) != nil || f.calls.Load() != 1 {
		t.Fatalf("got %d %q Retry-After %q, vendor calls %d", resp.StatusCode, resp.Header.Values(RefusalHeader), resp.Header.Get("Retry-After"), f.calls.Load())
	}
}

// A streamed body cut off at its limit (a git push) is refused with the
// reason header like any other refusal, not a bare 413.
func TestOversizedStreamedBodyNamesItsRefusal(t *testing.T) {
	vendor := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
	}))
	defer vendor.Close()
	p := &Proxy{upstream: vendor.Client().Transport.(*http.Transport)}
	body := &limitedBody{reader: strings.NewReader(strings.Repeat("x", 64<<10)), remaining: 1 << 10}
	out, err := http.NewRequest(http.MethodPost, vendor.URL+"/example/repo.git/git-receive-pack", body)
	if err != nil {
		t.Fatal(err)
	}
	var finished string
	rec := httptest.NewRecorder()
	p.relayScreened(rec, out, nil, 1<<20, func(_ int, outcome string) { finished = outcome }, func(*http.Response) {}, body.exceeded.Load)
	if rec.Code != http.StatusRequestEntityTooLarge || rec.Header().Get(RefusalHeader) != "request_too_large" || finished != "request_too_large" ||
		!strings.HasPrefix(rec.Body.String(), "request_too_large: ") {
		t.Fatalf("got %d %q %q, row %q", rec.Code, rec.Header().Get(RefusalHeader), rec.Body.String(), finished)
	}
}
