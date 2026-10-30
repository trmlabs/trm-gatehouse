package authorize

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/authorize/authorizetest"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/httpcatalog"
	"github.com/Infisical/agent-vault/internal/runnerid"
)

// subagentCatalog has explorer (auto-1, may register explorerSubagents; negative omits it) and auditor (auto-2, registers none).
func subagentCatalog(t *testing.T, explorerSubagents int) httpcatalog.Catalog {
	t.Helper()
	entry := func(name string) string {
		return `{"name":"` + name + `","host":"api.` + name + `.example","pathPrefixes":["/v1/"],"methods":["GET"],"header":"Authorization","scheme":"Bearer",` +
			`"placeholder":"__vault_KEY__","key":{"mount":"gatehouse","path":"vendors/x","field":"key"},"pools":["automations","automations-b"]}`
	}
	explorer := `{"id":"auto-1","name":"explorer","owner":"platform-team","entries":["tracker"]`
	if explorerSubagents > 0 {
		explorer += `,"subagents":` + strconv.Itoa(explorerSubagents)
	}
	explorer += `},`
	if explorerSubagents < 0 {
		explorer = ""
	}
	c, err := httpcatalog.Parse([]byte(`{
		"pools":[{"name":"automations","namespace":"cursor","serviceAccount":"worker","identity":"cursor-automation","ceiling":"T2"},
			{"name":"automations-b","namespace":"cursor-b","serviceAccount":"worker","identity":"cursor-automation","ceiling":"T2"}],
		"entries":[` + entry("tracker") + `,` + entry("ledger") + `],
		"automations":[` + explorer + `
			{"id":"auto-2","name":"auditor","owner":"platform-team","entries":["tracker","ledger"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// subagentRuns are two Automation runs plus runs whose tokens name no Automation, as a subagent's do.
var subagentRuns = cursorRuns{
	"parent":       subagentRunOf("bc-1", "AUTOMATIONS", "auto-1", "user:1", "7"),
	"auditor":      subagentRunOf("bc-2", "AUTOMATIONS", "auto-2", "user:1", "7"),
	"child":        subagentRunOf("bc-20", "API", "", "user:1", "7"),
	"child-2":      subagentRunOf("bc-21", "", "", "user:1", "7"),
	"child-3":      subagentRunOf("bc-22", "AUTOMATIONS", "", "user:1", "7"),
	"child-auto":   subagentRunOf("bc-23", "", "auto-1", "user:1", "7"),
	"other-owner":  subagentRunOf("bc-30", "API", "", "user:2", "7"),
	"other-team":   subagentRunOf("bc-31", "API", "", "user:1", "8"),
	"other-auto":   subagentRunOf("bc-32", "", "auto-2", "user:1", "7"),
	"unregistered": subagentRunOf("bc-40", "WEBSITE", "", "user:1", "7"),
}

func subagentRunOf(run, source, automation, owner, team string) runnerid.Session {
	return runnerid.Session{Kind: runnerid.KindPerson, Subject: "alice@example.com", Owner: owner, Run: run, Source: source, Automation: automation, Team: team}
}

// memSubagents mimics the store: first registration wins, a parent stops at its limit, expired rows vanish.
type memSubagents struct {
	mu   sync.Mutex
	rows map[string]memSubagent
	fail bool
}

type memSubagent struct {
	parent, record string
	expires        time.Time
}

func (m *memSubagents) RegisterSubagent(_ context.Context, run, parent, record string, expires time.Time, limit int) (string, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return "", "", errors.New("store down")
	}
	if m.rows == nil {
		m.rows = map[string]memSubagent{}
	}
	for k, r := range m.rows {
		if !time.Now().Before(r.expires) {
			delete(m.rows, k)
		}
	}
	if r, ok := m.rows[run]; ok {
		return r.parent, r.record, nil
	}
	held := 0
	for _, r := range m.rows {
		if r.parent == parent {
			held++
		}
	}
	if held >= limit {
		return "", "", nil
	}
	m.rows[run] = memSubagent{parent: parent, record: record, expires: expires}
	return parent, record, nil
}

func (m *memSubagents) Subagent(_ context.Context, run string) (string, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return "", "", errors.New("store down")
	}
	r, ok := m.rows[run]
	if !ok || !time.Now().Before(r.expires) {
		return "", "", nil
	}
	return r.parent, r.record, nil
}

// livePods answers PodRunning from a set of live Pod UID and run pairs.
type livePods struct {
	mu    sync.Mutex
	live  map[[2]string]bool
	fail  bool
	reads int
}

func (l *livePods) PodRunning(_ context.Context, pod brokercore.PodRef, run string) (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.reads++
	if l.fail {
		return false, errors.New("cluster unreadable")
	}
	return l.live[[2]string{pod.UID, run}], nil
}

func (l *livePods) set(uid, run string, live bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.live == nil {
		l.live = map[[2]string]bool{}
	}
	l.live[[2]string{uid, run}] = live
}

type subagentFixture struct {
	pool  httpcatalog.Pool
	reg   *memSubagents
	pods  *livePods
	b     *Subagents
	notAt time.Time
}

func newSubagentFixture(t *testing.T) *subagentFixture {
	t.Helper()
	pool, _ := subagentCatalog(t, 2).Pool("automations")
	f := &subagentFixture{pool: pool, reg: &memSubagents{}, pods: &livePods{}, notAt: time.Now().Add(time.Hour)}
	f.b = &Subagents{Binder: &authorizetest.MemBinder{}, Registry: f.reg, Pods: f.pods, Wait: 50 * time.Millisecond}
	f.pods.set("pod-parent", "bc-1", true)
	return f
}

// parentClaims are the claims of the parent's request: its located Pod and deadline.
func (f *subagentFixture) parentClaims() Claims {
	return Claims{Pod: "pod-parent", ClaimedRun: "bc-1", NotAfter: f.notAt,
		PodRef: brokercore.PodRef{Namespace: "cursor", Name: "worker-1", UID: "pod-parent", Container: "agent"}}
}

// register has the parent's run register run, as the route does.
func (f *subagentFixture) register(t *testing.T, token, run string) (time.Time, string) {
	t.Helper()
	claims := f.parentClaims()
	if token != "parent" {
		claims.Pod, claims.ClaimedRun, claims.PodRef.UID = "pod-"+token, subagentRuns[token].Run, "pod-"+token
	}
	who, refusal := Resolve(context.Background(), f.pool, token, claims, subagentRuns, f.b)
	if refusal != "" {
		return time.Time{}, refusal
	}
	return RegisterSubagent(context.Background(), f.pool, who, claims, run, f.b)
}

// resolveOn decides a request by token on its own Pod.
func (f *subagentFixture) resolveOn(pool httpcatalog.Pool, token string) (Requester, string) {
	run := subagentRuns[token]
	return Resolve(context.Background(), pool, token, Claims{Pod: "pod-" + token, ClaimedRun: run.Run}, subagentRuns, f.b)
}

// A registered subagent gets its parent's Automation block and audit fields naming its run, the parent run and the Automation.
func TestRegisteredSubagentActsAsItsAutomation(t *testing.T) {
	f := newSubagentFixture(t)
	expires, refusal := f.register(t, "parent", "bc-20")
	if refusal != "" || !expires.Equal(f.notAt) {
		t.Fatalf("register: %q %v, want expiry %v", refusal, expires, f.notAt)
	}
	parent, _ := Resolve(context.Background(), f.pool, "parent", f.parentClaims(), subagentRuns, f.b)
	who, refusal := f.resolveOn(f.pool, "child")
	if refusal != "" || who.Kind != "automation" || who.Subject != "auto-1" || who.AutomationName != "explorer" || who.AutomationOwner != "platform-team" ||
		who.Automation != "auto-1" || who.Source != "API" || who.Run != "bc-20" || who.ParentRun != "bc-1" || who.Audited() != "alice@example.com" ||
		who.TokenSHA256 != "sha-child" {
		t.Fatalf("%q %+v", refusal, who)
	}
	if parent.Run != "bc-1" || parent.ParentRun != "" {
		t.Fatalf("parent audit fields %+v", parent)
	}
	for _, entry := range []string{"tracker", "ledger", "vault"} {
		if who.MayWrite(entry) != parent.MayWrite(entry) {
			t.Errorf("%s: write grant differs from the parent's", entry)
		}
	}
	catalog := subagentCatalog(t, 2)
	tracker, err := catalog.Match("api.tracker.example", 443, "GET", "/v1/x", "automations")
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := catalog.Match("api.ledger.example", 443, "GET", "/v1/x", "automations")
	if err != nil {
		t.Fatal(err)
	}
	if d := Decide(context.Background(), nil, f.pool, *tracker, who); !d.Allowed {
		t.Fatalf("tracker: %+v", d)
	}
	// The subagent gets explorer's block and nothing from auditor's.
	if d := Decide(context.Background(), nil, f.pool, *ledger, who); d.Allowed || d.Outcome != "automation_not_granted" {
		t.Fatalf("ledger: %+v", d)
	}
}

// A subagent token naming no source, the Automation source without an id, or the parent's id is served once registered.
func TestSubagentTokenShapes(t *testing.T) {
	f := newSubagentFixture(t)
	for _, token := range []string{"child-2", "child-3"} {
		if _, refusal := f.register(t, "parent", subagentRuns[token].Run); refusal != "" {
			t.Fatalf("%s: register %q", token, refusal)
		}
		if who, refusal := f.resolveOn(f.pool, token); refusal != "" || who.Subject != "auto-1" {
			t.Errorf("%s: %q %+v", token, refusal, who)
		}
	}
	// Limits are per parent run: a fresh parent starts with no registrations.
	f2 := newSubagentFixture(t)
	if _, refusal := f2.register(t, "parent", "bc-23"); refusal != "" {
		t.Fatalf("register: %q", refusal)
	}
	if who, refusal := f2.resolveOn(f2.pool, "child-auto"); refusal != "" || who.Subject != "auto-1" {
		t.Errorf("child-auto: %q %+v", refusal, who)
	}
}

// An unregistered run is refused after the Pod's wait, and every run is refused when the broker serves no subagents.
func TestUnregisteredRunStillRefused(t *testing.T) {
	f := newSubagentFixture(t)
	who, refusal := f.resolveOn(f.pool, "unregistered")
	if refusal != "not_automation" || who.Kind != "none" || who.Run != "bc-40" || who.Source != "WEBSITE" || who.ParentRun != "" {
		t.Fatalf("%q %+v", refusal, who)
	}
	if _, refusal := f.register(t, "parent", "bc-20"); refusal != "" {
		t.Fatal(refusal)
	}
	run := subagentRuns["child"]
	if _, refusal := Resolve(context.Background(), f.pool, "child", Claims{Pod: "pod-child", ClaimedRun: run.Run}, subagentRuns, &authorizetest.MemBinder{}); refusal != "not_automation" {
		t.Fatalf("plain binder: %q", refusal)
	}
	if _, refusal := Resolve(context.Background(), f.pool, "child", Claims{Pod: "pod-child", ClaimedRun: run.Run}, subagentRuns, &Subagents{Binder: &authorizetest.MemBinder{}}); refusal != "not_automation" {
		t.Fatalf("no registry: %q", refusal)
	}
}

// A registration whose owner, team, pool or Automation differs, whose parent Pod ended, or whose Automation dropped subagents is refused.
func TestForgedOrStaleSubagentLinksRefused(t *testing.T) {
	cases := map[string]struct {
		token  string
		change func(f *subagentFixture) httpcatalog.Pool
		want   string
	}{
		"another owner":      {token: "other-owner", want: "subagent_mismatch"},
		"another team":       {token: "other-team", want: "subagent_mismatch"},
		"another Automation": {token: "other-auto", want: "subagent_mismatch"},
		"another pool": {token: "child", want: "subagent_mismatch", change: func(f *subagentFixture) httpcatalog.Pool {
			p, _ := subagentCatalog(t, 2).Pool("automations-b")
			return p
		}},
		"parent Pod ended":    {token: "child", want: "subagent_parent_gone", change: func(f *subagentFixture) httpcatalog.Pool { f.pods.set("pod-parent", "bc-1", false); return f.pool }},
		"subagents withdrawn": {token: "child", want: "subagents_not_granted", change: func(f *subagentFixture) httpcatalog.Pool { p, _ := subagentCatalog(t, 0).Pool("automations"); return p }},
		"Automation removed": {token: "child", want: "automation_unlisted", change: func(f *subagentFixture) httpcatalog.Pool {
			p, _ := subagentCatalog(t, -1).Pool("automations")
			return p
		}},
		"Automation became a Gumloop block": {token: "child", want: "automation_unlisted", change: func(f *subagentFixture) httpcatalog.Pool {
			c, err := httpcatalog.Parse([]byte(`{"pools":[{"name":"automations","namespace":"cursor","serviceAccount":"worker","identity":"cursor-automation","ceiling":"T2"}],
				"entries":[{"name":"tracker","host":"api.tracker.example","pathPrefixes":["/v1/"],"methods":["GET"],"header":"Authorization","scheme":"Bearer",
				"placeholder":"__vault_KEY__","key":{"mount":"gatehouse","path":"vendors/x","field":"key"},"pools":["automations"]}],
				"automations":[{"id":"auto-1","name":"explorer","owner":"platform-team","entries":["tracker"],"gumloop":{"orgID":"org-1"}}]}`))
			if err != nil {
				t.Fatal(err)
			}
			p, _ := c.Pool("automations")
			return p
		}},
		"Pod read fails": {token: "child", want: "subagent_unavailable", change: func(f *subagentFixture) httpcatalog.Pool { f.pods.fail = true; return f.pool }},
		"registry down":  {token: "child", want: "subagent_unavailable", change: func(f *subagentFixture) httpcatalog.Pool { f.reg.fail = true; return f.pool }},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newSubagentFixture(t)
			if _, refusal := f.register(t, "parent", subagentRuns[tc.token].Run); refusal != "" {
				t.Fatalf("register: %q", refusal)
			}
			pool := f.pool
			if tc.change != nil {
				pool = tc.change(f)
			}
			who, refusal := f.resolveOn(pool, tc.token)
			if refusal != tc.want || who.Kind != "none" || who.AutomationName != "" {
				t.Fatalf("%q %+v, want %s", refusal, who, tc.want)
			}
			if tc.want != "subagent_unavailable" && who.ParentRun != "bc-1" {
				t.Fatalf("the refusal's audit fields do not name the parent: %+v", who)
			}
		})
	}
}

// A registration ends at the parent Pod's deadline.
func TestSubagentRegistrationEndsAtTheParentsDeadline(t *testing.T) {
	f := newSubagentFixture(t)
	f.notAt = time.Now().Add(150 * time.Millisecond)
	if _, refusal := f.register(t, "parent", "bc-20"); refusal != "" {
		t.Fatal(refusal)
	}
	if _, refusal := f.resolveOn(f.pool, "child"); refusal != "" {
		t.Fatalf("before the deadline: %q", refusal)
	}
	time.Sleep(200 * time.Millisecond)
	if _, refusal := f.resolveOn(f.pool, "child"); refusal != "not_automation" {
		t.Fatalf("after the deadline: %q", refusal)
	}
}

// Only a verified Automation run whose block sets subagents registers, up to its count, and never a run another parent holds.
func TestSubagentRegistrationRefusals(t *testing.T) {
	f := newSubagentFixture(t)
	if _, refusal := f.register(t, "parent", "bc-20"); refusal != "" {
		t.Fatal(refusal)
	}
	// A registered subagent cannot register subagents of its own.
	claims := Claims{Pod: "pod-child", ClaimedRun: "bc-20", NotAfter: f.notAt, PodRef: brokercore.PodRef{Namespace: "cursor", Name: "worker-2", UID: "pod-child"}}
	child, refusal := Resolve(context.Background(), f.pool, "child", claims, subagentRuns, f.b)
	if refusal != "" {
		t.Fatal(refusal)
	}
	if _, refusal := RegisterSubagent(context.Background(), f.pool, child, claims, "bc-21", f.b); refusal != "subagent_nested" {
		t.Fatalf("nested: %q", refusal)
	}
	if _, refusal := f.register(t, "auditor", "bc-21"); refusal != "subagents_not_granted" {
		t.Fatalf("auditor: %q", refusal)
	}
	for _, run := range []string{"bc-1", "", "bc-", "run-21", "bc-21 x", "bc-21/../x"} {
		if _, refusal := f.register(t, "parent", run); refusal != "request_shape" {
			t.Errorf("%q: %q", run, refusal)
		}
	}
	parent, _ := Resolve(context.Background(), f.pool, "parent", f.parentClaims(), subagentRuns, f.b)
	for name, c := range map[string]func(*Claims){
		"no Pod ref":     func(c *Claims) { c.PodRef = brokercore.PodRef{} },
		"another Pod":    func(c *Claims) { c.PodRef.UID = "pod-other" },
		"no deadline":    func(c *Claims) { c.NotAfter = time.Time{} },
		"unnamed Pod":    func(c *Claims) { c.PodRef.Name = "" },
		"no namespace":   func(c *Claims) { c.PodRef.Namespace = "" },
		"unlocated root": func(c *Claims) { *c = Claims{Pod: "pod-parent"} },
	} {
		claims := f.parentClaims()
		c(&claims)
		if _, refusal := RegisterSubagent(context.Background(), f.pool, parent, claims, "bc-21", f.b); refusal != "session_unbindable" {
			t.Errorf("%s: %q", name, refusal)
		}
	}
	// The first registration wins: another parent cannot take the run.
	f.pods.set("pod-parent-2", "bc-3", true)
	other := subagentRunOf("bc-3", "AUTOMATIONS", "auto-1", "user:1", "7")
	runs := cursorRuns{"other-parent": other}
	otherClaims := Claims{Pod: "pod-parent-2", ClaimedRun: "bc-3", NotAfter: f.notAt, PodRef: brokercore.PodRef{Namespace: "cursor", Name: "worker-3", UID: "pod-parent-2"}}
	otherWho, refusal := Resolve(context.Background(), f.pool, "other-parent", otherClaims, runs, f.b)
	if refusal != "" {
		t.Fatal(refusal)
	}
	if _, refusal := RegisterSubagent(context.Background(), f.pool, otherWho, otherClaims, "bc-20", f.b); refusal != "subagent_taken" {
		t.Fatalf("taken: %q", refusal)
	}
	// A repeat by the same parent is accepted; a run over the count of two is refused.
	if _, refusal := f.register(t, "parent", "bc-20"); refusal != "" {
		t.Fatalf("repeat: %q", refusal)
	}
	if _, refusal := f.register(t, "parent", "bc-21"); refusal != "" {
		t.Fatalf("second: %q", refusal)
	}
	if _, refusal := f.register(t, "parent", "bc-22"); refusal != "subagent_limit" {
		t.Fatalf("over the count: %q", refusal)
	}
	f.reg.fail = true
	if _, refusal := f.register(t, "parent", "bc-24"); refusal != "subagent_unavailable" {
		t.Fatalf("registry down: %q", refusal)
	}
	f.reg.fail = false
	// A person's run, or a broker that serves no subagents, registers none.
	if _, refusal := RegisterSubagent(context.Background(), f.pool, Requester{Kind: "person", Subject: "alice@example.com"}, f.parentClaims(), "bc-24", f.b); refusal != "not_automation" {
		t.Fatalf("person: %q", refusal)
	}
	if _, refusal := RegisterSubagent(context.Background(), f.pool, parent, f.parentClaims(), "bc-24", &authorizetest.MemBinder{}); refusal != "broker_misconfigured" {
		t.Fatalf("plain binder: %q", refusal)
	}
}

// A static-token agent has no Cursor run to vouch for a subagent.
func TestStaticTokenAgentRegistersNoSubagent(t *testing.T) {
	f := newSubagentFixture(t)
	who := Requester{Kind: "automation", Subject: "auto-1", Source: SourceStaticToken, Automation: "auto-1"}
	a, _ := f.pool.Automation("auto-1")
	who.grant = &a
	if _, refusal := RegisterSubagent(context.Background(), f.pool, who, f.parentClaims(), "bc-20", f.b); refusal != "not_automation" {
		t.Fatalf("%q", refusal)
	}
}

// A subagent's first request waits for its registration within the Pod's wait.
func TestSubagentFirstRequestWaitsForItsRegistration(t *testing.T) {
	f := newSubagentFixture(t)
	f.b.Wait = 5 * time.Second
	done := make(chan string, 1)
	go func() {
		_, refusal := f.resolveOn(f.pool, "child")
		done <- refusal
	}()
	time.Sleep(250 * time.Millisecond)
	if _, refusal := f.register(t, "parent", "bc-20"); refusal != "" {
		t.Fatal(refusal)
	}
	select {
	case refusal := <-done:
		if refusal != "" {
			t.Fatalf("waited and refused: %q", refusal)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("the waiting request did not see the registration")
	}
	// The wait is counted from the Pod's first request, after which an unregistered run is refused at once.
	f.b.Wait = 100 * time.Millisecond
	start := time.Now()
	if _, refusal := f.resolveOn(f.pool, "unregistered"); refusal != "not_automation" {
		t.Fatal(refusal)
	}
	if _, refusal := f.resolveOn(f.pool, "unregistered"); refusal != "not_automation" || time.Since(start) > time.Second {
		t.Fatalf("%q after %v", refusal, time.Since(start))
	}
	again := time.Now()
	if _, refusal := f.resolveOn(f.pool, "unregistered"); refusal != "not_automation" || time.Since(again) > 50*time.Millisecond {
		t.Fatalf("a request after the wait waited %v", time.Since(again))
	}
}

// A pool where no Automation sets subagents never holds a request waiting for a registration.
func TestPoolWithoutSubagentsDoesNotWait(t *testing.T) {
	f := newSubagentFixture(t)
	f.pool, _ = subagentCatalog(t, 0).Pool("automations")
	f.b.Wait = 5 * time.Second
	start := time.Now()
	if _, refusal := f.resolveOn(f.pool, "unregistered"); refusal != "not_automation" || time.Since(start) > time.Second {
		t.Fatalf("%q after %v", refusal, time.Since(start))
	}
}

// A running parent is read once for a burst of requests, an error is never kept, and a kept answer lapses so a gone parent stops its subagents.
func TestSubagentParentPodReadIsCachedBriefly(t *testing.T) {
	f := newSubagentFixture(t)
	if _, refusal := f.register(t, "parent", "bc-20"); refusal != "" {
		t.Fatal(refusal)
	}
	base := f.pods.reads
	f.pods.fail = true
	if _, refusal := f.resolveOn(f.pool, "child"); refusal != "subagent_unavailable" {
		t.Fatalf("read error: %q", refusal)
	}
	f.pods.fail = false
	for i := range 3 {
		if _, refusal := f.resolveOn(f.pool, "child"); refusal != "" {
			t.Fatalf("request %d: %q", i, refusal)
		}
	}
	if got := f.pods.reads - base; got != 2 {
		t.Fatalf("%d Pod reads for one failed and three served requests, want 2", got)
	}
	f.pods.set("pod-parent", "bc-1", false)
	if _, refusal := f.resolveOn(f.pool, "child"); refusal != "" {
		t.Fatalf("inside the cache window: %q", refusal)
	}
	f.b.mu.Lock()
	for k := range f.b.live {
		f.b.live[k] = time.Now().Add(-time.Second)
	}
	f.b.mu.Unlock()
	if _, refusal := f.resolveOn(f.pool, "child"); refusal != "subagent_parent_gone" {
		t.Fatalf("after the window: %q", refusal)
	}
}
