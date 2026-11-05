package taskrelay

import (
	"context"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/proxyactivity"
	"github.com/Infisical/agent-vault/internal/store"
	"github.com/Infisical/agent-vault/internal/store/storetest"
)

type anyProxy struct{}

func (anyProxy) IdentifyProxy(context.Context, string, netip.Addr) (proxyactivity.Identity, error) {
	return proxyactivity.Identity{Scope: "td/gatehouse-proxy/uid", Namespaces: []string{"agent-sandboxes"}}, nil
}

type restoreRig struct {
	path   string
	raw    *sql.DB
	routes atomic.Value // http.Handler
	srv    *httptest.Server
	ca     string
}

func newRestoreRig(t *testing.T) *restoreRig {
	t.Helper()
	rig := &restoreRig{path: filepath.Join(t.TempDir(), "broker.db")}
	storetest.Seed(t, rig.path)
	rig.restartBroker(t)
	// Wait out the broker's write lock rather than failing with SQLITE_BUSY.
	raw, err := sql.Open("sqlite", rig.path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { raw.Close() })
	rig.raw = raw
	rig.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			c, buf, e := w.(http.Hijacker).Hijack()
			if e != nil {
				return
			}
			defer c.Close()
			buf.WriteString("HTTP/1.1 200 OK\r\n\r\n")
			buf.Flush()
			io.Copy(c, buf)
			return
		}
		rig.routes.Load().(http.Handler).ServeHTTP(w, r)
	}))
	t.Cleanup(rig.srv.Close)
	rig.ca = filepath.Join(t.TempDir(), "broker-ca.pem")
	writeTestFile(t, rig.ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rig.srv.Certificate().Raw}))
	return rig
}

func (rig *restoreRig) restartBroker(t *testing.T) {
	t.Helper()
	db, err := store.Open(rig.path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	service := &proxyactivity.Service{Store: db, Identifier: anyProxy{}, Retention: 24 * time.Hour}
	if err := service.Validate(); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	service.Register(mux)
	rig.routes.Store(http.Handler(mux))
}

func (rig *restoreRig) exec(t *testing.T, query string) {
	t.Helper()
	if _, err := rig.raw.Exec(query); err != nil {
		t.Fatal(err)
	}
}

func (rig *restoreRig) int64(t *testing.T, query string) int64 {
	t.Helper()
	var n int64
	if err := rig.raw.QueryRow(query).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func (rig *restoreRig) replica(t *testing.T) (*sharedFixture, string) {
	t.Helper()
	sf, admin := rig.start(t, sandboxPod("sandbox-a", "pod-a", "127.0.0.1"))
	pod := sandboxPod("sandbox-a", "pod-a", "127.0.0.1")
	pod["metadata"].(map[string]any)["ownerReferences"].([]any)[0].(map[string]any)["uid"] = "uid-sb-00007"
	sf.api.send(t, "MODIFIED", pod)
	// The watch applies on its own goroutine; until then a tunnel is attributed to the Pod's old owner.
	waitUntil(t, "the replica to see sb-00007's Pod", func() bool {
		for _, s := range local(t, admin).Sandboxes {
			if s.OwnerUID == "uid-sb-00007" {
				return true
			}
		}
		return false
	})
	return sf, admin
}

func (rig *restoreRig) idleReplica(t *testing.T) (*sharedFixture, string) {
	t.Helper()
	return rig.start(t)
}

func (rig *restoreRig) start(t *testing.T, pods ...map[string]any) (*sharedFixture, string) {
	t.Helper()
	admin := freeAddress(t)
	sf := startSharedPods(t, false, true, pods, func(c *FixedConfig) {
		u, _ := url.Parse(rig.srv.URL)
		c.Connect.Upstream.Address, c.Connect.Upstream.CAFile = u.Host, rig.ca
		c.AdminListen = admin
		c.DurableActivity = &DurableActivityConfig{PushSeconds: 1}
	})
	return sf, admin
}

func local(t *testing.T, admin string) ActivityReport {
	t.Helper()
	var r ActivityReport
	resp, err := http.Get("http://" + admin + ActivityLocalPath)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		t.Fatal(err)
	}
	return r
}

func (rig *restoreRig) use(t *testing.T, sf *sharedFixture) {
	t.Helper()
	before := time.Now().UnixMilli()
	c, _, status := sf.connect(t, "")
	if status != 200 {
		t.Fatalf("connect: %d", status)
	}
	c.Close()
	waitUntil(t, "sb-00007's use in the store", func() bool {
		var ms int64
		err := rig.raw.QueryRow(`SELECT last_seen_ms FROM proxy_activity WHERE owner_uid = 'uid-sb-00007'`).Scan(&ms)
		return err == nil && ms >= before
	})
}

func pass(t *testing.T, admin string, idle time.Duration) *janitorFixture {
	t.Helper()
	return passOver(t, idle, admin)
}

func passOver(t *testing.T, idle time.Duration, admins ...string) *janitorFixture {
	t.Helper()
	jf := newJanitor(t, nil)
	byIP := map[string]string{}
	for i, admin := range admins {
		ip := fmt.Sprintf("10.9.9.%d", i+1)
		byIP[ip] = admin
		jf.api.replicas = append(jf.api.replicas, replicaPod(fmt.Sprintf("proxy-%d", i), ip))
	}
	jf.j.replicaURL = func(ip, path string) string { return "http://" + byIP[ip] + path }
	jf.j.config.IdleSeconds = int64(idle / time.Second)
	// These tests are about holds; the delete cap would leave one of the two.
	jf.j.config.MaxDeleteFraction = 1
	jf.api.sandboxes = []map[string]any{janitorSandbox(1, 3*time.Hour), janitorSandbox(7, 3*time.Hour)}
	if e := jf.j.pass(context.Background()); e != nil {
		t.Fatalf("pass: %v", e)
	}
	return jf
}

func held(t *testing.T, jf *janitorFixture) any {
	t.Helper()
	return jf.events(t, "janitor_pass")[0]["held"]
}

func TestJanitorFirstPassAfterARestore(t *testing.T) {
	t.Parallel()
	const idle = 4 * time.Second
	rig := newRestoreRig(t)
	sf, admin := rig.replica(t)
	rig.use(t, sf)
	rig.exec(t, `UPDATE proxy_activity_scope SET history_started_ms = history_started_ms - 7200000`)
	time.Sleep(idle + time.Second)

	rig.use(t, sf)
	rig.exec(t, `DELETE FROM proxy_activity WHERE owner_uid = 'uid-sb-00007'`)
	time.Sleep(2 * time.Second) // two report intervals: nothing puts the row back
	if rig.int64(t, `SELECT COUNT(*) FROM proxy_activity WHERE owner_uid = 'uid-sb-00007'`) != 0 {
		t.Fatal("the lost row came back before the pass; the test would prove nothing")
	}
	jf := pass(t, admin, idle)
	if jf.api.deleted["sb-00007"] || !jf.api.deleted["sb-00001"] {
		t.Fatalf("restore of a row: deleted %v", jf.api.deleted)
	}

	rig.use(t, sf)
	rig.exec(t, `DELETE FROM proxy_activity`)
	rig.exec(t, `UPDATE proxy_activity_stream SET seq = seq - 3`)
	jf = pass(t, admin, idle)
	if len(jf.api.deleted) != 0 || held(t, jf) != "activity_history_lost" {
		t.Fatalf("restore past acknowledged reports: deleted %v, held %v", jf.api.deleted, held(t, jf))
	}
	waitUntil(t, "the replica's report of the loss", func() bool {
		return rig.int64(t, `SELECT COUNT(*) FROM proxy_activity WHERE owner_uid = 'uid-sb-00007'`) == 1
	})
	jf = pass(t, admin, idle)
	if len(jf.api.deleted) != 0 || held(t, jf) != "activity_history_young" {
		t.Fatalf("after the loss was reported: deleted %v, held %v", jf.api.deleted, held(t, jf))
	}
	time.Sleep(idle + time.Second)
	if jf = pass(t, admin, idle); held(t, jf) != nil || !jf.api.deleted["sb-00001"] {
		t.Fatalf("one idle window after the loss: deleted %v, held %v", jf.api.deleted, held(t, jf))
	}

	historyBefore := rig.int64(t, `SELECT history_started_ms FROM proxy_activity_scope`)
	rig.restartBroker(t)
	rig.use(t, sf)
	if after := rig.int64(t, `SELECT history_started_ms FROM proxy_activity_scope`); after != historyBefore {
		t.Fatalf("a broker restart with no loss moved the history: %d then %d", historyBefore, after)
	}
	if jf = pass(t, admin, idle); held(t, jf) != nil || !jf.api.deleted["sb-00001"] || jf.api.deleted["sb-00007"] {
		t.Fatalf("after a broker restart: deleted %v, held %v", jf.api.deleted, held(t, jf))
	}
}

func TestJanitorHoldsAfterEveryReplicaRestarts(t *testing.T) {
	const idle = 4 * time.Second
	rig := newRestoreRig(t)
	sf, _ := rig.replica(t)
	rig.use(t, sf)
	rig.exec(t, `UPDATE proxy_activity_scope SET history_started_ms = history_started_ms - 7200000`)
	_, admin := rig.replica(t)
	jf := pass(t, admin, idle)
	if len(jf.api.deleted) != 0 || held(t, jf) != "activity_history_unverified" {
		t.Fatalf("before the new replica's first report: deleted %v, held %v", jf.api.deleted, held(t, jf))
	}
	waitUntil(t, "the new replica's acknowledgment", func() bool {
		resp, err := http.Get("http://" + admin + ActivityLocalPath)
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		var r ActivityReport
		return json.NewDecoder(resp.Body).Decode(&r) == nil && r.AckedSeq > 0
	})
	jf = pass(t, admin, idle)
	if len(jf.api.deleted) != 0 || held(t, jf) != "activity_history_unverified" {
		t.Fatalf("within the idle window of its first acknowledgment: deleted %v, held %v", jf.api.deleted, held(t, jf))
	}
	time.Sleep(idle + time.Second)
	if jf = pass(t, admin, idle); held(t, jf) != nil || !jf.api.deleted["sb-00001"] {
		t.Fatalf("one idle window later: deleted %v, held %v", jf.api.deleted, held(t, jf))
	}
}

func TestJanitorSeesAnIdleReplicasLossPastABusyOne(t *testing.T) {
	t.Parallel()
	const idle = 4 * time.Second
	rig := newRestoreRig(t)
	busy, busyAdmin := rig.replica(t)
	quiet, quietAdmin := rig.replica(t)
	rig.use(t, busy)
	rig.use(t, quiet)
	waitUntil(t, "both acknowledgments", func() bool {
		return local(t, busyAdmin).AckedSeq > 0 && local(t, quietAdmin).AckedSeq > 0
	})
	rig.exec(t, `UPDATE proxy_activity_scope SET history_started_ms = history_started_ms - 7200000`)
	time.Sleep(idle + time.Second)
	rig.use(t, quiet)
	stream := local(t, quietAdmin).Replica
	waitUntil(t, "the idle replica's last report", func() bool {
		return rig.int64(t, `SELECT seq FROM proxy_activity_stream WHERE replica = '`+stream+`'`) == local(t, quietAdmin).AckedSeq
	})
	rig.exec(t, `UPDATE proxy_activity_stream SET seq = seq - 1 WHERE replica = '`+stream+`'`)
	history := rig.int64(t, `SELECT history_started_ms FROM proxy_activity_scope`)
	for range 5 {
		rig.use(t, busy)
	}
	if rig.int64(t, `SELECT history_started_ms FROM proxy_activity_scope`) != history {
		t.Fatal("the busy replica's reports restarted the history; the test would prove nothing")
	}
	jf := passOver(t, idle, busyAdmin, quietAdmin)
	if len(jf.api.deleted) != 0 || held(t, jf) != "activity_history_lost" {
		t.Fatalf("after the busy replica's reports: deleted %v, held %v", jf.api.deleted, held(t, jf))
	}
	waitUntil(t, "the idle replica's report of its loss", func() bool {
		return rig.int64(t, `SELECT history_started_ms FROM proxy_activity_scope`) != history
	})
	jf = passOver(t, idle, busyAdmin, quietAdmin)
	if len(jf.api.deleted) != 0 || held(t, jf) != "activity_history_young" {
		t.Fatalf("after the idle replica's report: deleted %v, held %v", jf.api.deleted, held(t, jf))
	}
	time.Sleep(idle + time.Second)
	rig.use(t, busy)
	if jf = passOver(t, idle, busyAdmin, quietAdmin); held(t, jf) != nil || !jf.api.deleted["sb-00001"] || jf.api.deleted["sb-00007"] {
		t.Fatalf("one idle window after the loss: deleted %v, held %v", jf.api.deleted, held(t, jf))
	}
}

func TestJanitorHoldEndsAWindowAfterAQuietRestart(t *testing.T) {
	t.Parallel()
	const idle = 4 * time.Second
	rig := newRestoreRig(t)
	sf, _ := rig.replica(t)
	rig.use(t, sf)
	rig.exec(t, `UPDATE proxy_activity_scope SET history_started_ms = history_started_ms - 7200000`)
	_, first := rig.idleReplica(t)
	_, second := rig.idleReplica(t)
	jf := passOver(t, idle, first, second)
	if len(jf.api.deleted) != 0 || held(t, jf) != "activity_history_unverified" {
		t.Fatalf("within the window: deleted %v, held %v", jf.api.deleted, held(t, jf))
	}
	time.Sleep(idle + time.Second)
	if r := local(t, first); r.AckedSeq != 0 {
		t.Fatalf("an idle replica reported: %+v", r)
	}
	if jf = passOver(t, idle, first, second); held(t, jf) != nil || !jf.api.deleted["sb-00001"] || !jf.api.deleted["sb-00007"] {
		t.Fatalf("one window after the restart: deleted %v, held %v", jf.api.deleted, held(t, jf))
	}
}
