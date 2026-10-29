//go:build loadtest

package mitm

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/loadstat"
	"github.com/Infisical/agent-vault/internal/ratelimit"
	"github.com/Infisical/agent-vault/internal/requestlog"
	"github.com/Infisical/agent-vault/internal/store"
	"github.com/Infisical/agent-vault/internal/store/storetest"
)

// The load harness runs the CONNECT tunnel path against a fake HTTPS upstream at N concurrent sessions; build with -tags loadtest.

const loadPlaceholderHeader = "Authorization: Bearer __vault_API_KEY__\r\n"

type loadSession struct {
	conn   net.Conn
	br     *bufio.Reader
	lat    []time.Duration
	status map[int]int
	errs   int
}

type loadErrors struct {
	mu   sync.Mutex
	seen map[string]int
}

func (e *loadErrors) add(err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.seen == nil {
		e.seen = map[string]int{}
	}
	msg := err.Error()
	if len(msg) > 120 {
		msg = msg[:120]
	}
	e.seen[msg]++
}

func (e *loadErrors) top() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	best, bestN := "", 0
	for m, n := range e.seen {
		if n > bestN {
			best, bestN = m, n
		}
	}
	if bestN == 0 {
		return "none"
	}
	return fmt.Sprintf("%dx %s", bestN, best)
}

func (s *loadSession) do(req []byte, record bool) (int, error) {
	start := time.Now()
	_ = s.conn.SetDeadline(start.Add(30 * time.Second))
	if _, err := s.conn.Write(req); err != nil {
		return 0, err
	}
	resp, err := http.ReadResponse(s.br, nil)
	if err != nil {
		return 0, err
	}
	_, err = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		return 0, err
	}
	if record {
		s.lat = append(s.lat, time.Since(start))
	}
	return resp.StatusCode, nil
}

func (s *loadSession) request(req []byte, errs *loadErrors) {
	status, err := s.do(req, true)
	if err != nil {
		s.errs++
		errs.add(err)
		return
	}
	s.status[status]++
}

func dialLoadSession(dialAddr string, viaProxy bool, token, target, sni string, roots *x509.CertPool) (*loadSession, error) {
	conn, err := net.DialTimeout("tcp", dialAddr, 30*time.Second)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	if viaProxy {
		auth := base64.StdEncoding.EncodeToString([]byte(token + ":"))
		if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\n\r\n", target, target, auth); err != nil {
			_ = conn.Close()
			return nil, err
		}
		resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			_ = conn.Close()
			return nil, fmt.Errorf("CONNECT answered %d", resp.StatusCode)
		}
	}
	tlsConn := tls.Client(conn, &tls.Config{RootCAs: roots, ServerName: sni, MinVersion: tls.VersionTLS12})
	if err := tlsConn.Handshake(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return &loadSession{conn: tlsConn, br: bufio.NewReader(tlsConn), status: map[int]int{}}, nil
}

func parallel(sessions []*loadSession, fn func(i int, s *loadSession)) {
	var wg sync.WaitGroup
	for i, s := range sessions {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fn(i, s)
		}()
	}
	wg.Wait()
}

func collect(sessions []*loadSession) (lat []time.Duration, ok, non200, errs int) {
	for _, s := range sessions {
		lat = append(lat, s.lat...)
		ok += s.status[200]
		for code, n := range s.status {
			if code != 200 {
				non200 += n
			}
		}
		errs += s.errs
		s.lat, s.status, s.errs = nil, map[int]int{}, 0
	}
	return lat, ok, non200, errs
}

func TestLoadProxy(t *testing.T) {
	limit := loadstat.RaiseFDLimit()
	t.Logf("descriptor limit %d, GOMAXPROCS %d", limit, runtime.GOMAXPROCS(0))
	for _, mode := range []string{"direct", "legacy", "legacy-ratelimit", "strict"} {
		for _, n := range loadstat.Levels(t) {
			t.Run(fmt.Sprintf("%s/%d", mode, n), func(t *testing.T) { runLoadProxy(t, mode, n) })
		}
	}
}

func runLoadProxy(t *testing.T, mode string, n int) {
	if only := loadModes(); only != nil && !only[mode] {
		t.Skip("mode not selected by LOADTEST_MODES")
	}
	perSession := 4 // client, tunnel, upstream, upstream's end
	if mode == "direct" {
		perSession = 2
	}
	loadstat.Budget(t, n, perSession)
	setupConc := loadstat.Int(t, "LOADTEST_SETUP_CONC", 64)
	pacedReqs := loadstat.Int(t, "LOADTEST_PACED_REQS", 5)
	pace := time.Duration(loadstat.Int(t, "LOADTEST_PACE_MS", 1000)) * time.Millisecond
	satReqs := loadstat.Int(t, "LOADTEST_SAT_REQS", 20)

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()
	upstreamAuthority := upstream.Listener.Addr().String()
	upstreamHost, _, _ := net.SplitHostPort(upstreamAuthority)
	upstreamRoots := x509.NewCertPool()
	upstreamRoots.AddCert(upstream.Certificate())

	dialAddr, roots := upstreamAuthority, upstreamRoots
	if mode != "direct" {
		dialAddr, roots = startLoadProxy(t, mode, upstreamHost, upstreamRoots)
	}

	req := []byte("GET /ping HTTP/1.1\r\nHost: " + upstreamAuthority + "\r\n" + loadPlaceholderHeader + "\r\n")
	errs := &loadErrors{}
	base := loadstat.Take()
	stop := loadstat.Profile(t, fmt.Sprintf("mitm-%s-%d", mode, n))
	defer stop()

	sessions := make([]*loadSession, n)
	setupLat := make([]time.Duration, n)
	slots := make(chan struct{}, setupConc)
	var failed atomic.Int64
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		slots <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-slots }()
			start := time.Now()
			s, err := dialLoadSession(dialAddr, mode != "direct", fmt.Sprintf("tok-%d", i), upstreamAuthority, upstreamHost, roots)
			if err != nil {
				failed.Add(1)
				errs.add(err)
				return
			}
			setupLat[i] = time.Since(start)
			s.request(req, errs) // the first request keeps the tunnel past its first-request timeout
			sessions[i] = s
		}()
	}
	wg.Wait()
	var live []*loadSession
	var setup []time.Duration
	for i, s := range sessions {
		if s != nil {
			live = append(live, s)
			setup = append(setup, setupLat[i])
		}
	}
	defer func() {
		for _, s := range live {
			_ = s.conn.Close()
		}
	}()
	first, _, _, _ := collect(live)
	firstP50, _, _ := loadstat.Percentiles(first)
	setupP50, setupP99, _ := loadstat.Percentiles(setup)
	held := loadstat.Take().Delta(base)
	m := max(len(live), 1)

	startPaced := time.Now()
	parallel(live, func(_ int, s *loadSession) {
		t0 := time.Now().Add(time.Duration(time.Now().UnixNano() % int64(pace)))
		for k := range pacedReqs {
			time.Sleep(time.Until(t0.Add(time.Duration(k) * pace)))
			s.request(req, errs)
		}
	})
	pacedElapsed := time.Since(startPaced)
	pacedLat, pacedOK, pacedBad, pacedErr := collect(live)
	pacedP50, pacedP99, _ := loadstat.Percentiles(pacedLat)

	gate := make(chan struct{})
	var ready sync.WaitGroup
	ready.Add(len(live))
	go func() {
		ready.Wait()
		close(gate)
	}()
	startSat := time.Now()
	parallel(live, func(_ int, s *loadSession) {
		ready.Done()
		<-gate
		for range satReqs {
			s.request(req, errs)
		}
	})
	satElapsed := time.Since(startSat)
	satLat, satOK, satBad, satErr := collect(live)
	satP50, satP99, _ := loadstat.Percentiles(satLat)

	loadstat.Row("mitm", mode, n, "established", len(live), "setup_failed", failed.Load(),
		"setup_p50_ms", ms(setupP50), "setup_p99_ms", ms(setupP99), "first_req_p50_ms", ms(firstP50),
		"paced_rps", rate(pacedOK+pacedBad, pacedElapsed), "paced_p50_ms", ms(pacedP50), "paced_p99_ms", ms(pacedP99), "paced_non200", pacedBad, "paced_err", pacedErr,
		"sat_rps", rate(satOK+satBad, satElapsed), "sat_p50_ms", ms(satP50), "sat_p99_ms", ms(satP99), "sat_non200", satBad, "sat_err", satErr,
		"heap_kib_per_session", held.Heap/uint64(m)/1024, "stack_kib_per_session", held.Stack/uint64(m)/1024,
		"goroutines_per_session", fmt.Sprintf("%.1f", float64(held.Goroutines)/float64(m)), "fds_per_session", fmt.Sprintf("%.1f", float64(held.FDs)/float64(m)),
		"top_error", errs.top())

	if len(live) == 0 || pacedOK+satOK == 0 {
		t.Fatalf("no working session: established %d of %d, successful requests %d: %s", len(live), n, pacedOK+satOK, errs.top())
	}
	if n <= 1000 && (len(live) < n || satErr+pacedErr > 0 || (mode != "legacy-ratelimit" && satBad+pacedBad > 0)) {
		t.Errorf("below the break point: established %d of %d, transport errors %d, non-200 %d: %s", len(live), n, satErr+pacedErr, satBad+pacedBad, errs.top())
	}
}

func startLoadProxy(t *testing.T, mode, upstreamHost string, upstreamRoots *x509.CertPool) (string, *x509.CertPool) {
	t.Helper()
	sessions := &fakeSessionResolver{resolve: func(token, _ string) (*brokercore.ProxyScope, error) {
		return &brokercore.ProxyScope{VaultID: "vault-1", VaultName: "default", AgentID: token, WorkloadID: "pod-" + token, VaultRole: "proxy"}, nil
	}}
	inject := &brokercore.InjectResult{Headers: map[string]string{"Authorization": "Bearer injected"}}
	if mode == "strict" {
		inject = &brokercore.InjectResult{MatchedName: "approved", MatchedHost: upstreamHost, CredentialKeys: []string{"API_KEY"},
			Substitutions: []brokercore.ResolvedSubstitution{{Placeholder: "__vault_API_KEY__", Value: "loadtest-value", In: []string{"header"}}}}
	}
	creds := &fakeCredProvider{byHost: map[string]fakeInjectResult{upstreamHost: {result: inject}}}
	proxyURL, roots, p := setupProxy(t, sessions, creds, func(o *Options) {
		switch mode {
		case "legacy-ratelimit":
			o.RateLimit = ratelimit.New(ratelimit.DefaultsFor(ratelimit.ProfileDefault))
		case "strict":
			auditPath := filepath.Join(t.TempDir(), "audit.db")
			storetest.Seed(t, auditPath)
			st, err := store.Open(auditPath)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = st.Close() })
			o.StrictCredentialProxy = true
			o.DurableAudit = requestlog.NewDurable(st)
		}
	})
	p.upstream.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: upstreamRoots}
	return proxyURL.Host, roots
}

func loadModes() map[string]bool {
	raw := os.Getenv("LOADTEST_MODES")
	if raw == "" {
		return nil
	}
	out := map[string]bool{}
	for _, m := range strings.Split(raw, ",") {
		out[m] = true
	}
	return out
}

func ms(d time.Duration) string { return fmt.Sprintf("%.2f", float64(d.Microseconds())/1000) }

func rate(n int, d time.Duration) string { return fmt.Sprintf("%.0f", float64(n)/d.Seconds()) }
