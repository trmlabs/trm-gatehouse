//go:build loadtest

package pgproxy

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/loadstat"
	"github.com/jackc/pgx/v5/pgproto3"
)

// The load harness runs the PostgreSQL proxy against a fake backend at N concurrent sessions; build with -tags loadtest.

type loadBackend struct {
	ln       net.Listener
	accepted atomic.Int64
}

func startLoadBackend(t *testing.T) *loadBackend {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	b := &loadBackend{ln: ln}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			b.accepted.Add(1)
			go serveLoadBackend(conn)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return b
}

func serveLoadBackend(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	be := pgproto3.NewBackend(conn, conn)
	msg, err := be.ReceiveStartupMessage()
	if err != nil {
		return
	}
	if _, ok := msg.(*pgproto3.SSLRequest); ok {
		if _, err := conn.Write([]byte{'N'}); err != nil {
			return
		}
		if msg, err = be.ReceiveStartupMessage(); err != nil {
			return
		}
	}
	if _, ok := msg.(*pgproto3.StartupMessage); !ok {
		return
	}
	be.Send(&pgproto3.AuthenticationOk{})
	be.Send(&pgproto3.ParameterStatus{Name: "server_version", Value: "16.0 (fake)"})
	be.Send(&pgproto3.BackendKeyData{ProcessID: 4242, SecretKey: []byte{9, 8, 7, 6}})
	be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	if err := be.Flush(); err != nil {
		return
	}
	for {
		m, err := be.Receive()
		if err != nil {
			return
		}
		switch m.(type) {
		case *pgproto3.Query:
			be.Send(&pgproto3.RowDescription{Fields: []pgproto3.FieldDescription{{Name: []byte("one"), DataTypeOID: 25}}})
			be.Send(&pgproto3.DataRow{Values: [][]byte{[]byte("1")}})
			be.Send(&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")})
			be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
			if err := be.Flush(); err != nil {
				return
			}
		case *pgproto3.Terminate:
			return
		}
	}
}

type loadAuth struct{}

func (loadAuth) Authenticate(_ context.Context, token, _ string) (*AgentScope, error) {
	return &AgentScope{VaultID: "vault-1", VaultName: "default", ActorID: token}, nil
}

type loadMinter struct {
	minted, revoked atomic.Int64
}

func (m *loadMinter) Mint(context.Context, AgentScope, *DatabaseService) (*Lease, error) {
	id := m.minted.Add(1)
	return &Lease{ID: fmt.Sprintf("lease-%d", id), Username: "v-user", Password: "pw", ExpiresAt: time.Now().Add(time.Hour), Renewable: true}, nil
}

func (m *loadMinter) Renew(context.Context, string, time.Duration) (time.Time, error) {
	return time.Now().Add(time.Hour), nil
}

func (m *loadMinter) Revoke(context.Context, string) error {
	m.revoked.Add(1)
	return nil
}

type loadPGSession struct {
	conn net.Conn
	fe   *pgproto3.Frontend
	lat  []time.Duration
	errs int
}

func dialLoadPG(addr, token string) (*loadPGSession, error) {
	conn, err := net.DialTimeout("tcp", addr, 30*time.Second)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	fe := pgproto3.NewFrontend(conn, conn)
	fe.Send(&pgproto3.StartupMessage{ProtocolVersion: pgproto3.ProtocolVersionNumber, Parameters: map[string]string{"user": "agent", "database": "appdb"}})
	if err := fe.Flush(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	for {
		msg, err := fe.Receive()
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		switch m := msg.(type) {
		case *pgproto3.AuthenticationCleartextPassword:
			fe.Send(&pgproto3.PasswordMessage{Password: token})
			if err := fe.Flush(); err != nil {
				_ = conn.Close()
				return nil, err
			}
		case *pgproto3.ReadyForQuery:
			return &loadPGSession{conn: conn, fe: fe}, nil
		case *pgproto3.ErrorResponse:
			_ = conn.Close()
			return nil, fmt.Errorf("%s (%s)", m.Message, m.Code)
		}
	}
}

func (s *loadPGSession) query(errs *loadPGErrors) {
	start := time.Now()
	_ = s.conn.SetDeadline(start.Add(30 * time.Second))
	s.fe.Send(&pgproto3.Query{String: "SELECT 1"})
	if err := s.fe.Flush(); err != nil {
		s.errs++
		errs.add(err)
		return
	}
	for {
		msg, err := s.fe.Receive()
		if err != nil {
			s.errs++
			errs.add(err)
			return
		}
		switch m := msg.(type) {
		case *pgproto3.ErrorResponse:
			s.errs++
			errs.add(fmt.Errorf("%s (%s)", m.Message, m.Code))
		case *pgproto3.ReadyForQuery:
			s.lat = append(s.lat, time.Since(start))
			return
		}
	}
}

type loadPGErrors struct {
	mu   sync.Mutex
	seen map[string]int
}

func (e *loadPGErrors) add(err error) {
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

func (e *loadPGErrors) top() string {
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

func parallelPG(sessions []*loadPGSession, fn func(s *loadPGSession)) {
	var wg sync.WaitGroup
	for _, s := range sessions {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fn(s)
		}()
	}
	wg.Wait()
}

func collectPG(sessions []*loadPGSession) (lat []time.Duration, errs int) {
	for _, s := range sessions {
		lat = append(lat, s.lat...)
		errs += s.errs
		s.lat, s.errs = nil, 0
	}
	return lat, errs
}

func TestLoadPostgres(t *testing.T) {
	t.Logf("descriptor limit %d", loadstat.RaiseFDLimit())
	for _, mode := range []string{"direct", "broker"} {
		for _, n := range loadstat.Levels(t) {
			t.Run(fmt.Sprintf("%s/%d", mode, n), func(t *testing.T) { runLoadPostgres(t, mode, n) })
		}
	}
}

func runLoadPostgres(t *testing.T, mode string, n int) {
	if raw := os.Getenv("LOADTEST_MODES"); raw != "" && !strings.Contains(","+raw+",", ","+mode+",") {
		t.Skip("mode not selected by LOADTEST_MODES")
	}
	perSession := 4 // agent, broker's agent side, broker's upstream side, backend
	if mode == "direct" {
		perSession = 2
	}
	loadstat.Budget(t, n, perSession)
	setupConc := loadstat.Int(t, "LOADTEST_SETUP_CONC", 64)
	pacedReqs := loadstat.Int(t, "LOADTEST_PACED_REQS", 5)
	pace := time.Duration(loadstat.Int(t, "LOADTEST_PACE_MS", 1000)) * time.Millisecond
	satReqs := loadstat.Int(t, "LOADTEST_SAT_REQS", 20)
	dbBudget := loadstat.Int(t, "LOADTEST_DB_BUDGET", n)

	backend := startLoadBackend(t)
	dialAddr := backend.ln.Addr().String()
	minter := &loadMinter{}
	if mode == "broker" {
		_, dialAddr = startBroker(t, Options{
			Auth:      loadAuth{},
			Databases: &fakeResolver{svc: &DatabaseService{Name: "analytics", Addr: backend.ln.Addr().String(), Mount: "database", Role: "readonly", SSLMode: "disable", MaxConns: dbBudget}},
			Leases:    minter,
			MaxConns:  max(n, 10000),
		})
	}

	errs := &loadPGErrors{}
	base := loadstat.Take()
	stop := loadstat.Profile(t, fmt.Sprintf("pg-%s-%d", mode, n))
	defer stop()

	sessions := make([]*loadPGSession, n)
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
			s, err := dialLoadPG(dialAddr, fmt.Sprintf("tok-%d", i))
			if err != nil {
				failed.Add(1)
				errs.add(err)
				return
			}
			setupLat[i] = time.Since(start)
			sessions[i] = s
		}()
	}
	wg.Wait()
	var live []*loadPGSession
	var setup []time.Duration
	for i, s := range sessions {
		if s != nil {
			live = append(live, s)
			setup = append(setup, setupLat[i])
		}
	}
	setupP50, setupP99, _ := loadstat.Percentiles(setup)
	held := loadstat.Take().Delta(base)
	m := max(len(live), 1)

	startPaced := time.Now()
	parallelPG(live, func(s *loadPGSession) {
		t0 := time.Now().Add(time.Duration(time.Now().UnixNano() % int64(pace)))
		for k := range pacedReqs {
			time.Sleep(time.Until(t0.Add(time.Duration(k) * pace)))
			s.query(errs)
		}
	})
	pacedElapsed := time.Since(startPaced)
	pacedLat, pacedErr := collectPG(live)
	pacedP50, pacedP99, _ := loadstat.Percentiles(pacedLat)

	gate := make(chan struct{})
	var ready sync.WaitGroup
	ready.Add(len(live))
	go func() {
		ready.Wait()
		close(gate)
	}()
	startSat := time.Now()
	parallelPG(live, func(s *loadPGSession) {
		ready.Done()
		<-gate
		for range satReqs {
			s.query(errs)
		}
	})
	satElapsed := time.Since(startSat)
	satLat, satErr := collectPG(live)
	satP50, satP99, _ := loadstat.Percentiles(satLat)

	for _, s := range live {
		s.fe.Send(&pgproto3.Terminate{})
		_ = s.fe.Flush()
		_ = s.conn.Close()
	}
	leaked := "n/a"
	if mode == "broker" {
		deadline := time.Now().Add(30 * time.Second)
		for minter.revoked.Load() < minter.minted.Load() && time.Now().Before(deadline) {
			time.Sleep(50 * time.Millisecond)
		}
		leaked = fmt.Sprint(minter.minted.Load() - minter.revoked.Load())
	}

	loadstat.Row("pg", mode, n, "established", len(live), "setup_failed", failed.Load(),
		"setup_p50_ms", msPG(setupP50), "setup_p99_ms", msPG(setupP99),
		"paced_rps", fmt.Sprintf("%.0f", float64(len(pacedLat))/pacedElapsed.Seconds()), "paced_p50_ms", msPG(pacedP50), "paced_p99_ms", msPG(pacedP99), "paced_err", pacedErr,
		"sat_rps", fmt.Sprintf("%.0f", float64(len(satLat))/satElapsed.Seconds()), "sat_p50_ms", msPG(satP50), "sat_p99_ms", msPG(satP99), "sat_err", satErr,
		"heap_kib_per_session", held.Heap/uint64(m)/1024, "stack_kib_per_session", held.Stack/uint64(m)/1024,
		"goroutines_per_session", fmt.Sprintf("%.1f", float64(held.Goroutines)/float64(m)), "fds_per_session", fmt.Sprintf("%.1f", float64(held.FDs)/float64(m)),
		"leases_unrevoked", leaked, "top_error", errs.top())

	if len(live) == 0 || len(pacedLat)+len(satLat) == 0 {
		t.Fatalf("no working session: established %d of %d, successful requests %d: %s", len(live), n, len(pacedLat)+len(satLat), errs.top())
	}
	if n <= 1000 && (failed.Load() > 0 || len(live) < n || satErr+pacedErr > 0) {
		t.Errorf("below the break point: established %d of %d, setup failures %d, request errors %d: %s", len(live), n, failed.Load(), satErr+pacedErr, errs.top())
	}
}

func msPG(d time.Duration) string { return fmt.Sprintf("%.2f", float64(d.Microseconds())/1000) }
