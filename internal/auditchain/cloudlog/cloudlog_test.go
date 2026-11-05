package cloudlog

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var testResource = Resource{ProjectID: "proj", Location: "loc", ClusterName: "clu", Namespace: "ns", Pod: "broker-0", Container: "app"}

const secretMarker = "row-content-marker"

func row(seq int, extra string) string {
	b, _ := json.Marshal(map[string]any{"type": "gatehouse.audit.v1", "replica": "broker-0", "boot": 3, "seq": seq, "ts": "2026-11-02T10:00:00.123456789Z", "event": "session_open", "note": extra})
	return string(b) + "\n"
}

type received struct {
	mu      sync.Mutex
	batches [][]entry
}

func (r *received) all() []entry {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []entry
	for _, b := range r.batches {
		out = append(out, b...)
	}
	return out
}

func decode(t *testing.T, req *http.Request) []entry {
	t.Helper()
	var body struct {
		Entries []entry `json:"entries"`
	}
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		t.Errorf("request body: %v", err)
	}
	return body.Entries
}

func newSink(t *testing.T, url string, logs *bytes.Buffer, mutate func(*Options)) *Sink {
	t.Helper()
	opts := Options{LogID: "gatehouse-audit-broker", Resource: testResource, Client: http.DefaultClient, Endpoint: url,
		Logger: slog.New(slog.NewTextHandler(logs, nil)), Backoff: time.Millisecond, FlushEvery: 5 * time.Millisecond}
	if mutate != nil {
		mutate(&opts)
	}
	s, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func closeSink(t *testing.T, s *Sink) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.Close(ctx); err != nil {
		t.Fatalf("close: %v", err)
	}
}

func TestEntriesCarryTheAgentLabelsAndAStableInsertID(t *testing.T) {
	t.Parallel()
	var got received
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		got.mu.Lock()
		got.batches = append(got.batches, decode(t, req))
		got.mu.Unlock()
	}))
	defer srv.Close()
	var logs bytes.Buffer
	s := newSink(t, srv.URL, &logs, nil)
	_, _ = s.Write([]byte(row(7, "x")))
	closeSink(t, s)
	entries := got.all()
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	e := entries[0]
	if e.LogName != "projects/proj/logs/gatehouse-audit-broker" || e.Resource.Type != "k8s_container" || e.InsertID != "broker-0.3.7" || e.Severity != "INFO" {
		t.Errorf("entry = %+v", e)
	}
	want := map[string]string{"project_id": "proj", "location": "loc", "cluster_name": "clu", "namespace_name": "ns", "pod_name": "broker-0", "container_name": "app"}
	for k, v := range want {
		if e.Resource.Labels[k] != v {
			t.Errorf("label %s = %q, want %q", k, e.Resource.Labels[k], v)
		}
	}
	if e.Timestamp != "2026-11-02T10:00:00.123456789Z" {
		t.Errorf("timestamp = %q", e.Timestamp)
	}
	var payload map[string]any
	if err := json.Unmarshal(e.JSONPayload, &payload); err != nil || payload["type"] != "gatehouse.audit.v1" || payload["seq"] != float64(7) {
		t.Errorf("payload = %s (%v)", e.JSONPayload, err)
	}
}

func TestLongReplicaNamesHashToAValidInsertID(t *testing.T) {
	t.Parallel()
	id := insertID(strings.Repeat("a", 200), 1, 2)
	if len(id) > maxInsertID || id != insertID(strings.Repeat("a", 200), 1, 2) {
		t.Fatalf("insertID = %q", id)
	}
}

func TestRetriesOn429And5xxWithTheSameRows(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	var statuses = []int{http.StatusTooManyRequests, http.StatusServiceUnavailable, http.StatusOK}
	var seen [][]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		var ids []string
		for _, e := range decode(t, req) {
			ids = append(ids, e.InsertID)
		}
		seen = append(seen, ids)
		w.WriteHeader(statuses[len(seen)-1])
	}))
	defer srv.Close()
	var logs bytes.Buffer
	s := newSink(t, srv.URL, &logs, nil)
	_, _ = s.Write([]byte(row(1, "")))
	_, _ = s.Write([]byte(row(2, "")))
	closeSink(t, s)
	if len(seen) != 3 {
		t.Fatalf("%d requests, want 3", len(seen))
	}
	for _, ids := range seen {
		if strings.Join(ids, ",") != "broker-0.3.1,broker-0.3.2" {
			t.Errorf("retry carried %v", ids)
		}
	}
	if s.delivered.Load() != 2 || s.droppedFailed.Load() != 0 {
		t.Errorf("delivered %d dropped %d", s.delivered.Load(), s.droppedFailed.Load())
	}
}

func TestClientErrorsAreFinalAndDropsLogNoRowContent(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		mu.Lock()
		calls++
		mu.Unlock()
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, secretMarker)
	}))
	defer srv.Close()
	var logs bytes.Buffer
	s := newSink(t, srv.URL, &logs, nil)
	_, _ = s.Write([]byte(row(1, secretMarker)))
	closeSink(t, s)
	if calls != 1 {
		t.Errorf("%d requests, want 1 for a 403", calls)
	}
	out := logs.String()
	if !strings.Contains(out, "status 403") || !strings.Contains(out, "delivery_failed=1") {
		t.Errorf("operational log = %q", out)
	}
	if strings.Contains(out, secretMarker) {
		t.Errorf("operational log carries row or response content: %q", out)
	}
}

func TestPartialSuccessKeepsTheRestOfTheBatchAndCountsRejectedRows(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	var partial []bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var body struct {
			PartialSuccess bool `json:"partialSuccess"`
		}
		raw, _ := io.ReadAll(req.Body)
		_ = json.Unmarshal(raw, &body)
		mu.Lock()
		partial = append(partial, body.PartialSuccess)
		mu.Unlock()
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":{"code":400,"status":"INVALID_ARGUMENT","message":"`+secretMarker+`","details":[{"@type":"type.googleapis.com/google.logging.v2.WriteLogEntriesPartialErrors","logEntryErrors":{"1":{"code":3,"message":"`+secretMarker+`"}}}]}}`)
	}))
	defer srv.Close()
	var logs bytes.Buffer
	s := newSink(t, srv.URL, &logs, nil)
	for i := 1; i <= 3; i++ {
		_, _ = s.Write([]byte(row(i, secretMarker)))
	}
	closeSink(t, s)
	if len(partial) != 1 || !partial[0] {
		t.Errorf("partialSuccess sent %v, want one request with true", partial)
	}
	if s.delivered.Load() != 2 || s.droppedFailed.Load() != 1 {
		t.Errorf("delivered %d dropped %d, want 2 and 1", s.delivered.Load(), s.droppedFailed.Load())
	}
	out := logs.String()
	if !strings.Contains(out, "rows rejected") || !strings.Contains(out, "rejected=1") || !strings.Contains(out, "codes=[3]") || strings.Contains(out, secretMarker) {
		t.Errorf("operational log = %q", out)
	}
}

func TestEachAttemptIsCappedSoTheWorstCaseFitsTheCheckWait(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	var mu sync.Mutex
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		mu.Lock()
		calls++
		mu.Unlock()
		select {
		case <-req.Context().Done():
		case <-release:
		}
	}))
	defer srv.Close()
	defer close(release)
	var logs bytes.Buffer
	s := newSink(t, srv.URL, &logs, func(o *Options) { o.Attempts = 2; o.AttemptTimeout = 50 * time.Millisecond })
	_, _ = s.Write([]byte(row(1, "")))
	start := time.Now()
	closeSink(t, s)
	mu.Lock()
	got := calls
	mu.Unlock()
	if got != 2 || s.droppedFailed.Load() != 1 || time.Since(start) > 5*time.Second {
		t.Errorf("calls %d dropped %d after %v, want 2 and 1 within the cap", got, s.droppedFailed.Load(), time.Since(start))
	}
}

func TestRetriesStopAfterTheAttemptBudget(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		mu.Lock()
		calls++
		mu.Unlock()
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	var logs bytes.Buffer
	s := newSink(t, srv.URL, &logs, func(o *Options) { o.Attempts = 3 })
	_, _ = s.Write([]byte(row(1, "")))
	closeSink(t, s)
	if calls != 3 || s.droppedFailed.Load() != 1 {
		t.Errorf("calls %d dropped %d, want 3 and 1", calls, s.droppedFailed.Load())
	}
}

func TestFullQueueDropsWithoutBlockingTheWriter(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { <-release }))
	defer srv.Close()
	var logs bytes.Buffer
	s := newSink(t, srv.URL, &logs, func(o *Options) { o.Queue = 2; o.Batch = 1 })
	done := make(chan struct{})
	go func() {
		for i := range 50 {
			_, _ = s.Write([]byte(row(i, "")))
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Write blocked on a stalled endpoint")
	}
	if s.droppedFull.Load() == 0 {
		t.Error("a stalled endpoint dropped nothing")
	}
	close(release)
	closeSink(t, s)
	if !strings.Contains(logs.String(), "queue_full_or_closed=") {
		t.Errorf("drops not logged: %q", logs.String())
	}
}

func TestCloseFlushesQueuedRows(t *testing.T) {
	t.Parallel()
	var got received
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		got.mu.Lock()
		got.batches = append(got.batches, decode(t, req))
		got.mu.Unlock()
	}))
	defer srv.Close()
	var logs bytes.Buffer
	s := newSink(t, srv.URL, &logs, func(o *Options) { o.FlushEvery = time.Hour; o.Batch = 1000 })
	for i := range 25 {
		_, _ = s.Write([]byte(row(i, "")))
	}
	closeSink(t, s)
	if n := len(got.all()); n != 25 {
		t.Errorf("delivered %d rows on close, want 25", n)
	}
	if _, err := s.Write([]byte(row(99, ""))); err != nil || s.droppedFull.Load() != 1 {
		t.Errorf("write after close: err %v drops %d", err, s.droppedFull.Load())
	}
}

func TestCloseEndsAtItsDeadlineAndCountsWhatItLeft(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { <-release }))
	defer srv.Close()
	defer close(release)
	var logs bytes.Buffer
	s := newSink(t, srv.URL, &logs, func(o *Options) { o.Batch = 1 })
	for i := range 3 {
		_, _ = s.Write([]byte(row(i, "")))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := s.Close(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("close = %v, want deadline exceeded", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Error("close outran its deadline")
	}
	if s.droppedFailed.Load() == 0 {
		t.Error("rows left behind were not counted")
	}
}

// slowTripper ignores the request context, as a token refresh inside oauth2.Transport does.
type slowTripper struct {
	calls atomic.Int32
	delay time.Duration
}

func (r *slowTripper) RoundTrip(*http.Request) (*http.Response, error) {
	r.calls.Add(1)
	time.Sleep(r.delay)
	return nil, errors.New("stalled")
}

func TestCloseDropsQueuedBatchesOncePastItsDeadline(t *testing.T) {
	t.Parallel()
	rt := &slowTripper{delay: 300 * time.Millisecond}
	var logs bytes.Buffer
	s := newSink(t, "http://example.invalid", &logs, func(o *Options) {
		o.Batch = 1
		o.Attempts = 1
		o.Client = &http.Client{Transport: rt}
	})
	for i := range 5 {
		_, _ = s.Write([]byte(row(i, "")))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_ = s.Close(ctx)
	if elapsed := time.Since(start); elapsed > 900*time.Millisecond {
		t.Errorf("close took %v, want one stalled batch at most", elapsed)
	}
	if n := rt.calls.Load(); n > 2 {
		t.Errorf("%d batches posted, want the rest dropped after the deadline", n)
	}
	if s.droppedFailed.Load() != 5 {
		t.Errorf("dropped %d rows, want all 5 counted", s.droppedFailed.Load())
	}
}

func TestNonJSONLinesAreDroppedNotSent(t *testing.T) {
	t.Parallel()
	var got received
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		got.mu.Lock()
		got.batches = append(got.batches, decode(t, req))
		got.mu.Unlock()
	}))
	defer srv.Close()
	var logs bytes.Buffer
	s := newSink(t, srv.URL, &logs, nil)
	_, _ = s.Write([]byte("not json\n"))
	_, _ = s.Write([]byte(row(1, "")))
	closeSink(t, s)
	if n := len(got.all()); n != 1 || s.droppedFailed.Load() != 1 {
		t.Errorf("sent %d rows, dropped %d; want 1 and 1", n, s.droppedFailed.Load())
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("stdout closed") }

func TestTeeKeepsPrimaryFailureAndSkipsTheSink(t *testing.T) {
	t.Parallel()
	var got received
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		got.mu.Lock()
		got.batches = append(got.batches, decode(t, req))
		got.mu.Unlock()
	}))
	defer srv.Close()
	var logs bytes.Buffer
	s := newSink(t, srv.URL, &logs, nil)
	if _, err := Tee(failWriter{}, s).Write([]byte(row(1, ""))); err == nil {
		t.Error("primary failure was swallowed")
	}
	var primary bytes.Buffer
	line := row(2, "")
	if n, err := Tee(&primary, s).Write([]byte(line)); err != nil || n != len(line) || primary.String() != line {
		t.Errorf("tee wrote %d, %v, %q", n, err, primary.String())
	}
	closeSink(t, s)
	if entries := got.all(); len(entries) != 1 || entries[0].InsertID != "broker-0.3.2" {
		t.Errorf("sink saw %+v", entries)
	}
}

func TestNewRequiresEveryLabel(t *testing.T) {
	t.Parallel()
	r := testResource
	r.Pod = ""
	if _, err := New(Options{LogID: "x", Resource: r, Client: http.DefaultClient}); err == nil {
		t.Error("a missing pod label was accepted")
	}
	if _, err := New(Options{Resource: testResource, Client: http.DefaultClient}); err == nil {
		t.Error("a missing log name was accepted")
	}
}

func TestNewChecksTheLogIDAndEscapesItInTheLogName(t *testing.T) {
	t.Parallel()
	for _, bad := range []string{"has space", "bad%2Fid", strings.Repeat("a", 513)} {
		if _, err := New(Options{LogID: bad, Resource: testResource, Client: http.DefaultClient}); err == nil {
			t.Errorf("log name %q was accepted", bad)
		}
	}
	s, err := New(Options{LogID: "team/audit", Resource: testResource, Client: http.DefaultClient})
	if err != nil {
		t.Fatal(err)
	}
	closeSink(t, s)
	if want := "projects/proj/logs/team%2Faudit"; s.logName != want {
		t.Errorf("logName = %q, want %q", s.logName, want)
	}
}
