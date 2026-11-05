// Package cloudlog copies audit rows to Cloud Logging entries.write; it never blocks or fails the chain.
package cloudlog

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

// Scope is the OAuth scope entries.write needs.
const Scope = "https://www.googleapis.com/auth/logging.write"

const (
	defaultEndpoint      = "https://logging.googleapis.com/v2/entries:write"
	defaultQueue         = 4096
	defaultBatch         = 100
	defaultFlushEvery    = time.Second
	defaultAttempts      = 5
	defaultBackoff       = 500 * time.Millisecond
	maxBackoff           = 10 * time.Second
	defaultAttemptCap    = 10 * time.Second
	maxInsertID          = 100
	dropReportEvery      = 10 * time.Second
	maxResponseDrainByte = 1 << 16
)

// logIDPattern is Cloud Logging's rule for a log ID.
var logIDPattern = regexp.MustCompile(`^[A-Za-z0-9_.\-/]{1,512}$`)

// Resource holds the labels the cluster agent would set, so a view filtered on them matches.
type Resource struct {
	ProjectID, Location, ClusterName, Namespace, Pod, Container string
}

// Valid reports whether every label is set.
func (r Resource) Valid() bool {
	return r.ProjectID != "" && r.Location != "" && r.ClusterName != "" && r.Namespace != "" && r.Pod != "" && r.Container != ""
}

// Options configures a Sink. Zero values take the defaults noted.
type Options struct {
	LogID    string       // log name within the project, such as gatehouse-audit-broker
	Resource Resource     // every label required
	Client   *http.Client // already authorized for Scope
	Logger   *slog.Logger // operational log; counts and status codes only, never rows
	// Endpoint is the entries.write URL. Default is the production API.
	Endpoint string
	// Queue is the most rows held for delivery; a full queue drops. Default 4096.
	Queue int
	// Batch is the most rows in one request. Default 100.
	Batch int
	// FlushEvery is how long a partial batch waits. Default 1s.
	FlushEvery time.Duration
	// Attempts is the tries per batch on 429, 5xx or a transport error. Default 5.
	Attempts int
	// AttemptTimeout caps one request, so the worst case across every attempt fits the audit check's wait. Default 10s.
	AttemptTimeout time.Duration
	// Backoff is the first retry delay, doubled to a 10s cap with jitter. Default 500ms.
	Backoff time.Duration
}

// Sink is a bounded queue and one delivery goroutine.
type Sink struct {
	opts    Options
	logName string

	mu     sync.RWMutex
	closed bool
	queue  chan []byte

	done   chan struct{}
	ctx    context.Context // cancelled when Close's deadline passes
	cancel context.CancelFunc

	droppedFull   atomic.Uint64
	droppedFailed atomic.Uint64
	delivered     atomic.Uint64
	reported      uint64
	reportedAt    time.Time
}

// New validates the options and starts delivery.
func New(opts Options) (*Sink, error) {
	if opts.LogID == "" || !opts.Resource.Valid() || opts.Client == nil {
		return nil, errors.New("cloud logging sink requires a log name, every resource label and an authorized client")
	}
	if !logIDPattern.MatchString(opts.LogID) {
		return nil, errors.New("cloud logging log name must be 1 to 512 letters, digits, and _ . - /")
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Endpoint == "" {
		opts.Endpoint = defaultEndpoint
	}
	if opts.Queue <= 0 {
		opts.Queue = defaultQueue
	}
	if opts.Batch <= 0 {
		opts.Batch = defaultBatch
	}
	if opts.FlushEvery <= 0 {
		opts.FlushEvery = defaultFlushEvery
	}
	if opts.Attempts <= 0 {
		opts.Attempts = defaultAttempts
	}
	if opts.AttemptTimeout <= 0 {
		opts.AttemptTimeout = defaultAttemptCap
	}
	if opts.Backoff <= 0 {
		opts.Backoff = defaultBackoff
	}
	s := &Sink{
		opts:    opts,
		logName: "projects/" + opts.Resource.ProjectID + "/logs/" + url.PathEscape(opts.LogID),
		queue:   make(chan []byte, opts.Queue),
		done:    make(chan struct{}),
	}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	go s.run()
	return s, nil
}

// Write queues a copy of one row line; it never fails or blocks, and a full or closed sink counts a drop.
func (s *Sink) Write(p []byte) (int, error) {
	line := bytes.TrimSpace(p)
	if len(line) == 0 {
		return len(p), nil
	}
	line = bytes.Clone(line)
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		s.droppedFull.Add(1)
		return len(p), nil
	}
	select {
	case s.queue <- line:
	default:
		s.droppedFull.Add(1)
	}
	return len(p), nil
}

// Close delivers what is queued until ctx ends; rows still queued then count as dropped.
func (s *Sink) Close(ctx context.Context) error {
	s.mu.Lock()
	if !s.closed {
		s.closed = true
		close(s.queue)
	}
	s.mu.Unlock()
	defer s.cancel()
	select {
	case <-s.done:
		return nil
	case <-ctx.Done():
		s.cancel()
		<-s.done
		return ctx.Err()
	}
}

// Tee writes primary first and returns its result; the sink sees a row only after primary took it.
func Tee(primary io.Writer, sink *Sink) io.Writer { return tee{primary, sink} }

type tee struct {
	primary io.Writer
	sink    *Sink
}

func (t tee) Write(p []byte) (int, error) {
	n, err := t.primary.Write(p)
	if err != nil {
		return n, err
	}
	_, _ = t.sink.Write(p[:n])
	return n, nil
}

func (s *Sink) run() {
	defer close(s.done)
	tick := time.NewTicker(s.opts.FlushEvery)
	defer tick.Stop()
	batch := make([][]byte, 0, s.opts.Batch)
	for {
		select {
		case line, ok := <-s.queue:
			if !ok {
				s.flush(batch)
				s.report(true)
				return
			}
			batch = append(batch, line)
			if len(batch) >= s.opts.Batch {
				s.flush(batch)
				batch = batch[:0]
			}
		case <-tick.C:
			s.flush(batch)
			batch = batch[:0]
			s.report(false)
		}
	}
}

func (s *Sink) flush(batch [][]byte) {
	if len(batch) == 0 {
		return
	}
	// Past Close's deadline nothing more is posted, so a stalled token fetch cannot hold shutdown.
	if s.ctx.Err() != nil {
		s.droppedFailed.Add(uint64(len(batch)))
		return
	}
	body, kept := s.build(batch)
	if kept == 0 {
		return
	}
	codes, err := s.send(body)
	rejected := len(codes)
	if err != nil {
		s.droppedFailed.Add(uint64(kept))
		s.opts.Logger.Warn("audit cloud logging: batch dropped", slog.Int("rows", kept), slog.String("reason", err.Error()))
		return
	}
	if rejected > kept {
		rejected = kept
	}
	if rejected > 0 {
		s.droppedFailed.Add(uint64(rejected))
		s.opts.Logger.Warn("audit cloud logging: rows rejected", slog.Int("rejected", rejected), slog.Int("rows", kept), slog.Any("codes", distinctCodes(codes)))
	}
	s.delivered.Add(uint64(kept - rejected))
}

type entry struct {
	LogName     string            `json:"logName"`
	Resource    monitoredResource `json:"resource"`
	JSONPayload json.RawMessage   `json:"jsonPayload"`
	Timestamp   string            `json:"timestamp,omitempty"`
	InsertID    string            `json:"insertId,omitempty"`
	Severity    string            `json:"severity"`
}

type monitoredResource struct {
	Type   string            `json:"type"`
	Labels map[string]string `json:"labels"`
}

// build makes the request body; a line that is not a JSON object is dropped and counted.
func (s *Sink) build(batch [][]byte) ([]byte, int) {
	r := s.opts.Resource
	res := monitoredResource{Type: "k8s_container", Labels: map[string]string{
		"project_id": r.ProjectID, "location": r.Location, "cluster_name": r.ClusterName,
		"namespace_name": r.Namespace, "pod_name": r.Pod, "container_name": r.Container,
	}}
	entries := make([]entry, 0, len(batch))
	for _, line := range batch {
		var head struct {
			Replica string `json:"replica"`
			Boot    uint64 `json:"boot"`
			Seq     uint64 `json:"seq"`
			TS      string `json:"ts"`
		}
		if json.Unmarshal(line, &head) != nil || line[0] != '{' {
			s.droppedFailed.Add(1)
			continue
		}
		e := entry{LogName: s.logName, Resource: res, JSONPayload: line, Severity: "INFO"}
		if t, err := time.Parse(time.RFC3339Nano, head.TS); err == nil {
			e.Timestamp = t.UTC().Format(time.RFC3339Nano)
			// Entries with one insertId, timestamp and log name are deduplicated, so a retry cannot double a row.
			e.InsertID = insertID(head.Replica, head.Boot, head.Seq)
		}
		entries = append(entries, e)
	}
	if len(entries) == 0 {
		return nil, 0
	}
	// logName, resource and severity ride on each entry; partialSuccess keeps one rejected entry from failing the batch.
	body, err := json.Marshal(struct {
		Entries        []entry `json:"entries"`
		PartialSuccess bool    `json:"partialSuccess"`
	}{entries, true})
	if err != nil {
		s.droppedFailed.Add(uint64(len(entries)))
		return nil, 0
	}
	return body, len(entries)
}

// jitter is a random duration in [0, max].
func jitter(max time.Duration) time.Duration {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)+1))
	if err != nil {
		return 0
	}
	return time.Duration(n.Int64())
}

func insertID(replica string, boot, seq uint64) string {
	id := fmt.Sprintf("%s.%d.%d", replica, boot, seq)
	if len(id) <= maxInsertID {
		return id
	}
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:])
}

// distinctCodes is the sorted set of per-entry status codes, never their messages.
func distinctCodes(codes []int) []int {
	out := slices.Clone(codes)
	slices.Sort(out)
	return slices.Compact(out)
}

// send retries 429, 5xx and transport errors with backoff; it returns the status code of each entry the API rejected, and the error names a status or class, never body text.
func (s *Sink) send(body []byte) ([]int, error) {
	wait := s.opts.Backoff
	var last error
	for attempt := 1; attempt <= s.opts.Attempts; attempt++ {
		rejected, retry, err := s.post(body)
		if err == nil {
			return rejected, nil
		}
		last = err
		if !retry || attempt == s.opts.Attempts {
			break
		}
		// Jitter keeps replicas from retrying in step.
		delay := wait/2 + jitter(wait/2)
		select {
		case <-time.After(delay):
		case <-s.ctx.Done():
			return nil, fmt.Errorf("%w after %d attempts: shutdown", last, attempt)
		}
		wait = min(2*wait, maxBackoff)
	}
	return nil, last
}

// partialErrors is the error detail entries.write returns, keyed by entry index, when partialSuccess skipped some entries.
type partialErrors struct {
	Error struct {
		Details []struct {
			LogEntryErrors map[string]struct {
				Code int `json:"code"`
			} `json:"logEntryErrors"`
		} `json:"details"`
	} `json:"error"`
}

// post makes one attempt; a 4xx that lists rejected entries is a delivery of the rest, with each rejected entry's status code returned.
func (s *Sink) post(body []byte) (rejected []int, retry bool, err error) {
	req, err := http.NewRequest(http.MethodPost, s.opts.Endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, false, errors.New("request")
	}
	req.Header.Set("Content-Type", "application/json")
	ctx, cancel := context.WithTimeout(s.ctx, s.opts.AttemptTimeout)
	defer cancel()
	resp, err := s.opts.Client.Do(req.WithContext(ctx))
	if err != nil {
		return nil, true, errors.New("transport error")
	}
	defer func() { _ = resp.Body.Close() }()
	reply, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseDrainByte))
	switch {
	case resp.StatusCode/100 == 2:
		return nil, false, nil
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		return nil, true, fmt.Errorf("status %d", resp.StatusCode)
	}
	var partial partialErrors
	if json.Unmarshal(reply, &partial) == nil {
		for _, d := range partial.Error.Details {
			if len(d.LogEntryErrors) > 0 {
				for _, e := range d.LogEntryErrors {
					rejected = append(rejected, e.Code)
				}
				return rejected, false, nil
			}
		}
	}
	return nil, false, fmt.Errorf("status %d", resp.StatusCode)
}

// report logs drop counts when they changed, at most every 10 seconds unless force.
func (s *Sink) report(force bool) {
	drops := s.droppedFull.Load() + s.droppedFailed.Load()
	if drops == s.reported || (!force && time.Since(s.reportedAt) < dropReportEvery) {
		return
	}
	s.reported, s.reportedAt = drops, time.Now()
	s.opts.Logger.Warn("audit cloud logging: rows dropped",
		slog.Uint64("queue_full_or_closed", s.droppedFull.Load()), slog.Uint64("delivery_failed", s.droppedFailed.Load()), slog.Uint64("delivered", s.delivered.Load()))
}
