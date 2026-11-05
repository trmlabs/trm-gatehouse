package taskrelay

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/Infisical/agent-vault/internal/workloadidentity"
)

// activity holds last-seen times per agent Sandbox (no target, bytes or profile), keyed by controller so a replaced Pod keeps its history.
type activity struct {
	mu        sync.Mutex
	started   time.Time
	retention time.Duration
	owners    map[string]activityEntry // by controller UID
	durable   *durable
}

type activityEntry struct {
	namespace string
	lastSeen  time.Time
	pushed    time.Time // the last time the broker accepted for it
}

const defaultActivityRetention = 24 * time.Hour

func newActivity(now time.Time, retention time.Duration) *activity {
	return &activity{started: now, retention: retention, owners: map[string]activityEntry{}}
}

func (a *activity) seen(att workloadidentity.Attestation, when time.Time) {
	a.record(att.Namespace, att.OwnerUID, when)
}

func (a *activity) record(namespace, owner string, when time.Time) {
	if a == nil || owner == "" {
		return
	}
	a.mu.Lock()
	if e, ok := a.owners[owner]; !ok || when.After(e.lastSeen) {
		a.owners[owner] = activityEntry{namespace: namespace, lastSeen: when, pushed: e.pushed}
	}
	a.mu.Unlock()
}

func (a *activity) pending() []SandboxActivity {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []SandboxActivity
	for owner, e := range a.owners {
		if e.lastSeen.After(e.pushed) {
			out = append(out, SandboxActivity{Namespace: e.namespace, OwnerUID: owner, LastSeen: e.lastSeen.UTC()})
		}
	}
	return out
}

// repushMissing re-marks entries the broker no longer holds (a restored or emptied table).
func (a *activity) repushMissing(view []SandboxActivity) {
	held := make(map[string]time.Time, len(view))
	for _, r := range view {
		held[r.OwnerUID] = r.LastSeen
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for owner, e := range a.owners {
		// The broker keeps milliseconds.
		if !e.pushed.IsZero() && held[owner].Before(e.pushed.Truncate(time.Millisecond)) {
			e.pushed = time.Time{}
			a.owners[owner] = e
		}
	}
}

func (a *activity) repushAll() {
	a.mu.Lock()
	defer a.mu.Unlock()
	for owner, e := range a.owners {
		e.pushed = time.Time{}
		a.owners[owner] = e
	}
}

func (a *activity) accepted(rows []SandboxActivity) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, r := range rows {
		if e, ok := a.owners[r.OwnerUID]; ok && r.LastSeen.After(e.pushed) {
			e.pushed = r.LastSeen
			a.owners[r.OwnerUID] = e
		}
	}
}

type ActivityReport struct {
	// ReplicaStarted: a Sandbox absent from Sandboxes was unused since then or beyond RetentionSeconds.
	ReplicaStarted   time.Time         `json:"replicaStarted"`
	RetentionSeconds int64             `json:"retentionSeconds"`
	Sandboxes        []SandboxActivity `json:"sandboxes"`
	// Durable: Sandboxes include the broker's view of every replica.
	Durable        bool             `json:"durable"`
	HistoryStreams map[string]int64 `json:"historyStreams,omitempty"`
	// AckedSeq above its stream's sequence, or a missing stream, means the broker lost writes.
	// FirstAcked is zero until a report is accepted.
	Replica    string    `json:"replica,omitempty"`
	AckedSeq   int64     `json:"ackedSeq,omitempty"`
	FirstAcked time.Time `json:"firstAcked,omitzero"`
	// HistoryStarted is zero for a new or emptied history, which vouches for nothing.
	HistoryStarted time.Time `json:"historyStarted,omitzero"`
	// BrokerUnreachableAt is the last failed report or read; the janitor holds while any live replica's is within its idle window.
	BrokerUnreachableAt time.Time `json:"brokerUnreachableAt,omitzero"`
}

type SandboxActivity struct {
	Namespace string    `json:"namespace"`
	OwnerUID  string    `json:"ownerUID"`
	LastSeen  time.Time `json:"lastSeen"`
}

func (a *activity) report(now time.Time) ActivityReport {
	a.mu.Lock()
	out := ActivityReport{ReplicaStarted: a.started.UTC(), RetentionSeconds: int64(a.retention / time.Second), Sandboxes: make([]SandboxActivity, 0, len(a.owners))}
	for owner, e := range a.owners {
		if now.Sub(e.lastSeen) > a.retention {
			delete(a.owners, owner)
			continue
		}
		out.Sandboxes = append(out.Sandboxes, SandboxActivity{Namespace: e.namespace, OwnerUID: owner, LastSeen: e.lastSeen.UTC()})
	}
	a.mu.Unlock()
	sort.Slice(out.Sandboxes, func(i, j int) bool { return out.Sandboxes[i].OwnerUID < out.Sandboxes[j].OwnerUID })
	return out
}

const (
	ActivityPath      = "/v1/activity"
	ActivityLocalPath = "/v1/activity/local"
)

// handler serves GET on the two activity paths only; everything else is 404.
func (a *activity) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet || (req.URL.Path != ActivityPath && req.URL.Path != ActivityLocalPath) || req.URL.RawQuery != "" {
			http.NotFound(w, req)
			return
		}
		report := a.report(time.Now())
		if a.durable != nil {
			report.AckedSeq, report.FirstAcked = a.durable.verification()
			report.Replica = a.durable.replica
			if req.URL.Path == ActivityPath {
				report = a.withDurable(req.Context(), report)
			}
			report.BrokerUnreachableAt = a.durable.unreachable()
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(report)
	})
}

func (a *activity) withDurable(ctx context.Context, report ActivityReport) ActivityReport {
	// Read the acknowledgment before the view so one given during the read is not mistaken for a loss.
	acked, _ := a.durable.verification()
	view, e := a.durable.read(ctx)
	if e != nil {
		// A janitor that gave up waiting is not the broker failing.
		if ctx.Err() == nil {
			a.durable.failed()
		}
		return report
	}
	a.repushMissing(view.sandboxes)
	if acked > view.streams[a.durable.replica] {
		// The store lost acknowledged writes: report everything again, even if empty, to restart the history.
		a.repushAll()
		a.durable.oweLoss()
	}
	rows, retention := view.sandboxes, view.retention
	byOwner := make(map[string]int, len(report.Sandboxes))
	for i, s := range report.Sandboxes {
		byOwner[s.OwnerUID] = i
	}
	for _, r := range rows {
		if i, ok := byOwner[r.OwnerUID]; ok {
			if r.LastSeen.After(report.Sandboxes[i].LastSeen) {
				report.Sandboxes[i].LastSeen = r.LastSeen.UTC()
			}
			continue
		}
		byOwner[r.OwnerUID] = len(report.Sandboxes)
		report.Sandboxes = append(report.Sandboxes, SandboxActivity{Namespace: r.Namespace, OwnerUID: r.OwnerUID, LastSeen: r.LastSeen.UTC()})
	}
	sort.Slice(report.Sandboxes, func(i, j int) bool { return report.Sandboxes[i].OwnerUID < report.Sandboxes[j].OwnerUID })
	report.RetentionSeconds = min(report.RetentionSeconds, retention)
	report.Durable, report.HistoryStarted, report.HistoryStreams = true, view.historyStarted, view.streams
	return report
}
