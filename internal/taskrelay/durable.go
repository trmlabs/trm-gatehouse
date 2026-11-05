package taskrelay

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

// DurableActivityConfig keeps activity in the broker's shared store so it outlives this replica; reports go over the CONNECT upstream.
type DurableActivityConfig struct {
	PushSeconds int64 `json:"pushSeconds,omitempty"`
}

const (
	activityRecordPath = "/v1/proxy/activity"
	activityReadPath   = "/v1/proxy/activity/read"
	activityRecordRows = 5000
	finalPushTimeout   = 5 * time.Second
)

func (d *DurableActivityConfig) interval() time.Duration {
	if d.PushSeconds == 0 {
		return 15 * time.Second
	}
	return time.Duration(d.PushSeconds) * time.Second
}

type durable struct {
	activity *activity
	upstream UpstreamConfig
	interval time.Duration

	mu sync.Mutex
	// A replica with no acknowledgment cannot vouch the broker's history is whole, so the janitor holds until one has.
	replica    string
	acked      int64
	firstAcked time.Time
	// An acknowledgment older than keep or the replica's retention is forgotten: the broker may have pruned the stream.
	lastAcked time.Time
	keep      time.Duration
	// lossOwed forces the next report even with nothing new, once per loss, so the broker restarts the history.
	lossOwed      bool
	unreachableAt time.Time
}

func (d *durable) failed() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.unreachableAt = time.Now().UTC()
}

func (d *durable) unreachable() time.Time {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.unreachableAt
}

func (d *durable) oweLoss() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.lossOwed = true
}

func (d *durable) verification() (int64, time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if time.Since(d.lastAcked) > min(d.keep, d.activity.retention) {
		return 0, d.firstAcked
	}
	return d.acked, d.firstAcked
}

func newReplicaID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (d *durable) run(ctx context.Context) {
	ticker := time.NewTicker(d.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			final, cancel := context.WithTimeout(context.Background(), finalPushTimeout)
			_ = d.push(final)
			cancel()
			return
		case <-ticker.C:
			_ = d.push(ctx)
		}
	}
}

// push reports Sandboxes newer than the broker's last acceptance; after a reported loss every held entry is re-sent, once per loss.
func (d *durable) push(ctx context.Context) error {
	rows := d.activity.pending()
	d.mu.Lock()
	owed := d.lossOwed
	d.mu.Unlock()
	for start := 0; start < len(rows) || (start == 0 && owed); start += activityRecordRows {
		chunk := rows[start:min(start+activityRecordRows, len(rows))]
		acked, _ := d.verification()
		body, e := json.Marshal(map[string]any{"sandboxes": chunk, "replica": d.replica, "ackedSeq": acked})
		if e != nil {
			return e
		}
		status, b, e := brokerPost(ctx, d.upstream, activityRecordPath, body, 4096)
		if e != nil {
			d.failed()
			return e
		}
		var answer struct {
			Seq              int64 `json:"seq"`
			Lost             bool  `json:"lost"`
			RetentionSeconds int64 `json:"retentionSeconds"`
		}
		if status != http.StatusOK || json.Unmarshal(b, &answer) != nil || answer.Seq <= 0 || answer.RetentionSeconds <= 0 {
			d.failed()
			return errDenied
		}
		d.activity.accepted(chunk)
		d.mu.Lock()
		d.acked, d.lastAcked, d.keep = answer.Seq, time.Now(), time.Duration(answer.RetentionSeconds)*time.Second
		d.lossOwed = false
		if d.firstAcked.IsZero() {
			d.firstAcked = time.Now()
		}
		d.mu.Unlock()
		if answer.Lost {
			d.activity.repushAll()
			return nil
		}
	}
	return nil
}

type durableView struct {
	sandboxes      []SandboxActivity
	retention      int64
	historyStarted time.Time
	streams        map[string]int64
}

func (d *durable) read(ctx context.Context) (durableView, error) {
	var view durableView
	for after := ""; ; {
		body, _ := json.Marshal(map[string]string{"after": after})
		status, b, e := brokerPost(ctx, d.upstream, activityReadPath, body, 64<<20)
		if e != nil {
			return view, e
		}
		var page struct {
			RetentionSeconds int64             `json:"retentionSeconds"`
			HistoryStarted   *time.Time        `json:"historyStarted"`
			Streams          map[string]int64  `json:"streams"`
			Sandboxes        []SandboxActivity `json:"sandboxes"`
			Next             string            `json:"next"`
		}
		if status != http.StatusOK || json.Unmarshal(b, &page) != nil || page.RetentionSeconds <= 0 || (page.Next != "" && page.Next <= after) {
			return view, errDenied
		}
		if after == "" {
			view.streams = page.Streams
			if page.HistoryStarted != nil {
				view.historyStarted = page.HistoryStarted.UTC()
			}
		}
		view.sandboxes, view.retention = append(view.sandboxes, page.Sandboxes...), page.RetentionSeconds
		if after = page.Next; after == "" {
			return view, nil
		}
	}
}
