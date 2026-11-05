package workloadidentity

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/jackc/pgx/v5/pgconn"
)

// An admitted Pod counts as live only while it is the same Running Pod with its worker container running and its run annotation intact.
func TestPodRunningRereadsTheAdmittedPod(t *testing.T) {
	f := setupPool(t)
	f.pod["metadata"].(map[string]any)["annotations"] = map[string]any{brokercore.CursorRunAnnotation: "bc-1"}
	scope, err := f.r.Attest(context.Background(), f.token(f.c), workerIP)
	if err != nil {
		t.Fatal(err)
	}
	want := brokercore.PodRef{Namespace: "pool", Name: "worker-abc", UID: "pod-uid", Container: "agent"}
	if scope.Pod != want {
		t.Fatalf("Pod %+v, want %+v", scope.Pod, want)
	}
	if live, err := f.r.PodRunning(context.Background(), scope.Pod, "bc-1"); !live || err != nil {
		t.Fatalf("the admitted Pod is not live: %v", err)
	}
	meta := func() map[string]any { return f.pod["metadata"].(map[string]any) }
	status := func() map[string]any { return f.pod["status"].(map[string]any) }
	gone := map[string]func(){
		"another run":         func() { meta()["annotations"] = map[string]any{brokercore.CursorRunAnnotation: "bc-2"} },
		"no run":              func() { delete(meta(), "annotations") },
		"deleted":             func() { f.podStatus = 404 },
		"terminating":         func() { meta()["deletionTimestamp"] = time.Now().UTC().Format(time.RFC3339) },
		"succeeded":           func() { status()["phase"] = "Succeeded" },
		"replaced":            func() { meta()["uid"] = "other-uid" },
		"worker exited":       func() { workerState(f, map[string]any{"terminated": map[string]any{}}, 0) },
		"worker restarted":    func() { workerState(f, map[string]any{"running": map[string]any{}}, 1) },
		"no worker container": func() { status()["containerStatuses"] = []any{} },
	}
	for name, change := range gone {
		t.Run(name, func(t *testing.T) {
			saved := f.pod
			f.pod = clonePod(t, saved)
			defer func() { f.pod, f.podStatus = saved, 200 }()
			change()
			if live, err := f.r.PodRunning(context.Background(), scope.Pod, "bc-1"); live || err != nil {
				t.Fatalf("live %v, err %v; want a definitive not-live", live, err)
			}
		})
	}
	for name, ref := range map[string]brokercore.PodRef{
		"empty":          {},
		"unknown domain": {Domain: "elsewhere", Namespace: "pool", Name: "worker-abc", UID: "pod-uid"},
	} {
		if live, err := f.r.PodRunning(context.Background(), ref, "bc-1"); live || err != nil {
			t.Errorf("%s: live %v, err %v", name, live, err)
		}
	}
	if live, err := f.r.PodRunning(context.Background(), scope.Pod, ""); live || err != nil {
		t.Errorf("a Pod with no run named: live %v, err %v", live, err)
	}
}

// A failed Pod read is an error, never a verdict that the Pod is gone.
func TestPodRunningReportsATransientReadFailure(t *testing.T) {
	f := setupPool(t)
	f.pod["metadata"].(map[string]any)["annotations"] = map[string]any{brokercore.CursorRunAnnotation: "bc-1"}
	scope, err := f.r.Attest(context.Background(), f.token(f.c), workerIP)
	if err != nil {
		t.Fatal(err)
	}
	for _, status := range []int{500, 503, 429} {
		f.podStatus = status
		if live, err := f.r.PodRunning(context.Background(), scope.Pod, "bc-1"); live || err == nil {
			t.Errorf("status %d: live %v, err %v; want an error", status, live, err)
		}
	}
}

// A pool Pod read or grant the broker could not complete is retryable; a Pod the API says is gone or unreadable stays refused.
func TestAttestUnfinishedChecksAreRetryable(t *testing.T) {
	f := setupPool(t)
	for status, reason := range map[int]string{500: "pod_lookup_unavailable", 503: "pod_lookup_unavailable", 429: "pod_lookup_unavailable", 404: "pod_unreadable", 403: "pod_unreadable"} {
		f.podStatus = status
		_, err := f.r.Attest(context.Background(), f.token(f.c), workerIP)
		if brokercore.DenialReason(err) != reason || brokercore.DenialUnavailable(err) != (reason == "pod_lookup_unavailable") {
			t.Errorf("Pod read %d: %v", status, err)
		}
	}
	f.podStatus = 200
	f.r.store = &fakeStore{status: "active", role: "proxy", err: &pgconn.PgError{Code: "08006"}}
	if _, err := f.r.Attest(context.Background(), f.token(f.c), workerIP); brokercore.DenialReason(err) != "store_unavailable" || !brokercore.DenialUnavailable(err) {
		t.Errorf("store outage: %v", err)
	}
	f.r.store = &fakeStore{status: "revoked", role: "proxy"}
	if _, err := f.r.Attest(context.Background(), f.token(f.c), workerIP); err == nil || brokercore.DenialUnavailable(err) {
		t.Errorf("revoked agent: %v", err)
	}
}

func workerState(f *poolFixture, state map[string]any, restarts int) {
	f.pod["status"].(map[string]any)["containerStatuses"] = []any{map[string]any{"name": "agent", "imageID": "registry.example/worker@" + workerDigest,
		"restartCount": restarts, "state": state}}
}

// clonePod copies a fixture Pod, so a case's change is undone by restoring it.
func clonePod(t *testing.T, pod map[string]any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(pod)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}
