package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/auditchain/cloudlog"
)

func TestAuditOutputIsStdoutAloneUnlessCloudLoggingIsOn(t *testing.T) {
	var stdout bytes.Buffer
	for _, env := range []map[string]string{{}, {"AGENT_VAULT_AUDIT_CLOUD_LOGGING": "false"}} {
		out, sink, err := auditOutput(context.Background(), &stdout, func(k string) string { return env[k] }, slog.New(slog.DiscardHandler))
		if err != nil || sink != nil || out != io.Writer(&stdout) {
			t.Fatalf("env %v: out %v sink %v err %v, want stdout alone", env, out, sink, err)
		}
	}
	if _, _, err := auditOutput(context.Background(), &stdout, func(string) string { return "maybe" }, slog.New(slog.DiscardHandler)); err == nil {
		t.Fatal("an unreadable AGENT_VAULT_AUDIT_CLOUD_LOGGING was accepted")
	}
}

func TestAuditOutputWritesStdoutFirstAndMirrorsToCloudLogging(t *testing.T) {
	var mu sync.Mutex
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(b))
		mu.Unlock()
	}))
	defer srv.Close()
	old := newAuditCloudLog
	t.Cleanup(func() { newAuditCloudLog = old })
	newAuditCloudLog = func(_ context.Context, getenv func(string) string, logger *slog.Logger) (*cloudlog.Sink, error) {
		return cloudlog.New(cloudlog.Options{LogID: "gatehouse-audit-broker", Endpoint: srv.URL, Client: http.DefaultClient, Logger: logger,
			Resource: cloudlog.Resource{ProjectID: "proj", Location: "loc", ClusterName: "clu", Namespace: "ns", Pod: "broker-0", Container: "app"}})
	}
	var stdout bytes.Buffer
	out, sink, err := auditOutput(context.Background(), &stdout, func(k string) string {
		return map[string]string{"AGENT_VAULT_AUDIT_CLOUD_LOGGING": "true"}[k]
	}, slog.New(slog.DiscardHandler))
	if err != nil || sink == nil {
		t.Fatalf("sink %v err %v", sink, err)
	}
	row, _ := json.Marshal(map[string]any{"type": "gatehouse.audit.v1", "replica": "broker-0", "boot": 1, "seq": 0, "ts": "2026-11-02T10:00:00Z"})
	if _, err := out.Write(append(row, '\n')); err != nil {
		t.Fatal(err)
	}
	closeSink(sink)
	if stdout.String() != string(row)+"\n" {
		t.Errorf("stdout = %q", stdout.String())
	}
	if len(bodies) != 1 || !strings.Contains(bodies[0], `"container_name":"app"`) || !strings.Contains(bodies[0], "gatehouse.audit.v1") {
		t.Errorf("Cloud Logging got %v", bodies)
	}
}

func TestAuditCloudLogNeedsThePodLabelsBeforeAnyCredentialLookup(t *testing.T) {
	for _, env := range []map[string]string{
		{},
		{"AGENT_VAULT_AUDIT_CLOUD_LOGGING_NAMESPACE": "gatehouse", "AGENT_VAULT_AUDIT_CLOUD_LOGGING_POD": "broker-0"},
		{"AGENT_VAULT_AUDIT_CLOUD_LOGGING_POD": "broker-0", "AGENT_VAULT_AUDIT_CLOUD_LOGGING_CONTAINER": "app"},
	} {
		sink, err := buildAuditCloudLog(context.Background(), func(k string) string { return env[k] }, slog.New(slog.DiscardHandler))
		if err == nil || sink != nil {
			t.Fatalf("env %v accepted", env)
		}
	}
}

func TestStopAuditCheckpointsWaitsForTheLoopToReturn(t *testing.T) {
	ctx, stop := context.WithCancel(context.Background())
	t.Cleanup(stop)
	stopped := make(chan struct{})
	returned := false
	go func() {
		<-ctx.Done()
		time.Sleep(20 * time.Millisecond)
		returned = true
		close(stopped)
	}()
	sharedAudit.Lock()
	oldStop, oldStopped := sharedAudit.stop, sharedAudit.stopped
	sharedAudit.stop, sharedAudit.stopped = stop, stopped
	sharedAudit.Unlock()
	t.Cleanup(func() {
		sharedAudit.Lock()
		sharedAudit.stop, sharedAudit.stopped = oldStop, oldStopped
		sharedAudit.Unlock()
	})
	stopAuditCheckpoints()
	if !returned {
		t.Fatal("stopAuditCheckpoints returned before the checkpoint loop did")
	}
}

func TestDialTransportConnectsToTheGivenAddressWhateverTheURLHost(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "logging.googleapis.example" {
			t.Errorf("Host = %q, want the URL's host", r.Host)
		}
	}))
	defer srv.Close()
	transport, err := dialTransport(srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	resp, err := (&http.Client{Transport: transport}).Get("http://logging.googleapis.example/v2/entries:write")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
}

func TestDialTransportRefusesAnythingButAnIPAndPort(t *testing.T) {
	for _, raw := range []string{"logging.googleapis.com:443", "10.0.0.1", "0.0.0.0:443", "10.0.0.1:0"} {
		if _, err := dialTransport(raw); err == nil {
			t.Errorf("%q accepted", raw)
		}
	}
}

func TestDialTransportIgnoresProxySettings(t *testing.T) {
	transport, err := dialTransport("127.0.0.1:443")
	if err != nil {
		t.Fatal(err)
	}
	if transport.Proxy != nil {
		t.Error("a fixed dial address kept the proxy setting")
	}
}
