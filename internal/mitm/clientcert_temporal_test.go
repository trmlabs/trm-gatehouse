package mitm

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The real Temporal clients through the broker, opt-in: a Temporal CLI dev
// server (temporal server start-dev, plaintext gRPC) behind a front that
// accepts only client certificates, as Temporal Cloud does, and the broker
// presenting the entry's certificate. Set GATEHOUSE_TEMPORAL_DEV_ADDR to the
// dev server's host:port, and GATEHOUSE_TEMPORAL_PYTHON (a Python with the
// temporalio package) and GATEHOUSE_TEMPORAL_CLI (the temporal binary) for
// the clients to run.

// temporalProbe is the Python SDK's side: connect through the broker as an
// HTTP CONNECT proxy, trusting only the broker's CA and holding no client
// certificate, read, then try three writes.
const temporalProbe = `
import asyncio, json, sys
from temporalio.client import Client, TLSConfig
from temporalio.service import HttpConnectProxyConfig

async def main():
    proxy, ca_path, workflow_id = sys.argv[1:4]
    with open(ca_path, "rb") as f:
        ca = f.read()
    client = await Client.connect("temporal.example.com:7233", namespace="default",
        tls=TLSConfig(server_root_ca_cert=ca, domain="temporal.example.com"),
        http_connect_proxy_config=HttpConnectProxyConfig(target_host=proxy, basic_auth=("workload-token", "")))
    out = {"list": [w.id async for w in client.list_workflows()]}
    out["count"] = (await client.count_workflows()).count
    handle = client.get_workflow_handle(workflow_id)
    out["describe"] = (await handle.describe()).status.name
    out["history_events"] = len((await handle.fetch_history()).events)
    writes = {
        "start": lambda: client.start_workflow("Probe", id=workflow_id + "-write", task_queue="gatehouse-probe"),
        "signal": lambda: handle.signal("probe"),
        "terminate": lambda: handle.terminate("probe"),
    }
    for name, write in writes.items():
        try:
            await write()
            out[name] = "allowed"
        except Exception as e:
            out[name] = type(e).__name__ + ": " + str(getattr(e, "status", "")) + " " + str(e)
    print(json.dumps(out))

asyncio.run(main())
`

// temporalFront serves TLS for temporal.example.com, takes client
// certificates only from the fixture's client CA, records each call's method
// and certificate, and relays it to the dev server over plaintext HTTP/2.
func temporalFront(t *testing.T, f *clientCertFixture, devAddr string) string {
	t.Helper()
	h2c := &http.Transport{Protocols: new(http.Protocols)}
	h2c.Protocols.SetUnencryptedHTTP2(true)
	relay := &httputil.ReverseProxy{Transport: h2c, FlushInterval: -1, Rewrite: func(r *httputil.ProxyRequest) {
		r.SetURL(&url.URL{Scheme: "http", Host: devAddr})
	}}
	front := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.grpcSide.record(mtlsCall{method: r.URL.Path, client: r.TLS.PeerCertificates[0].Subject.CommonName, auth: r.Header.Get("Authorization")})
		relay.ServeHTTP(w, r)
	}))
	front.EnableHTTP2 = true
	front.TLS = &tls.Config{Certificates: []tls.Certificate{f.serverCA.Server(t, "temporal.example.com")}, ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs: f.clientCA.Pool(), MinVersion: tls.VersionTLS12}
	front.StartTLS()
	t.Cleanup(front.Close)
	return front.Listener.Addr().String()
}

func TestTemporalClientsThroughTheBroker(t *testing.T) {
	devAddr, python, cli := os.Getenv("GATEHOUSE_TEMPORAL_DEV_ADDR"), os.Getenv("GATEHOUSE_TEMPORAL_PYTHON"), os.Getenv("GATEHOUSE_TEMPORAL_CLI")
	if devAddr == "" || (python == "" && cli == "") {
		t.Skip("set GATEHOUSE_TEMPORAL_DEV_ADDR and GATEHOUSE_TEMPORAL_PYTHON or GATEHOUSE_TEMPORAL_CLI to run the Temporal clients")
	}
	f := newClientCertFixture(t)
	f.routes.Store("temporal.example.com:7233", temporalFront(t, f, devAddr))
	dir := t.TempDir()
	caPath := filepath.Join(dir, "gatehouse-ca.pem")
	if err := os.WriteFile(caPath, f.proxy.RootPEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	run := func(env []string, name string, args ...string) (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, name, args...) // #nosec G204 G702 -- the person running the test names the client binaries
		cmd.Env = append(os.Environ(), env...)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	// A workflow to read, started on the dev server directly. No worker
	// polls its task queue, so it stays running.
	workflowID := "gatehouse-read-probe-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	if cli == "" {
		t.Skip("GATEHOUSE_TEMPORAL_CLI is needed to start the workflow the clients read")
	}
	if out, err := run(nil, cli, "workflow", "start", "--address", devAddr, "--namespace", "default", "--type", "Probe",
		"--task-queue", "gatehouse-probe", "--workflow-id", workflowID); err != nil {
		t.Fatalf("starting the probe workflow on the dev server: %v\n%s", err, out)
	}

	if python != "" {
		script := filepath.Join(dir, "probe.py")
		if err := os.WriteFile(script, []byte(temporalProbe), 0o600); err != nil {
			t.Fatal(err)
		}
		out, err := run(nil, python, script, f.grpc.proxyURL.Host, caPath, workflowID)
		if err != nil {
			t.Fatalf("Python SDK: %v\n%s", err, out)
		}
		var got struct {
			List                     []string
			Count                    int
			HistoryEvents            int `json:"history_events"`
			Describe                 string
			Start, Signal, Terminate string
		}
		lines := strings.Split(strings.TrimSpace(out), "\n")
		if err := json.Unmarshal([]byte(lines[len(lines)-1]), &got); err != nil {
			t.Fatalf("Python SDK output: %v\n%s", err, out)
		}
		t.Logf("Python SDK: %s", lines[len(lines)-1])
		if !containsString(got.List, workflowID) || got.Count < 1 || got.Describe != "RUNNING" || got.HistoryEvents < 1 {
			t.Fatalf("Python SDK reads: %+v", got)
		}
		for name, result := range map[string]string{"start": got.Start, "signal": got.Signal, "terminate": got.Terminate} {
			// The SDK prints the status as its number: 7 is PERMISSION_DENIED.
			if !strings.HasPrefix(result, "RPCError: 7 ") || !strings.Contains(result, "gatehouse refused: unlisted") {
				t.Errorf("Python SDK %s: %s", name, result)
			}
		}
	}

	if cli != "" {
		env := []string{"HTTPS_PROXY=http://workload-token:@" + f.grpc.proxyURL.Host, "https_proxy=", "NO_PROXY=", "no_proxy="}
		common := []string{"--address", "temporal.example.com:7233", "--namespace", "default", "--tls-ca-path", caPath}
		for _, read := range [][]string{{"workflow", "list"}, {"workflow", "count"}, {"workflow", "describe", "--workflow-id", workflowID},
			{"workflow", "show", "--workflow-id", workflowID}} {
			out, err := run(env, cli, append(read, common...)...)
			if err != nil {
				t.Fatalf("temporal %s: %v\n%s", strings.Join(read, " "), err, out)
			}
			if read[1] != "count" && !strings.Contains(out, workflowID) && read[1] != "show" {
				t.Fatalf("temporal %s did not name the workflow:\n%s", strings.Join(read, " "), out)
			}
		}
		for _, write := range [][]string{{"workflow", "start", "--type", "Probe", "--task-queue", "gatehouse-probe", "--workflow-id", workflowID + "-cli"},
			{"workflow", "signal", "--workflow-id", workflowID, "--name", "probe"}, {"workflow", "terminate", "--workflow-id", workflowID}} {
			out, err := run(env, cli, append(write, common...)...)
			if err == nil || !strings.Contains(out, "gatehouse refused: unlisted") {
				t.Errorf("temporal %s: %v\n%s", strings.Join(write, " "), err, out)
			}
		}
	}

	// What the clients called: every call that reached Temporal presented
	// the entry's certificate and was a listed read; every other one was
	// refused at the broker.
	reached, refused := map[string]int{}, map[string]int{}
	for _, c := range f.grpcSide.all() {
		reached[strings.TrimPrefix(c.method, workflowService)]++
		if c.client != "factory-reader" || c.auth != "" || !containsString(temporalReads, strings.TrimPrefix(c.method, workflowService)) {
			t.Errorf("Temporal took %+v", c)
		}
	}
	for _, e := range f.audit.all() {
		if e.Outcome == "unlisted" {
			refused[e.Path]++
		}
	}
	t.Logf("reached Temporal: %v", sortedCounts(reached))
	t.Logf("refused at the broker: %v", sortedCounts(refused))
}

func sortedCounts(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k, v := range m {
		out = append(out, k+"="+strconv.Itoa(v))
	}
	sort.Strings(out)
	return out
}
