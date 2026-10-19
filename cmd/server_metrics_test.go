package cmd

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	vaultapi "github.com/hashicorp/vault/api"

	"github.com/Infisical/agent-vault/internal/httpcatalog"
	"github.com/Infisical/agent-vault/internal/httpcatalog/clientcerttest"
)

// certKV holds client certificates by Vault read path.
type certKV struct {
	mu      sync.Mutex
	secrets map[string]map[string]interface{}
}

func (v *certKV) ReadWithDataWithContext(_ context.Context, path string, _ map[string][]string) (*vaultapi.Secret, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	fields, ok := v.secrets[path]
	if !ok {
		return nil, nil
	}
	return &vaultapi.Secret{Data: map[string]interface{}{"data": fields, "metadata": map[string]interface{}{"version": float64(1)}}}, nil
}

// lockedBuffer is a log destination the watcher writes from its goroutine.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}
func (l *lockedBuffer) String() string { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

func TestClientCertificateWatchAndMetrics(t *testing.T) {
	ca := clientcerttest.NewCA(t, "example-ca")
	certPEM, keyPEM := ca.ValidClient(t, "reader")
	kv := &certKV{secrets: map[string]map[string]interface{}{
		"gatehouse/data/vendors/reads": {"cert": certPEM, "key": keyPEM},
	}}
	catalog, err := httpcatalog.Parse([]byte(`{"entries":[
	  {"name":"reads","host":"a.example.com","pathPrefixes":["/v1/"],"methods":["GET"],"clientCertificate":{"mount":"gatehouse","path":"vendors/reads"},"pools":["p"]},
	  {"name":"gone","host":"b.example.com","pathPrefixes":["/v1/"],"methods":["GET"],"clientCertificate":{"mount":"gatehouse","path":"vendors/gone"},"pools":["p"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	certs := &httpcatalog.ClientCertificates{Vault: kv}
	var logs lockedBuffer
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		watchClientCertificates(ctx, certs, catalog, 10*time.Millisecond, slog.New(slog.NewTextHandler(&logs, nil)))
		close(done)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(logs.String(), "cannot be presented") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond) // a few more checks, which change nothing and log nothing
	cancel()
	<-done
	out := logs.String()
	if strings.Count(out, "upstream client certificate in use") != 1 || !strings.Contains(out, "binding=reads") ||
		strings.Count(out, "upstream client certificate cannot be presented") != 1 || !strings.Contains(out, "binding=gone") || strings.Contains(out, "BEGIN") {
		t.Fatalf("logs:\n%s", out)
	}

	for _, bad := range []string{"0", "65536", "port", "09464", "-1"} {
		if err := serveMetrics(bad, certs, slog.New(slog.DiscardHandler)); err == nil {
			t.Errorf("port %q accepted", bad)
		}
	}
	if err := serveMetrics("", certs, slog.New(slog.DiscardHandler)); err != nil {
		t.Fatalf("unset: %v", err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := strconv.Itoa(l.Addr().(*net.TCPAddr).Port)
	_ = l.Close()
	if err := serveMetrics(port, certs, slog.New(slog.DiscardHandler)); err != nil {
		t.Fatal(err)
	}
	get := func(method, path string) (int, string) {
		r, _ := http.NewRequest(method, "http://127.0.0.1:"+port+path, nil)
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body)
	}
	code, body := get(http.MethodGet, "/metrics")
	if code != http.StatusOK || !strings.Contains(body, `gatehouse_upstream_client_certificate_valid{binding="reads"} 1`) ||
		!strings.Contains(body, `gatehouse_upstream_client_certificate_valid{binding="gone"} 0`) {
		t.Fatalf("metrics: %d\n%s", code, body)
	}
	if code, _ := get(http.MethodGet, "/"); code != http.StatusNotFound {
		t.Fatalf("other path: %d", code)
	}
	if code, _ := get(http.MethodPost, "/metrics"); code != http.StatusMethodNotAllowed {
		t.Fatalf("POST: %d", code)
	}
}
