package mitm

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
)

func TestUpstreamConnectionsAreReusedAcrossConcurrentCallers(t *testing.T) {
	const callers = 40
	var accepted atomic.Int64
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(50 * time.Millisecond)
		_, _ = io.WriteString(w, "ok")
	}))
	upstream.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			accepted.Add(1)
		}
	}
	upstream.StartTLS()
	defer upstream.Close()
	host, _, _ := net.SplitHostPort(strings.TrimPrefix(upstream.URL, "https://"))

	scope := &brokercore.ProxyScope{VaultID: "v1", VaultName: "default", VaultRole: "proxy"}
	cp := &fakeCredProvider{byHost: map[string]fakeInjectResult{host: {result: &brokercore.InjectResult{Headers: map[string]string{"Authorization": "Bearer x"}}}}}
	proxyURL, roots, p := setupProxy(t, validTokenResolver("tok", scope), cp)
	upstreamRoots := x509.NewCertPool()
	upstreamRoots.AddCert(upstream.Certificate())
	p.upstream.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: upstreamRoots}
	client := newTrustingClient(proxyURL, url.User("tok"), roots)
	client.Transport.(*http.Transport).MaxIdleConnsPerHost = callers

	wave := func() {
		var wg sync.WaitGroup
		for range callers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				resp, err := client.Get(upstream.URL + "/ping")
				if err != nil {
					t.Errorf("get: %v", err)
					return
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
			}()
		}
		wg.Wait()
	}
	wave()
	first := accepted.Load()
	wave()
	if extra := accepted.Load() - first; extra > callers/4 {
		t.Fatalf("second wave opened %d new upstream connections after %d in the first; idle connections are not being reused", extra, first)
	}
}

func TestUpstreamIdleConnectionLimitIsConfigurable(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	if p := New("127.0.0.1:0", Options{Logger: logger}); p.upstream.MaxIdleConns != DefaultMaxIdleUpstreamConns || p.upstream.MaxIdleConnsPerHost != DefaultMaxIdleUpstreamConns {
		t.Fatalf("default %d per host of %d", p.upstream.MaxIdleConnsPerHost, p.upstream.MaxIdleConns)
	}
	if DefaultMaxIdleUpstreamConns < DefaultMaxTunnels {
		t.Fatalf("default %d idle connections is below the %d sessions a replica admits", DefaultMaxIdleUpstreamConns, DefaultMaxTunnels)
	}
	if p := New("127.0.0.1:0", Options{Logger: logger, MaxIdleUpstreamConns: 50000}); p.upstream.MaxIdleConns != 50000 || p.upstream.MaxIdleConnsPerHost != 50000 {
		t.Fatalf("configured %d per host of %d", p.upstream.MaxIdleConnsPerHost, p.upstream.MaxIdleConns)
	}
}
