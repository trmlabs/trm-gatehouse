package mitm

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"slices"
	"syscall"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/auditchain"
)

type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func TestUpstreamCauseNamesTheFailure(t *testing.T) {
	for name, tc := range map[string]struct {
		err  error
		want string
	}{
		"dial timeout":     {&net.OpError{Op: "dial", Err: timeoutError{}}, "dial_timeout"},
		"refused":          {&net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}, "conn_refused"},
		"reset":            {&net.OpError{Op: "read", Err: syscall.ECONNRESET}, "conn_reset"},
		"dns":              {&net.DNSError{Err: "no such host", Name: "example.com"}, "dns"},
		"handshake":        {errors.New("net/http: TLS handshake timeout"), "tls_handshake"},
		"alert":            {&net.OpError{Op: "remote error", Err: errors.New("tls: handshake failure")}, "tls_handshake"},
		"certificate":      {x509.UnknownAuthorityError{}, "tls_certificate"},
		"response timeout": {errors.New("net/http: timeout awaiting response headers"), "response_timeout"},
		"cancelled":        {context.Canceled, "other"},
	} {
		t.Run(name, func(t *testing.T) {
			got := upstreamCause(tc.err)
			if got != tc.want || !slices.Contains(auditchain.Causes, got) {
				t.Fatalf("cause %q, want %q", got, tc.want)
			}
		})
	}
}

// Errors from a real transport, not constructed ones: a closed port, and a
// peer that accepts and never answers the handshake.
func TestUpstreamCauseOfRealTransportErrors(t *testing.T) {
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedAddr := closed.Addr().String()
	_ = closed.Close()
	silent, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	defer close(done)
	defer func() { _ = silent.Close() }()
	go func() {
		for {
			c, err := silent.Accept()
			if err != nil {
				return
			}
			go func() {
				<-done
				_ = c.Close()
			}()
		}
	}()
	transport := &http.Transport{TLSHandshakeTimeout: 100 * time.Millisecond}
	for want, addr := range map[string]string{"conn_refused": closedAddr, "tls_handshake": silent.Addr().String()} {
		req, _ := http.NewRequest(http.MethodGet, "https://"+addr+"/", nil)
		resp, err := transport.RoundTrip(req)
		if err == nil {
			_ = resp.Body.Close()
			t.Fatalf("%s: no error", want)
		}
		if got := upstreamCause(err); got != want {
			t.Errorf("cause %q, want %q", got, want)
		}
	}
}

func TestSplitOutcomeKeepsTheOutcomeFixed(t *testing.T) {
	if o, c := splitOutcome("upstream_error/dns"); o != "upstream_error" || c != "dns" {
		t.Fatalf("got %q %q", o, c)
	}
	if o, c := splitOutcome("completed"); o != "completed" || c != "" {
		t.Fatalf("got %q %q", o, c)
	}
}
