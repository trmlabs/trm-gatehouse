package server

import (
	"bufio"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
)

// loopbackPair is a connection accepted on loopback, as from the TLS front.
func loopbackPair(t *testing.T, send string) net.Conn {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		c, err := net.Dial("tcp", l.Addr().String())
		if err == nil {
			_, _ = io.WriteString(c, send)
			time.Sleep(200 * time.Millisecond)
			_ = c.Close()
		}
	}()
	c, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

const proxyLine = "PROXY TCP4 192.0.2.7 10.0.0.1 51000 16443\r\n"

func TestCrossClusterRoutesByFirstBytes(t *testing.T) {
	for name, c := range map[string]struct {
		send     string
		postgres bool
		ok       bool
	}{
		"PostgreSQL attestation preamble": {proxyLine + "GHATTS1 abc\nrest", true, true},
		"HTTP CONNECT":                    {proxyLine + "CONNECT h:443 HTTP/1.1\r\n\r\n", false, true},
		"plain PostgreSQL startup":        {proxyLine + "\x00\x00\x00\x08\x04\xd2\x16\x2f", false, false},
		"plain HTTP request":              {proxyLine + "GET / HTTP/1.1\r\n\r\n", false, false},
		"session preamble only":           {proxyLine + "GHSESS1 a.b.c\n", false, false},
		"no PROXY header":                 {"CONNECT h:443 HTTP/1.1\r\n\r\n", false, false},
		"no PROXY header, PostgreSQL":     {"GHATTS1 abc\n", false, false},
		"a second PROXY line":             {proxyLine + proxyLine + "CONNECT h:443 HTTP/1.1\r\n\r\n", false, false},
	} {
		routed, route, err := routeCrossCluster(loopbackPair(t, c.send))
		postgres := route == routePostgres
		if (err == nil) != c.ok || (c.ok && postgres != c.postgres) {
			t.Errorf("%s: postgres %v err %v", name, postgres, err)
			continue
		}
		if !c.ok {
			continue
		}
		// The server that gets it reads every byte, PROXY header first, and
		// admits only proxy-attested identities.
		b, _ := io.ReadAll(routed)
		if string(b) != c.send || !brokercore.KindAdmitted(brokercore.ConnKinds(routed), brokercore.KindProxyAttested) ||
			brokercore.KindAdmitted(brokercore.ConnKinds(routed), brokercore.KindPodToken) {
			t.Errorf("%s: replayed %q", name, b)
		}
	}
}

func TestMergedListenerServesBothAndCloses(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	m := newMergedListener(l)
	go func() {
		c, err := net.Dial("tcp", l.Addr().String())
		if err == nil {
			defer c.Close()
			time.Sleep(time.Second)
		}
	}()
	if c, err := m.Accept(); err != nil {
		t.Fatalf("own connection: %v", err)
	} else {
		c.Close()
	}
	a, b := net.Pipe()
	defer b.Close()
	go m.inject(a)
	if c, err := m.Accept(); err != nil || c != a {
		t.Fatalf("injected connection: %v", err)
	}
	_ = m.Close()
	if _, err := m.Accept(); err == nil {
		t.Fatal("accepted after close")
	}
	x, y := net.Pipe()
	defer y.Close()
	m.inject(x) // closed, not blocked
	if _, err := x.Write([]byte("x")); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("injection after close left the connection open: %v", err)
	}
}

func TestCrossClusterListenerMustBeLoopback(t *testing.T) {
	s := &Server{}
	for _, addr := range []string{"0.0.0.0:14325", "10.0.0.1:14325", "[::]:14325", ":14325", "localhost:14325", "127.0.0.2:14325", "[::1]:14325"} {
		if s.EnableCrossCluster(addr) == nil {
			t.Errorf("cross-cluster listener on %s accepted", addr)
		}
	}
	if err := s.EnableCrossCluster("127.0.0.1:14325"); err != nil || s.crossClusterAddr != "127.0.0.1:14325" {
		t.Fatalf("loopback refused: %v", err)
	}
}

// remoteConn reports another remote address, as if the TCP peer were not the
// TLS front in the same Pod.
type remoteConn struct {
	net.Conn
	remote net.Addr
}

func (c remoteConn) RemoteAddr() net.Addr { return c.remote }

// The PROXY header is trusted only from a loopback TCP peer: a valid-looking
// header from anywhere else is refused.
func TestCrossClusterTrustsPROXYOnlyFromLoopback(t *testing.T) {
	c := loopbackPair(t, proxyLine+"CONNECT h:443 HTTP/1.1\r\n\r\n")
	peer := remoteConn{Conn: c, remote: &net.TCPAddr{IP: net.ParseIP("192.0.2.7"), Port: 51000}}
	if _, _, err := routeCrossCluster(peer); err == nil {
		t.Fatal("a PROXY header from a non-loopback peer was trusted")
	}
}

// A shared proxy's certificate request is HTTP, routed to the certificate
// server with the PROXY header consumed and the proxy's address as the
// connection's remote address.
func TestCrossClusterRoutesCertificateRequests(t *testing.T) {
	request := "POST /v1/proxy/certificate HTTP/1.1\r\nHost: x\r\n\r\n"
	routed, route, err := routeCrossCluster(loopbackPair(t, proxyLine+request))
	if err != nil || route != routeCertificate {
		t.Fatalf("route %q err %v", route, err)
	}
	if got := routed.RemoteAddr().String(); got != "192.0.2.7:0" {
		t.Errorf("remote address %s, want the proxy's", got)
	}
	b, _ := io.ReadAll(routed)
	if string(b) != request {
		t.Errorf("replayed %q", b)
	}
	// Any other HTTP method or path start is not routed.
	for _, start := range []string{"POST /v2/x HTTP/1.1\r\n\r\n", "PUT /v1/x HTTP/1.1\r\n\r\n", "GET /v1/proxy/certificate HTTP/1.1\r\n\r\n"} {
		if _, _, err := routeCrossCluster(loopbackPair(t, proxyLine+start)); err == nil {
			t.Errorf("%q routed", start)
		}
	}
}

// crossClusterFixture serves the cross-cluster listener with real routing: held HTTP
// connections stay open, and the certificate server answers 200.
func crossClusterFixture(t *testing.T, limits CrossClusterLimits) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	httpLn := newMergedListener(newDeadListener(l.Addr()))
	certLn := newInjectedListener(l.Addr())
	go func() {
		for {
			c, err := httpLn.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(io.Discard, c); _ = c.Close() }()
		}
	}()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/proxy/certificate", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	certServer := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = certServer.Serve(certLn) }()
	go func() {
		_ = serveCrossCluster(l, httpLn, nil, certLn, limits.withDefaults(), slog.New(slog.DiscardHandler))
	}()
	t.Cleanup(func() { _ = l.Close(); _ = httpLn.Close(); _ = certLn.Close(); _ = certServer.Close() })
	return l.Addr().String()
}

// deadListener never accepts: the merged HTTP listener here only receives injected connections.
type deadListener struct {
	addr net.Addr
	done chan struct{}
}

func newDeadListener(addr net.Addr) *deadListener {
	return &deadListener{addr: addr, done: make(chan struct{})}
}

func (l *deadListener) Accept() (net.Conn, error) { <-l.done; return nil, net.ErrClosed }
func (l *deadListener) Close() error {
	select {
	case <-l.done:
	default:
		close(l.done)
	}
	return nil
}
func (l *deadListener) Addr() net.Addr { return l.addr }

func dialSend(t *testing.T, addr, send string) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if _, err := io.WriteString(c, send); err != nil {
		t.Fatal(err)
	}
	return c
}

// refusedAtLimit reports whether the listener closed c without serving it.
func refusedAtLimit(c net.Conn) bool {
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err := c.Read(make([]byte, 1))
	return err != nil && !errors.Is(err, os.ErrDeadlineExceeded)
}

func certificateStatus(t *testing.T, addr string) string {
	t.Helper()
	c := dialSend(t, addr, proxyLine+"POST /v1/proxy/certificate HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n")
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	line, _ := bufio.NewReader(c).ReadString('\n')
	return strings.TrimSpace(line)
}

// A flood of HTTP connections at their limit cannot stop a certificate renewal.
func TestCrossClusterRenewalSurvivesAnHTTPFlood(t *testing.T) {
	addr := crossClusterFixture(t, CrossClusterLimits{Open: 3, Certificate: 2})
	connect := proxyLine + "CONNECT h:443 HTTP/1.1\r\n\r\n"
	var held []net.Conn
	for range 3 {
		held = append(held, dialSend(t, addr, connect))
	}
	time.Sleep(200 * time.Millisecond)
	if !refusedAtLimit(dialSend(t, addr, connect)) {
		t.Fatal("an HTTP connection past the limit was served")
	}
	if got := certificateStatus(t, addr); got != "HTTP/1.1 200 OK" {
		t.Fatalf("renewal under an HTTP flood: %q", got)
	}
	// A closed connection frees its slot.
	_ = held[0].Close()
	time.Sleep(200 * time.Millisecond)
	if refusedAtLimit(dialSend(t, addr, connect)) {
		t.Error("a slot freed by a closed connection was not reused")
	}
}

// Connections that never say what they are fill the routing step, not the routed classes.
func TestCrossClusterBoundsConnectionsAwaitingRouting(t *testing.T) {
	addr := crossClusterFixture(t, CrossClusterLimits{Pending: 2})
	for range 2 {
		dialSend(t, addr, "")
	}
	time.Sleep(200 * time.Millisecond)
	if !refusedAtLimit(dialSend(t, addr, "")) {
		t.Error("a connection past the pending limit was kept")
	}
}

func TestCrossClusterLimitDefaultsAreSizedForScale(t *testing.T) {
	got := CrossClusterLimits{}.withDefaults()
	if got.Pending < 10000 || got.Open < 10000 || got.Certificate < 1 {
		t.Errorf("defaults %+v", got)
	}
	if got := (CrossClusterLimits{Open: 5}).withDefaults(); got.Open != 5 || got.Pending != defaultCrossClusterPending {
		t.Errorf("an explicit limit was overridden: %+v", got)
	}
	if err := (&Server{}).SetCrossClusterLimits(CrossClusterLimits{Open: -1}); err == nil {
		t.Error("a negative limit was accepted")
	}
}
