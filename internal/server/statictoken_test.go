package server

import (
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
)

// The static-token listener carries HTTP CONNECT only, behind its TLS front's
// PROXY header; every other start is closed, and what it admits is tagged so
// the HTTP proxy takes it only as a static token.
func TestStaticTokenListenerAdmitsOnlyConnect(t *testing.T) {
	for name, c := range map[string]struct {
		send string
		ok   bool
	}{
		"HTTP CONNECT":                      {proxyLine + "CONNECT h:443 HTTP/1.1\r\n\r\n", true},
		"PostgreSQL attestation preamble":   {proxyLine + "GHATTS1 abc\nrest", false},
		"proxy certificate request":         {proxyLine + "POST /v1/proxy-certificate HTTP/1.1\r\n\r\n", false},
		"plain HTTP request":                {proxyLine + "GET / HTTP/1.1\r\n\r\n", false},
		"absolute-form forward-proxy start": {proxyLine + "GET http://h/ HTTP/1.1\r\n\r\n", false},
		"no PROXY header":                   {"CONNECT h:443 HTTP/1.1\r\n\r\n", false},
		"a second PROXY line":               {proxyLine + proxyLine + "CONNECT h:443 HTTP/1.1\r\n\r\n", false},
		"too short after the header":        {proxyLine + "CONN", false},
	} {
		routed, err := routeStaticToken(loopbackPair(t, c.send))
		if (err == nil) != c.ok {
			t.Errorf("%s: err %v", name, err)
			continue
		}
		if !c.ok {
			continue
		}
		b, _ := io.ReadAll(routed)
		kinds := brokercore.ConnKinds(routed)
		if string(b) != c.send || len(kinds) != 1 || kinds[0] != brokercore.KindStaticToken {
			t.Errorf("%s: replayed %q with kinds %v", name, b, kinds)
		}
	}
}

// The cross-cluster listener still admits proxy-attested identities only, and
// refuses the CONNECT of a static token's client as it always refused any
// identity but its own: the two listeners share no kind.
func TestStaticTokenAndCrossClusterShareNoKind(t *testing.T) {
	routed, _, err := routeCrossCluster(loopbackPair(t, proxyLine+"CONNECT h:443 HTTP/1.1\r\n\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	if brokercore.KindAdmitted(brokercore.ConnKinds(routed), brokercore.KindStaticToken) {
		t.Error("the cross-cluster listener admits a static token")
	}
	static, err := routeStaticToken(loopbackPair(t, proxyLine+"CONNECT h:443 HTTP/1.1\r\n\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{brokercore.KindProxyAttested, brokercore.KindPodToken, brokercore.KindTokenReview, ""} {
		if brokercore.KindAdmitted(brokercore.ConnKinds(static), kind) {
			t.Errorf("the static-token listener admits %q", kind)
		}
	}
}

func TestStaticTokenListenerMustBeLoopbackAndApartFromCrossCluster(t *testing.T) {
	s := &Server{}
	for _, addr := range []string{"0.0.0.0:14326", "192.0.2.10:14326", "[::]:14326", ":14326", "localhost:14326", "127.0.0.2:14326", "[::1]:14326"} {
		if s.EnableStaticToken(addr) == nil {
			t.Errorf("static-token listener on %s accepted", addr)
		}
	}
	if err := s.EnableCrossCluster("127.0.0.1:14325"); err != nil {
		t.Fatal(err)
	}
	if s.EnableStaticToken("127.0.0.1:14325") == nil {
		t.Error("the static-token listener took the cross-cluster port")
	}
	if err := s.EnableStaticToken("127.0.0.1:14326"); err != nil || s.staticTokenAddr != "127.0.0.1:14326" {
		t.Fatalf("loopback refused: %v", err)
	}
}

// serveStaticToken injects each admitted connection into the HTTP listener
// and closes the rest.
func TestServeStaticTokenInjectsOnlyConnect(t *testing.T) {
	front, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	merged := newMergedListener(inner)
	t.Cleanup(func() { _ = merged.Close(); _ = front.Close() })
	go func() { _ = serveStaticToken(front, merged, slog.New(slog.DiscardHandler)) }()

	bad, err := net.Dial("tcp", front.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(bad, proxyLine+"GET / HTTP/1.1\r\n\r\n")
	_ = bad.SetReadDeadline(time.Now().Add(5 * time.Second))
	// Closed with the start unread, which the peer sees as a reset or an end;
	// what it must not see is a connection left open until the deadline.
	if _, err := io.ReadAll(bad); err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			t.Fatalf("a refused start was left open: %v", err)
		}
	}

	good, err := net.Dial("tcp", front.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer good.Close()
	_, _ = io.WriteString(good, proxyLine+"CONNECT h:443 HTTP/1.1\r\n\r\n")
	got := make(chan net.Conn, 1)
	go func() {
		c, _ := merged.Accept()
		got <- c
	}()
	select {
	case c := <-got:
		kinds := brokercore.ConnKinds(c)
		if len(kinds) != 1 || kinds[0] != brokercore.KindStaticToken {
			t.Errorf("kinds %v", kinds)
		}
		_ = c.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("a CONNECT was not handed to the HTTP listener")
	}
}
