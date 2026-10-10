package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testPair makes a self-signed certificate for name and returns its PEM
// certificate, PEM key and parsed certificate.
func testPair(t *testing.T, name string) ([]byte, []byte, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
		DNSNames: []string{name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), cert
}

func writePair(t *testing.T, dir string, certPEM, keyPEM []byte) (string, string) {
	t.Helper()
	certFile, keyFile := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

// startPostgresTLS runs the TLS front onto a loopback listener standing in
// for the PostgreSQL broker's, and returns the front's address and the
// listener the broker would serve.
func startPostgresTLS(t *testing.T, certFile, keyFile string) (string, *mergedListener) {
	t.Helper()
	s := &Server{logger: slog.New(slog.DiscardHandler)}
	if err := s.EnablePostgresTLS("127.0.0.1:0", certFile, keyFile); err != nil {
		t.Fatal(err)
	}
	pgLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	merged := newMergedListener(pgLn)
	tlsLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tlsLn.Close(); _ = merged.Close() })
	go func() { _ = servePostgresTLS(tlsLn, merged, s.pgTLS.config(), s.logger) }()
	return tlsLn.Addr().String(), merged
}

func acceptWithin(t *testing.T, l net.Listener) net.Conn {
	t.Helper()
	got := make(chan net.Conn, 1)
	go func() {
		c, err := l.Accept()
		if err == nil {
			got <- c
		}
	}()
	select {
	case c := <-got:
		t.Cleanup(func() { _ = c.Close() })
		return c
	case <-time.After(5 * time.Second):
		t.Fatal("no connection reached the broker's listener")
		return nil
	}
}

// A TLS client's bytes reach the broker's listener decrypted, and the
// connection's remote address is the client's own, which pool admission
// reads in place of a PROXY header.
func TestPostgresTLSHandsOffWithClientAddress(t *testing.T) {
	certPEM, keyPEM, cert := testPair(t, "broker.gatehouse.svc.cluster.local")
	certFile, keyFile := writePair(t, t.TempDir(), certPEM, keyPEM)
	addr, broker := startPostgresTLS(t, certFile, keyFile)

	roots := x509.NewCertPool()
	roots.AddCert(cert)
	// The server's half of the handshake runs when the broker first reads, as
	// in the broker's connection handler, so the client dials alongside it.
	dialed := make(chan *tls.Conn, 1)
	go func() {
		client, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr,
			&tls.Config{RootCAs: roots, ServerName: "broker.gatehouse.svc.cluster.local", MinVersion: tls.VersionTLS12})
		if err != nil {
			t.Error(err)
			close(dialed)
			return
		}
		_, _ = io.WriteString(client, "GHATTS1 abc\n")
		dialed <- client
	}()

	served := acceptWithin(t, broker)
	_ = served.SetDeadline(time.Now().Add(5 * time.Second))
	line := make([]byte, len("GHATTS1 abc\n"))
	if _, err := io.ReadFull(served, line); err != nil || string(line) != "GHATTS1 abc\n" {
		t.Fatalf("read %q, %v", line, err)
	}
	client, ok := <-dialed
	if !ok {
		t.FailNow()
	}
	defer client.Close()
	if served.RemoteAddr().String() != client.LocalAddr().String() {
		t.Fatalf("remote address %s, want the client's %s", served.RemoteAddr(), client.LocalAddr())
	}
}

// A plaintext client gets nothing through: the handshake fails before any of
// its bytes reach the broker as protocol data.
func TestPostgresTLSRefusesPlaintext(t *testing.T) {
	certPEM, keyPEM, _ := testPair(t, "broker")
	certFile, keyFile := writePair(t, t.TempDir(), certPEM, keyPEM)
	addr, broker := startPostgresTLS(t, certFile, keyFile)

	client, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	// A PostgreSQL SSLRequest, sent without TLS.
	if _, err := client.Write([]byte{0, 0, 0, 8, 4, 210, 22, 47}); err != nil {
		t.Fatal(err)
	}
	served := acceptWithin(t, broker)
	_ = served.SetDeadline(time.Now().Add(5 * time.Second))
	if n, err := served.Read(make([]byte, 64)); err == nil || n > 0 {
		t.Fatalf("plaintext read %d bytes, err %v", n, err)
	}
}

// A rotated certificate serves from the next handshake after the reload
// interval, and a half-written rotation keeps the last good pair.
func TestCertificateFilesReload(t *testing.T) {
	dir := t.TempDir()
	certA, keyA, _ := testPair(t, "a")
	certFile, keyFile := writePair(t, dir, certA, keyA)
	c, err := loadCertificateFiles(certFile, keyFile, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	c.now = func() time.Time { return now }
	served := func() string {
		cert, err := c.get(nil)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		return parsed.Subject.CommonName
	}
	if got := served(); got != "a" {
		t.Fatalf("served %s", got)
	}

	certB, keyB, _ := testPair(t, "b")
	writePair(t, dir, certB, keyB)
	if got := served(); got != "a" {
		t.Fatalf("reloaded inside the interval: served %s", got)
	}
	now = now.Add(pgTLSReloadInterval)
	if got := served(); got != "b" {
		t.Fatalf("after rotation served %s", got)
	}

	certC, _, _ := testPair(t, "c")
	writePair(t, dir, certC, keyB)
	now = now.Add(pgTLSReloadInterval)
	if got := served(); got != "b" {
		t.Fatalf("mismatched pair replaced the last good one: served %s", got)
	}
	if err := os.Remove(keyFile); err != nil {
		t.Fatal(err)
	}
	now = now.Add(pgTLSReloadInterval)
	if got := served(); got != "b" {
		t.Fatalf("missing key replaced the last good pair: served %s", got)
	}
}

// Startup fails closed on a pair that does not load, and the TLS listener
// cannot sit beside the cross-cluster listener's PROXY header.
func TestEnablePostgresTLSFailsClosed(t *testing.T) {
	dir := t.TempDir()
	certA, keyA, _ := testPair(t, "a")
	_, keyB, _ := testPair(t, "b")
	s := &Server{logger: slog.New(slog.DiscardHandler)}
	if err := s.EnablePostgresTLS("127.0.0.1:0", filepath.Join(dir, "none.crt"), filepath.Join(dir, "none.key")); err == nil {
		t.Error("missing files accepted")
	}
	certFile, keyFile := writePair(t, dir, certA, keyB)
	if err := s.EnablePostgresTLS("127.0.0.1:0", certFile, keyFile); err == nil {
		t.Error("mismatched pair accepted")
	}
	if err := s.EnablePostgresTLS("127.0.0.1:0", "", ""); err == nil {
		t.Error("no files accepted")
	}
	certFile, keyFile = writePair(t, dir, certA, keyA)
	if err := s.EnablePostgresTLS("no-port", certFile, keyFile); err == nil {
		t.Error("an address without a port accepted")
	}
	cross := &Server{logger: slog.New(slog.DiscardHandler), crossClusterAddr: "127.0.0.1:16443"}
	if err := cross.EnablePostgresTLS("127.0.0.1:0", certFile, keyFile); err == nil || !strings.Contains(err.Error(), "cross-cluster") {
		t.Errorf("combined with cross-cluster: %v", err)
	}
	if s.pgTLS != nil {
		t.Error("a failed enable left the listener configured")
	}
}
