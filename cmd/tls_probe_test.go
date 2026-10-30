package cmd

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// tlsProbeServer starts a TLS server whose certificate is valid for 127.0.0.1 and returns its address and a pool trusting it.
func tlsProbeServer(t *testing.T, serve func(net.Conn, *tls.Config)) (string, *x509.CertPool, string) {
	t.Helper()
	ts := httptest.NewUnstartedServer(nil)
	ts.StartTLS()
	cert := ts.TLS.Certificates[0]
	ts.Close()
	conf := &tls.Config{Certificates: []tls.Certificate{cert}}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serve(c, conf)
		}
	}()
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	bundle := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}))
	return ln.Addr().String(), pool, bundle
}

func serveTLS(c net.Conn, conf *tls.Config) {
	defer c.Close()
	tc := tls.Server(c, conf)
	if tc.Handshake() == nil {
		_, _ = tc.Read(make([]byte, 1))
	}
}

func servePostgres(c net.Conn, conf *tls.Config) {
	buf := make([]byte, 8)
	if _, err := c.Read(buf); err != nil || !bytes.Equal(buf[4:], []byte{0x04, 0xd2, 0x16, 0x2f}) {
		c.Close()
		return
	}
	_, _ = c.Write([]byte("S"))
	serveTLS(c, conf)
}

func serveSMTP(c net.Conn, conf *tls.Config) {
	br := bufio.NewReader(c)
	_, _ = c.Write([]byte("220 ready\r\n"))
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			c.Close()
			return
		}
		switch {
		case strings.HasPrefix(line, "EHLO"):
			_, _ = c.Write([]byte("250-mail\r\n250 STARTTLS\r\n"))
		case strings.HasPrefix(line, "STARTTLS"):
			_, _ = c.Write([]byte("220 go ahead\r\n"))
			serveTLS(c, conf)
			return
		}
	}
}

func TestProbeTLSSchemes(t *testing.T) {
	for name, tc := range map[string]struct {
		serve  func(net.Conn, *tls.Config)
		scheme string
	}{
		"direct":   {serveTLS, ""},
		"postgres": {servePostgres, "postgres://"},
		"smtp":     {serveSMTP, "smtp://"},
	} {
		t.Run(name, func(t *testing.T) {
			addr, pool, _ := tlsProbeServer(t, tc.serve)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			state, err := probeTLS(ctx, tc.scheme+addr, pool)
			if err != nil {
				t.Fatal(err)
			}
			if state.Version != tls.VersionTLS13 || state.CipherSuite == 0 || state.CurveID == 0 {
				t.Fatalf("incomplete state: %+v", state)
			}
		})
	}
}

func TestProbeTLSFailures(t *testing.T) {
	addr, pool, _ := tlsProbeServer(t, serveTLS)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := probeTLS(ctx, addr, x509.NewCertPool()); err == nil {
		t.Fatal("an untrusted certificate must fail")
	}
	if _, err := probeTLS(ctx, "postgres://"+addr, pool); err == nil {
		t.Fatal("a server that answers SSLRequest with TLS bytes must fail")
	}
	if _, err := probeTLS(ctx, "ftp://"+addr, pool); err == nil {
		t.Fatal("an unknown scheme must fail")
	}
	if _, err := probeTLS(ctx, "no-port", pool); err == nil {
		t.Fatal("a target without a port must fail")
	}
}

func TestTLSProbeCommandPrintsOneLineAndFailsOnAnyFailure(t *testing.T) {
	good, _, bundle := tlsProbeServer(t, serveTLS)
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, []byte(bundle), 0o600); err != nil {
		t.Fatal(err)
	}
	bad := "127.0.0.1:1"

	var out bytes.Buffer
	tlsProbeCmd.SetOut(&out)
	tlsProbeCmd.SetIn(strings.NewReader(good + "\n\n# comment\n" + bad + "\n"))
	if err := tlsProbeCmd.Flags().Set("ca-file", caFile); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tlsProbeCmd.Flags().Set("ca-file", "") })
	err := tlsProbeCmd.RunE(tlsProbeCmd, nil)
	if err == nil {
		t.Fatal("expected a failure exit")
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 || !strings.HasPrefix(lines[0], good+" OK TLS 1.3 TLS_") || !strings.HasPrefix(lines[1], bad+" FAIL ") {
		t.Fatalf("unexpected output:\n%s", out.String())
	}
}

func TestTLSProbeRequiresTargets(t *testing.T) {
	tlsProbeCmd.SetIn(strings.NewReader(""))
	if err := tlsProbeCmd.RunE(tlsProbeCmd, nil); err == nil {
		t.Fatal("no targets must be an error")
	}
}

func TestTLSProbeOutputNeverEchoesUserinfoOrQuery(t *testing.T) {
	targets := []string{
		"postgres://user:pass@127.0.0.1:1/db?sslmode=require&password=hunter2",
		"user:pass@127.0.0.1:1",
		"postgres://user:pass@no-port",
		"FAKEUSERINFO@nohost.invalid:443",
		"nohost.invalid:443?token=FAKEQUERY",
		"nohost.invalid:443/FAKEPATH",
	}
	var out bytes.Buffer
	tlsProbeCmd.SetOut(&out)
	tlsProbeCmd.SetIn(strings.NewReader(strings.Join(targets, "\n")))
	t.Cleanup(func() { tlsProbeCmd.SetIn(nil) })
	if err := tlsProbeCmd.RunE(tlsProbeCmd, nil); err == nil {
		t.Fatal("expected a failure exit")
	}
	for _, secret := range []string{"user", "pass", "hunter2", "sslmode", "/db", "FAKEUSERINFO", "FAKEQUERY", "FAKEPATH"} {
		if strings.Contains(out.String(), secret) {
			t.Fatalf("output echoes %q:\n%s", secret, out.String())
		}
	}
	if !strings.Contains(out.String(), "postgres://127.0.0.1:1 FAIL") {
		t.Fatalf("expected host:port label:\n%s", out.String())
	}
}
