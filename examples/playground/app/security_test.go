package main

import (
	"encoding/base64"
	"encoding/hex"
	"net"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestBrowserBoundary(t *testing.T) {
	cases := []struct {
		method, host, origin, upgrade string
		want                          bool
	}{
		{"GET", "127.0.0.1:8787", "", "", true},
		{"POST", "localhost:8787", "http://localhost:8787", "", true},
		{"GET", "127.0.0.1:8787", "http://127.0.0.1:8787", "websocket", true},
		{"POST", "127.0.0.1:8787", "", "", false},
		{"GET", "attacker.example:8787", "", "", false},
		{"POST", "localhost:8787", "https://attacker.example", "", false},
		{"GET", "localhost:8787", "null", "websocket", false},
		{"GET", "localhost:8787", "", "websocket", false},
		{"GET", "localhost:8787.attacker.example", "", "", false},
	}
	for _, c := range cases {
		r := httptest.NewRequest(c.method, "http://localhost:8787/", nil)
		r.Host = c.host
		r.Header.Set("Origin", c.origin)
		r.Header.Set("Upgrade", c.upgrade)
		if got := allowedBrowser(r); got != c.want {
			t.Errorf("%+v: got %v", c, got)
		}
	}
}
func TestTargetRecognition(t *testing.T) {
	key := "demo_" + strings.Repeat("9a", 32)
	target := []targetHash{{Name: "test", SHA256: hash(key), Length: len(key)}}
	for name, value := range map[string]string{"raw": key, "embedded": "diagnostic: " + key + " end", "base64": base64.StdEncoding.EncodeToString([]byte(key)), "hex": hex.EncodeToString([]byte(key)), "url": "%64" + url.QueryEscape(key[1:])} {
		t.Run(name, func(t *testing.T) {
			if len(matches(value, target)) != 1 {
				t.Fatal("missed target")
			}
		})
	}
	for _, v := range []string{"__vault_PAYMENTS_KEY__", "demo_" + strings.Repeat("a1", 32), "", strings.Repeat("x", 40000)} {
		if len(matches(v, target)) != 0 {
			t.Fatal("false positive")
		}
	}
}

func TestTunnelClosesWhenEitherPeerLeaves(t *testing.T) {
	for _, upstream := range []bool{false, true} {
		a, client := net.Pipe()
		b, server := net.Pipe()
		done := make(chan struct{})
		go func() { pipe(a, b); close(done) }()
		peer := server
		if upstream {
			_ = server.Close()
			peer = client
		} else {
			_ = client.Close()
		}
		_ = peer.SetReadDeadline(time.Now().Add(time.Second))
		var buf [1]byte
		_, err := peer.Read(buf[:])
		if err == nil {
			t.Fatal("peer did not close")
		}
		if e, ok := err.(net.Error); ok && e.Timeout() {
			t.Fatal("closed peer left tunnel hanging")
		}
		_ = peer.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("tunnel did not exit")
		}
	}
}
