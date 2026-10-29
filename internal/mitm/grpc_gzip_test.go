package mitm

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"crypto/tls"
	"encoding/binary"
	"io"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/encoding"
	grpcgzip "google.golang.org/grpc/encoding/gzip"
	"google.golang.org/grpc/status"
)

// testDeflate is a compressor gRPC does not name, which the broker cannot
// read and refuses.
type testDeflate struct{}

func (testDeflate) Compress(w io.Writer) (io.WriteCloser, error) {
	return flate.NewWriter(w, flate.BestSpeed)
}
func (testDeflate) Decompress(r io.Reader) (io.Reader, error) { return flate.NewReader(r), nil }
func (testDeflate) Name() string                              { return "x-test-deflate" }

func init() { encoding.RegisterCompressor(testDeflate{}) }

// A gzip-compressed call, as Temporal's Rust-based SDKs send every call, is
// checked and forwarded as uncompressed messages: the vendor reads the
// message, and a placeholder or decoy inside it is still found.
func TestGRPCGzipRequestsAreCheckedUncompressed(t *testing.T) {
	f := newGRPCFixture(t)
	cc := f.client(t, "rpc.example.com")
	out, _, err := f.unary(t, cc, "/example.v1.Reads/Get", strings.Repeat("row 7 ", 200), grpc.UseCompressor(grpcgzip.Name))
	if err != nil || out != "got "+strings.Repeat("row 7 ", 200) {
		t.Fatalf("gzip call: %.40q %v", out, err)
	}
	_, _, err = f.unary(t, cc, "/example.v1.Reads/Get", "id __vault_RPC_KEY__", grpc.UseCompressor(grpcgzip.Name))
	if status.Code(err) != codes.InvalidArgument || !strings.Contains(status.Convert(err).Message(), "placeholder_misplaced") {
		t.Fatalf("placeholder inside a gzip message: %v", err)
	}
}

func gzipped(t *testing.T, data []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	_, _ = zw.Write(data)
	_ = zw.Close()
	return b.Bytes()
}

func frame(flag byte, message []byte) []byte {
	out := []byte{flag, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(out[1:], uint32(len(message))) // #nosec G115 -- test messages are small
	return append(out, message...)
}

func TestGRPCPlainMessages(t *testing.T) {
	plain := append(frame(0, []byte("one")), frame(0, []byte("two"))...)
	mixed := append(frame(1, gzipped(t, []byte("one"))), frame(0, []byte("two"))...)
	for name, tc := range map[string]struct {
		body     []byte
		encoding string
		limit    int64
		want     []byte
		outcome  string
	}{
		"plain stays as is":           {plain, "", 1024, plain, ""},
		"gzip messages decompress":    {mixed, "gzip", 1024, plain, ""},
		"empty body":                  {nil, "gzip", 1024, []byte{}, ""},
		"compressed without gzip":     {mixed, "identity", 1024, nil, "request_shape"},
		"unknown flag":                {frame(2, []byte("one")), "gzip", 1024, nil, "request_shape"},
		"cut header":                  {plain[:3], "", 1024, nil, "request_shape"},
		"cut message":                 {plain[:len(plain)-1], "", 1024, nil, "request_shape"},
		"not gzip inside":             {frame(1, []byte("not gzip")), "gzip", 1024, nil, "request_shape"},
		"bomb past the limit":         {frame(1, gzipped(t, make([]byte, 1<<20))), "gzip", 4096, nil, "request_too_large"},
		"plain past the limit":        {frame(0, make([]byte, 100)), "", 50, nil, "request_too_large"},
		"decompressed exactly at max": {frame(1, gzipped(t, make([]byte, 95))), "gzip", 100, frame(0, make([]byte, 95)), ""},
	} {
		got, outcome := grpcPlainMessages(tc.body, tc.encoding, tc.limit)
		if outcome != tc.outcome || (outcome == "" && !bytes.Equal(got, tc.want)) {
			t.Errorf("%s: %q %q", name, outcome, got)
		}
	}
}

// A gRPC client that sets a TLS server name sends it, without the port, as
// the call's authority; over HTTP/2 that names the tunnel's host.
func TestGRPCAuthorityWithoutPort(t *testing.T) {
	f := newClientCertFixture(t)
	cc, err := grpc.NewClient("passthrough:///temporal.example.com:7233", grpc.WithNoProxy(), grpc.WithContextDialer(f.grpc.connect),
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{RootCAs: f.grpc.roots, ServerName: "temporal.example.com", MinVersion: tls.VersionTLS12})),
		grpc.WithDefaultCallOptions(grpc.ForceCodec(rawCodec{})))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cc.Close() })
	if out, err := f.call(t, cc, "GetSystemInfo"); err != nil || !strings.HasSuffix(out, "GetSystemInfo") {
		t.Fatalf("bare-host authority: %q %v", out, err)
	}
}
