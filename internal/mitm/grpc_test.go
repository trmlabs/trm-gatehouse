package mitm

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/Infisical/agent-vault/internal/auditchain"
	"github.com/Infisical/agent-vault/internal/authorize/authorizetest"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/entitlement"
	"github.com/Infisical/agent-vault/internal/httpcatalog"
	"github.com/Infisical/agent-vault/internal/runnerid"
)

// Synthetic vendor key; never a real credential.
const grpcKey = "sk-synthetic-grpc-key-9d21e4"

type rawCodec struct{}

func (rawCodec) Marshal(v any) ([]byte, error) { return *(v.(*[]byte)), nil }
func (rawCodec) Unmarshal(data []byte, v any) error {
	*(v.(*[]byte)) = append([]byte(nil), data...)
	return nil
}
func (rawCodec) Name() string { return "raw" }

// grpcVendor is a grpc-go server for example.v1.Reads that checks the key and answers by request: "echo-key", "trailer-key", "missing", "stale", and the streaming "sync" and "leak".
type grpcVendor struct {
	mu        sync.Mutex
	auth      []string
	params    []string
	deadline  bool
	firstRead chan struct{}
}

func (v *grpcVendor) check(ctx context.Context) error {
	md, _ := metadata.FromIncomingContext(ctx)
	v.mu.Lock()
	v.auth = append(v.auth, strings.Join(md.Get("authorization"), ","))
	v.params = append(v.params, strings.Join(md.Get("x-example-param"), ","))
	_, v.deadline = ctx.Deadline()
	v.mu.Unlock()
	if strings.Join(md.Get("authorization"), ",") != "Bearer "+grpcKey {
		return status.Error(codes.Unauthenticated, "bad key")
	}
	return nil
}

func (v *grpcVendor) desc() *grpc.ServiceDesc {
	return &grpc.ServiceDesc{
		ServiceName: "example.v1.Reads",
		HandlerType: (*any)(nil),
		Methods: []grpc.MethodDesc{{MethodName: "Get", Handler: func(_ any, ctx context.Context, dec func(any) error, _ grpc.UnaryServerInterceptor) (any, error) {
			var in []byte
			if err := dec(&in); err != nil {
				return nil, err
			}
			if err := v.check(ctx); err != nil {
				return nil, err
			}
			switch string(in) {
			case "echo-key":
				out := []byte("debug: Bearer " + grpcKey)
				return &out, nil
			case "trailer-key":
				_ = grpc.SetTrailer(ctx, metadata.Pairs("x-debug", grpcKey))
			case "missing":
				return nil, status.Error(codes.NotFound, "no such row")
			case "stale":
				return nil, status.Error(codes.Unauthenticated, "token expired")
			}
			out := append([]byte("got "), in...)
			return &out, nil
		}}},
		Streams: []grpc.StreamDesc{{StreamName: "Stream", ServerStreams: true, Handler: func(_ any, stream grpc.ServerStream) error {
			var in []byte
			if err := stream.RecvMsg(&in); err != nil {
				return err
			}
			if err := v.check(stream.Context()); err != nil {
				return err
			}
			// The first message ends with the start of the key, which a byte stream must hold back until it knows what follows.
			first := []byte("row 1 ends sk-synth")
			if string(in) == "leak" {
				first = []byte("row 1")
			}
			if err := stream.SendMsg(&first); err != nil {
				return err
			}
			switch string(in) {
			case "sync":
				select {
				case <-v.firstRead:
				case <-time.After(5 * time.Second):
					return status.Error(codes.DeadlineExceeded, "the first message never arrived")
				}
			case "leak":
				leaked := []byte("row 2 " + grpcKey)
				return stream.SendMsg(&leaked)
			}
			second := []byte("row 2")
			return stream.SendMsg(&second)
		}}},
	}
}

type grpcFixture struct {
	vendor   *grpcVendor
	keys     *adapterKeys
	audit    *adapterAudit
	proxyURL *url.URL
	roots    *x509.CertPool
	proxy    *Proxy
	session  string // the runner session a sidecar sends on CONNECT, if any
}

func grpcTestCert(t *testing.T, hosts ...string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: hosts[0]}, DNSNames: hosts,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, roots
}

func newGRPCFixture(t *testing.T, options ...func(*Options)) *grpcFixture {
	t.Helper()
	f := &grpcFixture{vendor: &grpcVendor{firstRead: make(chan struct{}, 1)}, keys: &adapterKeys{value: grpcKey}, audit: &adapterAudit{}}
	cert, vendorRoots := grpcTestCert(t, "rpc.example.com")
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})),
		grpc.ForceServerCodec(rawCodec{}))
	srv.RegisterService(f.vendor.desc(), nil)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(srv.Stop)
	catalog, err := httpcatalog.Parse([]byte(`{"entries":[
	  {"name":"rpc","host":"rpc.example.com","http2":true,"pathPrefixes":["/example.v1.Reads/"],"methods":["POST"],
	   "header":"Authorization","scheme":"Bearer","placeholder":"__vault_RPC_KEY__","forwardHeaders":["X-Example-Param"],
	   "key":{"mount":"gatehouse","path":"vendors/rpc","field":"key"},"pools":["pool-agent"]},
	  {"name":"rest","host":"rest.example.com","pathPrefixes":["/v1/"],"methods":["GET"],
	   "header":"Authorization","scheme":"Bearer","placeholder":"__vault_REST_KEY__",
	   "key":{"mount":"gatehouse","path":"vendors/rest","field":"key"},"pools":["pool-agent"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	sessions := &scopeResolver{scope: &brokercore.ProxyScope{VaultID: "vault-1", AgentID: "agent-uuid-1", Pool: "pool-agent", WorkloadID: "pod-uid-1", VaultRole: "proxy"}}
	proxyURL, roots, p := setupProxy(t, sessions, &fakeCredProvider{}, func(o *Options) {
		o.StrictCredentialProxy = true
		o.HeaderAdapter = &HeaderAdapter{Catalog: catalog, Keys: f.keys, Audit: f.audit}
		for _, option := range options {
			option(o)
		}
	})
	p.upstream.TLSClientConfig.RootCAs = vendorRoots
	vendorAddr := l.Addr().String()
	p.upstream.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, vendorAddr)
	}
	f.proxyURL, f.roots, f.proxy = proxyURL, roots, p
	return f
}

func (f *grpcFixture) connect(ctx context.Context, addr string) (net.Conn, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", f.proxyURL.Host)
	if err != nil {
		return nil, err
	}
	auth := base64.StdEncoding.EncodeToString([]byte("workload-token:"))
	session := ""
	if f.session != "" {
		session = SessionHeader + ": " + f.session + "\r\n"
	}
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\n%s\r\n", addr, addr, auth, session); err != nil {
		_ = conn.Close()
		return nil, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("CONNECT %s: %w", addr, err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_ = conn.Close()
		return nil, fmt.Errorf("CONNECT %s refused: %s", addr, resp.Status)
	}
	return conn, nil
}

func (f *grpcFixture) client(t *testing.T, host string) *grpc.ClientConn {
	t.Helper()
	cc, err := grpc.NewClient("passthrough:///"+host+":443", grpc.WithNoProxy(),
		grpc.WithContextDialer(f.connect),
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{RootCAs: f.roots, ServerName: host, MinVersion: tls.VersionTLS12})),
		grpc.WithDefaultCallOptions(grpc.ForceCodec(rawCodec{})))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cc.Close() })
	return cc
}

func placeholderContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer __vault_RPC_KEY__", "x-example-param", "table=a")
}

func (f *grpcFixture) unary(t *testing.T, cc *grpc.ClientConn, method, in string, opts ...grpc.CallOption) (string, metadata.MD, error) {
	t.Helper()
	req, out := []byte(in), []byte(nil)
	var header, trailer metadata.MD
	opts = append(opts, grpc.Header(&header), grpc.Trailer(&trailer))
	err := cc.Invoke(placeholderContext(t), method, &req, &out, opts...)
	for _, md := range []metadata.MD{header, trailer} {
		if strings.Contains(fmt.Sprint(md), grpcKey) {
			t.Fatal("the key reached the worker")
		}
	}
	if strings.Contains(string(out), grpcKey) || (err != nil && strings.Contains(err.Error(), grpcKey)) {
		t.Fatal("the key reached the worker")
	}
	return string(out), header, err
}

func TestGRPCUnaryCallGetsTheKeyInjected(t *testing.T) {
	f := newGRPCFixture(t)
	cc := f.client(t, "rpc.example.com")
	out, _, err := f.unary(t, cc, "/example.v1.Reads/Get", "row 7")
	if err != nil || out != "got row 7" {
		t.Fatalf("call: %q %v", out, err)
	}
	f.vendor.mu.Lock()
	auth, params, deadline := f.vendor.auth, f.vendor.params, f.vendor.deadline
	f.vendor.mu.Unlock()
	if len(auth) != 1 || auth[0] != "Bearer "+grpcKey || params[0] != "table=a" || !deadline {
		t.Fatalf("vendor saw %d calls, key injected %v, params %q, deadline %v", len(auth), len(auth) == 1 && auth[0] == "Bearer "+grpcKey, params, deadline)
	}
	var rows []auditchain.Event
	for _, e := range f.audit.all() {
		if e.Binding == "rpc" {
			rows = append(rows, e)
		}
	}
	if len(rows) != 2 || rows[0].Outcome != "admitted" || rows[1].Outcome != "completed" || rows[1].Status != 200 {
		t.Fatalf("audit rows: %+v", rows)
	}
	if rows[0].GRPCStatus != "" || rows[1].GRPCStatus != "0" {
		t.Fatalf("gRPC status on the admitted row %q and the response row %q, want none and 0", rows[0].GRPCStatus, rows[1].GRPCStatus)
	}
	for _, e := range rows {
		if e.Method != "POST" || e.Path != "/example.v1.Reads/Get" {
			t.Fatalf("row method %q path %q", e.Method, e.Path)
		}
	}
}

// A streamed message reaches the worker as soon as it is whole, even when it ends with the start of the key, since the next byte would be a message header.
func TestGRPCServerStreamDeliversEachMessageAtOnce(t *testing.T) {
	f := newGRPCFixture(t)
	cc := f.client(t, "rpc.example.com")
	stream, err := cc.NewStream(placeholderContext(t), &grpc.StreamDesc{ServerStreams: true}, "/example.v1.Reads/Stream")
	if err != nil {
		t.Fatal(err)
	}
	req := []byte("sync")
	if err := stream.SendMsg(&req); err != nil {
		t.Fatal(err)
	}
	_ = stream.CloseSend()
	var first, second []byte
	if err := stream.RecvMsg(&first); err != nil || string(first) != "row 1 ends sk-synth" {
		t.Fatalf("first: %q %v", first, err)
	}
	f.vendor.firstRead <- struct{}{}
	if err := stream.RecvMsg(&second); err != nil || string(second) != "row 2" {
		t.Fatalf("second: %q %v", second, err)
	}
	var none []byte
	if err := stream.RecvMsg(&none); !errors.Is(err, io.EOF) {
		t.Fatalf("stream end: %v", err)
	}
}

// The key in a streamed message or trailer ends the call with INTERNAL before it reaches the worker.
func TestGRPCKeyInStreamOrTrailerEndsTheCall(t *testing.T) {
	f := newGRPCFixture(t)
	cc := f.client(t, "rpc.example.com")
	stream, err := cc.NewStream(placeholderContext(t), &grpc.StreamDesc{ServerStreams: true}, "/example.v1.Reads/Stream")
	if err != nil {
		t.Fatal(err)
	}
	req := []byte("leak")
	_ = stream.SendMsg(&req)
	_ = stream.CloseSend()
	for {
		var msg []byte
		err = stream.RecvMsg(&msg)
		if strings.Contains(string(msg), grpcKey) {
			t.Fatal("the key reached the worker")
		}
		if err != nil {
			break
		}
	}
	if status.Code(err) != codes.Internal {
		t.Fatalf("leaked stream ended with %v", err)
	}
	if last := f.audit.last(); last.Outcome != "secret_echo" || last.GRPCStatus != "13" {
		t.Fatalf("stream row: %+v", last)
	}
	for _, in := range []string{"trailer-key", "echo-key"} {
		if _, _, err := f.unary(t, cc, "/example.v1.Reads/Get", in); status.Code(err) != codes.Internal {
			t.Fatalf("%s: %v", in, err)
		}
		if last := f.audit.last(); last.Outcome != "secret_echo" {
			t.Fatalf("%s outcome %q", in, last.Outcome)
		}
	}
}

func TestGRPCRefusalsAndUpstreamStatuses(t *testing.T) {
	f := newGRPCFixture(t)
	cc := f.client(t, "rpc.example.com")
	_, header, err := f.unary(t, cc, "/example.v1.Writes/Append", "x")
	if status.Code(err) != codes.PermissionDenied || !strings.Contains(status.Convert(err).Message(), "gatehouse refused: unlisted") ||
		strings.Join(header.Get(strings.ToLower(RefusalHeader)), "") != "unlisted" {
		t.Fatalf("unlisted: %v %v", err, header)
	}
	if last := f.audit.last(); last.Outcome != "unlisted" || last.Path != "/example.v1.Writes/Append" || last.Method != "POST" || last.GRPCStatus != "7" {
		t.Fatalf("unlisted row: %+v", last)
	}
	// A request compressed with anything but gzip could not be checked for decoys or placeholders.
	if _, _, err := f.unary(t, cc, "/example.v1.Reads/Get", "x", grpc.UseCompressor(testDeflate{}.Name())); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("compressed: %v", err)
	}
	if last := f.audit.last(); last.GRPCStatus != "3" {
		t.Fatalf("compressed row records gRPC status %q, want 3", last.GRPCStatus)
	}
	if _, _, err := f.unary(t, cc, "/example.v1.Reads/Get", "missing"); status.Code(err) != codes.NotFound || status.Convert(err).Message() != "no such row" {
		t.Fatalf("upstream status: %v", err)
	}
	if last := f.audit.last(); last.Outcome != "completed" || last.GRPCStatus != "5" {
		t.Fatalf("upstream NOT_FOUND row: %+v", last)
	}
	if _, _, err := f.unary(t, cc, "/example.v1.Reads/Get", "stale"); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("stale: %v", err)
	}
	if last := f.audit.last(); last.GRPCStatus != "16" {
		t.Fatalf("stale row records gRPC status %q, want 16", last.GRPCStatus)
	}
	f.keys.mu.Lock()
	invalidated := f.keys.invalidated
	f.keys.err = errors.New("vault down")
	f.keys.mu.Unlock()
	if invalidated != 1 {
		t.Fatalf("UNAUTHENTICATED dropped the key %d times", invalidated)
	}
	if _, _, err := f.unary(t, cc, "/example.v1.Reads/Get", "x"); status.Code(err) != codes.Unavailable ||
		!strings.Contains(status.Convert(err).Message(), "key_unavailable") {
		t.Fatalf("key unavailable: %v", err)
	}
	if last := f.audit.last(); last.Outcome != "key_unavailable" || last.GRPCStatus != "14" {
		t.Fatalf("key unavailable row: %+v", last)
	}
}

// The tunnel offers HTTP/2 only to a host whose entries take it.
func TestHTTP2OnlyForHTTP2Hosts(t *testing.T) {
	f := newGRPCFixture(t)
	for host, want := range map[string]string{"rpc.example.com": "h2", "rest.example.com": "http/1.1"} {
		conn, err := f.connect(context.Background(), host+":443")
		if err != nil {
			t.Fatal(err)
		}
		tlsConn := tls.Client(conn, &tls.Config{RootCAs: f.roots, ServerName: host, NextProtos: []string{"h2", "http/1.1"}, MinVersion: tls.VersionTLS12})
		if err := tlsConn.Handshake(); err != nil {
			t.Fatal(err)
		}
		if got := tlsConn.ConnectionState().NegotiatedProtocol; got != want {
			t.Errorf("%s negotiated %q, want %q", host, got, want)
		}
		_ = tlsConn.Close()
	}
	cc := f.client(t, "rest.example.com")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, out := []byte("x"), []byte(nil)
	if err := cc.Invoke(ctx, "/v1/x", &req, &out); err == nil {
		t.Fatal("a gRPC call reached a host without http2")
	}
}

// An http2 entry whose vendor does not offer HTTP/2 fails the call: the broker never falls back to HTTP/1.1.
func TestHTTP2EntryNeverFallsBackToHTTP1(t *testing.T) {
	cert, vendorRoots := grpcTestCert(t, "old.example.com")
	var reached atomic.Int32
	vendor := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	vendor.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	vendor.StartTLS() // HTTP/1.1 only
	t.Cleanup(vendor.Close)
	catalog, err := httpcatalog.Parse([]byte(`{"entries":[
	  {"name":"old","host":"old.example.com","http2":true,"pathPrefixes":["/example.v1.Reads/"],"methods":["POST"],
	   "header":"Authorization","scheme":"Bearer","placeholder":"__vault_RPC_KEY__",
	   "key":{"mount":"gatehouse","path":"vendors/rpc","field":"key"},"pools":["pool-agent"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	sessions := &scopeResolver{scope: &brokercore.ProxyScope{VaultID: "vault-1", AgentID: "agent-uuid-1", Pool: "pool-agent", WorkloadID: "pod-uid-1", VaultRole: "proxy"}}
	audit := &adapterAudit{}
	proxyURL, roots, p := setupProxy(t, sessions, &fakeCredProvider{}, func(o *Options) {
		o.StrictCredentialProxy = true
		o.HeaderAdapter = &HeaderAdapter{Catalog: catalog, Keys: &adapterKeys{value: grpcKey}, Audit: audit}
	})
	p.upstream.TLSClientConfig.RootCAs = vendorRoots
	p.upstream.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, vendor.Listener.Addr().String())
	}
	f := &grpcFixture{proxyURL: proxyURL, roots: roots, proxy: p}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, out := []byte("x"), []byte(nil)
	err = f.client(t, "old.example.com").Invoke(ctx, "/example.v1.Reads/Get", &req, &out)
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("call to an HTTP/1.1-only vendor: %v, want UNAVAILABLE", err)
	}
	if n := reached.Load(); n != 0 {
		t.Fatalf("the vendor received %d HTTP/1.1 requests", n)
	}
}

func TestGRPCGoogleEntryStreamsAReadSession(t *testing.T) {
	cert, googleRoots := grpcTestCert(t, "sts.googleapis.com", "iamcredentials.googleapis.com", "bigquerystorage.googleapis.com")
	fake := &gcpFake{boundary: map[string]string{}, accounts: map[string]string{}}
	var seen sync.Map
	frame := func(msg string) []byte {
		b := make([]byte, 5+len(msg))
		binary.BigEndian.PutUint32(b[1:], uint32(len(msg))) // #nosec G115 -- short test message
		copy(b[5:], msg)
		return b
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Host, "bigquerystorage.googleapis.com") {
			fake.handler(w, r)
			return
		}
		fake.mu.Lock()
		account := fake.accounts[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
		fake.mu.Unlock()
		body, _ := io.ReadAll(r.Body)
		for name, value := range map[string]string{"proto": r.Proto, "account": account, "params": r.Header.Get("X-Goog-Request-Params"),
			"te": r.Header.Get("Te"), "accept": r.Header.Get("Grpc-Accept-Encoding"), "timeout": fmt.Sprint(r.Header.Get("Grpc-Timeout") != ""),
			"path": r.URL.Path, "body": string(body)} {
			seen.Store(name, value)
		}
		if account == "" {
			w.Header().Set("Content-Type", "application/grpc")
			w.Header().Set("Grpc-Status", "16")
			return
		}
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status")
		_, _ = w.Write(frame("rows-1"))
		w.(http.Flusher).Flush()
		_, _ = w.Write(frame("rows-2"))
		w.Header().Set("Grpc-Status", "0")
	}))
	srv.EnableHTTP2 = true
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	addr := srv.Listener.Addr().String()
	dial := func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	catalog, err := httpcatalog.Parse([]byte(`{"pools":[
	  {"name":"claude","namespace":"n","serviceAccount":"claude","identity":"claude-session","ccpoolID":"ccpool_abc","ceiling":"T1"}],
	 "entries":[
	  {"name":"bq-read","kind":"gcp","http2":true,"host":"bigquerystorage.googleapis.com","tier":"T1","requires":["` + authzGroup + `"],
	   "placeholder":"__vault_GCP__","pools":["claude"],"pathPrefixes":["/google.cloud.bigquery.storage.v1.BigQueryRead/"],
	   "gcp":{"serviceAccount":"bq-cases@example-analytics.iam.gserviceaccount.com","scopes":["https://www.googleapis.com/auth/bigquery"]}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{DialContext: dial, TLSClientConfig: &tls.Config{RootCAs: googleRoots, MinVersion: tls.VersionTLS12}}}
	audit := &adapterAudit{}
	sessions := &scopeResolver{scope: &brokercore.ProxyScope{VaultID: "vault-1", AgentID: "pool-agent", Pool: "claude", WorkloadID: "pod-uid-1", VaultRole: "proxy"}}
	runner := fakeRunner{"alice": {Kind: runnerid.KindPerson, Subject: "sso|alice", Pools: []string{"ccpool_abc"}, TokenSHA256: "aa"}}
	proxyURL, roots, p := setupProxy(t, sessions, &fakeCredProvider{}, func(o *Options) {
		o.StrictCredentialProxy = true
		o.HeaderAdapter = &HeaderAdapter{Catalog: catalog, Keys: &adapterKeys{value: "unused"}, Audit: audit, Runner: runner,
			Sessions:     &authorizetest.MemBinder{},
			Entitlements: &entitlement.Cache{Source: directory{"sso|alice": {authzGroup}}},
			GCPTokens: &httpcatalog.GCPTokens{Root: gcpRoot{}, Client: client, STSURL: "https://sts.googleapis.com/v1/token",
				IAMCredentialsURL: "https://iamcredentials.googleapis.com"}}
	})
	p.upstream.TLSClientConfig.RootCAs = googleRoots
	p.upstream.DialContext = dial
	f := &grpcFixture{proxyURL: proxyURL, roots: roots, session: "alice"}
	cc := f.client(t, "bigquerystorage.googleapis.com")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer __vault_GCP__",
		"x-goog-request-params", "read_stream=projects/example-analytics/locations/us/sessions/s1/streams/0")
	stream, err := cc.NewStream(ctx, &grpc.StreamDesc{ServerStreams: true}, "/google.cloud.bigquery.storage.v1.BigQueryRead/ReadRows")
	if err != nil {
		t.Fatal(err)
	}
	req := []byte("read stream 0")
	_ = stream.SendMsg(&req)
	_ = stream.CloseSend()
	var got []string
	for {
		var msg []byte
		if err := stream.RecvMsg(&msg); err != nil {
			if !errors.Is(err, io.EOF) {
				t.Fatalf("stream: %v", err)
			}
			break
		}
		if strings.Contains(string(msg), "synthetic-") {
			t.Fatal("a Google token reached the worker")
		}
		got = append(got, string(msg))
	}
	if strings.Join(got, ",") != "rows-1,rows-2" {
		t.Fatalf("messages %q", got)
	}
	want := map[string]string{"proto": "HTTP/2.0", "account": "bq-cases@example-analytics.iam.gserviceaccount.com",
		"params": "read_stream=projects/example-analytics/locations/us/sessions/s1/streams/0", "te": "trailers", "accept": "identity",
		"timeout": "true", "path": "/google.cloud.bigquery.storage.v1.BigQueryRead/ReadRows", "body": string(frame("read stream 0"))}
	for name, value := range want {
		if got, _ := seen.Load(name); got != value {
			t.Errorf("Google saw %s %q, want %q", name, got, value)
		}
	}
	if last := audit.last(); last.Binding != "bq-read" || last.Outcome != "completed" || last.Path != "/google.cloud.bigquery.storage.v1.BigQueryRead/ReadRows" || last.GRPCStatus != "0" {
		t.Fatalf("audit row %+v", last)
	}
}

// A draining broker sends GOAWAY: idle tunnels close at once, calls in flight finish, and Shutdown returns before its deadline.
func TestHTTP2TunnelsDrainWithGOAWAY(t *testing.T) {
	f := newGRPCFixture(t, func(o *Options) { o.DrainTunnels = true })
	idle := f.client(t, "rpc.example.com")
	if _, _, err := f.unary(t, idle, "/example.v1.Reads/Get", "x"); err != nil {
		t.Fatal(err)
	}
	busy := f.client(t, "rpc.example.com")
	stream, err := busy.NewStream(placeholderContext(t), &grpc.StreamDesc{ServerStreams: true}, "/example.v1.Reads/Stream")
	if err != nil {
		t.Fatal(err)
	}
	req := []byte("sync")
	_ = stream.SendMsg(&req)
	_ = stream.CloseSend()
	var first []byte
	if err := stream.RecvMsg(&first); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	stopped := make(chan error, 1)
	start := time.Now()
	go func() { stopped <- f.proxy.Shutdown(ctx) }()
	select {
	case err := <-stopped:
		t.Fatalf("Shutdown returned with a call in flight: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	f.vendor.firstRead <- struct{}{}
	var second, none []byte
	if err := stream.RecvMsg(&second); err != nil || string(second) != "row 2" {
		t.Fatalf("in-flight call: %q %v", second, err)
	}
	if err := stream.RecvMsg(&none); !errors.Is(err, io.EOF) {
		t.Fatalf("in-flight call end: %v", err)
	}
	select {
	case err := <-stopped:
		if err != nil || time.Since(start) > 10*time.Second {
			t.Fatalf("Shutdown: %v after %v", err, time.Since(start))
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Shutdown waited past the last call; an HTTP/2 tunnel stayed open")
	}
}

// A status outside 0 to 16 from an upstream is read as none, so its row is still written.
func TestGRPCCallStatusIgnoresOutOfRangeCodes(t *testing.T) {
	for in, want := range map[string]int{"0": 0, "16": 16, "17": -1, "99": -1, "-3": -1, "x": -1, "": -1} {
		resp := &http.Response{Header: http.Header{"Grpc-Status": {in}}, Trailer: http.Header{}}
		if got := grpcCallStatus(resp); got != want {
			t.Errorf("status %q read as %d, want %d", in, got, want)
		}
	}
	if got := grpcStatusRecord(&grpcCall{status: -1}, http.StatusOK); got != "" {
		t.Errorf("a call with no status recorded %q", got)
	}
}

// The row records the code the broker sent, so an upstream 503 with Retry-After reads UNAVAILABLE, as the worker saw.
func TestGRPCWriterRemembersTheCodeItSent(t *testing.T) {
	for _, tc := range []struct {
		name       string
		retryAfter string
		httpStatus int
		want       int
	}{
		{"503 with Retry-After", "5", http.StatusServiceUnavailable, 14},
		{"503 without", "", http.StatusServiceUnavailable, 9},
		{"refusal", "", http.StatusForbidden, 7},
	} {
		rec := httptest.NewRecorder()
		w := &grpcWriter{ResponseWriter: rec}
		if tc.retryAfter != "" {
			w.Header().Set("Retry-After", tc.retryAfter)
		}
		w.WriteHeader(tc.httpStatus)
		call := &grpcCall{status: w.sent}
		if got, trailer := grpcStatusRecord(call, tc.httpStatus), rec.Result().Header.Get(http.TrailerPrefix+"Grpc-Status"); got != strconv.Itoa(tc.want) || (trailer != "" && trailer != got) {
			t.Errorf("%s: row %q, trailer %q, want %d", tc.name, got, trailer, tc.want)
		}
	}
}

// An upstream error whose body echoes the key ends the call with INTERNAL, and the row records that code, not the 403 mapping.
func TestGRPCUpstreamErrorBodyEchoingTheKeyRecordsTheSentStatus(t *testing.T) {
	cert, vendorRoots := grpcTestCert(t, "err.example.com")
	vendor := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("denied " + grpcKey))
	}))
	vendor.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	vendor.EnableHTTP2 = true
	vendor.StartTLS()
	t.Cleanup(vendor.Close)
	catalog, err := httpcatalog.Parse([]byte(`{"entries":[
	  {"name":"err","host":"err.example.com","http2":true,"pathPrefixes":["/example.v1.Reads/"],"methods":["POST"],
	   "header":"Authorization","scheme":"Bearer","placeholder":"__vault_RPC_KEY__",
	   "key":{"mount":"gatehouse","path":"vendors/rpc","field":"key"},"pools":["pool-agent"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	sessions := &scopeResolver{scope: &brokercore.ProxyScope{VaultID: "vault-1", AgentID: "agent-uuid-1", Pool: "pool-agent", WorkloadID: "pod-uid-1", VaultRole: "proxy"}}
	audit := &adapterAudit{}
	proxyURL, roots, p := setupProxy(t, sessions, &fakeCredProvider{}, func(o *Options) {
		o.StrictCredentialProxy = true
		o.HeaderAdapter = &HeaderAdapter{Catalog: catalog, Keys: &adapterKeys{value: grpcKey}, Audit: audit}
	})
	p.upstream.TLSClientConfig.RootCAs = vendorRoots
	p.upstream.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, vendor.Listener.Addr().String())
	}
	f := &grpcFixture{proxyURL: proxyURL, roots: roots, proxy: p}
	_, _, err = f.unary(t, f.client(t, "err.example.com"), "/example.v1.Reads/Get", "x")
	if status.Code(err) != codes.Internal {
		t.Fatalf("call ended with %v, want INTERNAL", err)
	}
	if last := audit.last(); last.Outcome != "secret_echo" || last.GRPCStatus != "13" {
		t.Fatalf("row: %+v", last)
	}
}
