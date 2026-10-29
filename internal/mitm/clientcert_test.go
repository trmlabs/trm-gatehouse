package mitm

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

	vaultapi "github.com/hashicorp/vault/api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/Infisical/agent-vault/internal/auditchain"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/httpcatalog"
	"github.com/Infisical/agent-vault/internal/httpcatalog/clientcerttest"
)

// workflowService is the Temporal frontend service a read-only entry lists
// methods of; the tests need no Temporal code, since gRPC routes by path.
const workflowService = "/temporal.api.workflowservice.v1.WorkflowService/"

// temporalReads are the reads the test entry lists.
var temporalReads = []string{"GetSystemInfo", "ListWorkflowExecutions", "CountWorkflowExecutions", "DescribeWorkflowExecution", "GetWorkflowExecutionHistory"}

// certVault answers like a KV version 2 mount holding client certificates.
type certVault struct {
	mu      sync.Mutex
	secrets map[string]map[string]interface{} // by "<mount>/data/<path>"
	version map[string]int
	err     error
	reads   map[string]int
}

// at stores a new version at path, taking a certificate and key as
// clientcerttest issues them: f.vault.at(path)(ca.ValidClient(t, name)).
func (v *certVault) at(path string) func(certPEM, keyPEM string) {
	return func(certPEM, keyPEM string) {
		v.mu.Lock()
		defer v.mu.Unlock()
		v.version[path]++
		v.secrets[path] = map[string]interface{}{httpcatalog.ClientCertificateField: certPEM, httpcatalog.ClientCertificateKeyField: keyPEM}
	}
}

func (v *certVault) remove(path string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	delete(v.secrets, path)
}

func (v *certVault) readsOf(path string) int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.reads[path]
}

func (v *certVault) ReadWithDataWithContext(_ context.Context, path string, _ map[string][]string) (*vaultapi.Secret, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.reads[path]++
	if v.err != nil {
		return nil, v.err
	}
	fields, ok := v.secrets[path]
	if !ok {
		return nil, nil
	}
	return &vaultapi.Secret{Data: map[string]interface{}{"data": fields,
		"metadata": map[string]interface{}{"version": json.Number(strconv.Itoa(v.version[path]))}}}, nil
}

// mtlsCall is one call an upstream that requires client certificates took:
// the gRPC method or HTTP path, the client certificate's common name, any
// Authorization the broker sent with it, and (HTTP/1.1 side) the serials of
// the intermediates presented after the leaf.
type mtlsCall struct{ method, client, auth, chain string }

// intermediates lists the serials of the certificates presented after the
// leaf.
func intermediates(presented []*x509.Certificate) string {
	var serials []string
	for _, c := range presented[1:] {
		serials = append(serials, c.SerialNumber.String())
	}
	return strings.Join(serials, ",")
}

type mtlsUpstream struct {
	mu    sync.Mutex
	calls []mtlsCall
}

func (u *mtlsUpstream) record(c mtlsCall) {
	u.mu.Lock()
	u.calls = append(u.calls, c)
	u.mu.Unlock()
}

func (u *mtlsUpstream) all() []mtlsCall {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]mtlsCall(nil), u.calls...)
}

func (u *mtlsUpstream) last() mtlsCall {
	calls := u.all()
	if len(calls) == 0 {
		return mtlsCall{}
	}
	return calls[len(calls)-1]
}

const (
	temporalPath = "gatehouse/data/vendors/temporal-read"
	restPath     = "gatehouse/data/vendors/rest-read"
)

// clientCertFixture is a broker in front of three upstreams that each require
// a client certificate from clientCA: a gRPC server playing a Temporal
// frontend (temporal.example.com:7233, entry temporal-read, certificate-only),
// an HTTP/1.1 server (rest.example.com, entry rest-read, its own certificate
// besides a header key), and the same HTTP/1.1 server under another name
// (nocert.example.com, entry nocert, a header key and no certificate).
type clientCertFixture struct {
	serverCA *clientcerttest.CA // signs the upstreams' server certificates
	clientCA *clientcerttest.CA // the only CA the upstreams take client certificates from
	routes   sync.Map           // host:port the broker dials -> listener address
	proxy    *Proxy
	vault    *certVault
	now      atomic.Int64 // the certificate cache's clock, Unix nanoseconds
	grpcSide *mtlsUpstream
	restSide *mtlsUpstream
	audit    *adapterAudit
	keys     *adapterKeys
	grpc     *grpcFixture // its connect dials the broker
	http     *http.Client
}

func newClientCertFixture(t *testing.T, options ...func(*HeaderAdapter)) *clientCertFixture {
	t.Helper()
	serverCA, clientCA := clientcerttest.NewCA(t, "upstream-server-ca"), clientcerttest.NewCA(t, "upstream-client-ca")
	f := &clientCertFixture{serverCA: serverCA, clientCA: clientCA, grpcSide: &mtlsUpstream{}, restSide: &mtlsUpstream{}, audit: &adapterAudit{}, keys: &adapterKeys{value: grpcKey},
		vault: &certVault{secrets: map[string]map[string]interface{}{}, version: map[string]int{}, reads: map[string]int{}}}
	f.now.Store(time.Now().UnixNano())
	f.vault.at(temporalPath)(clientCA.ValidClient(t, "factory-reader"))
	f.vault.at(restPath)(clientCA.ValidClient(t, "rest-reader"))
	requireClientCert := func(cert tls.Certificate) *tls.Config {
		return &tls.Config{Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientCA.Pool(), MinVersion: tls.VersionTLS12}
	}

	// TLS 1.2 on the gRPC side, so a refused certificate fails the handshake
	// itself. Under TLS 1.3 the refusal arrives just after the handshake, and
	// on loopback the broker's first write can meet the closed connection
	// before it reads the alert, which the refusal tests would lose at random.
	// The HTTP/1.1 upstreams and the Temporal clients test use TLS 1.3.
	grpcTLS := requireClientCert(serverCA.Server(t, "temporal.example.com"))
	grpcTLS.MaxVersion = tls.VersionTLS12
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(grpcTLS)), grpc.ForceServerCodec(rawCodec{}),
		grpc.UnknownServiceHandler(func(_ any, stream grpc.ServerStream) error {
			method, _ := grpc.MethodFromServerStream(stream)
			var in []byte
			if err := stream.RecvMsg(&in); err != nil {
				return err
			}
			p, _ := peer.FromContext(stream.Context())
			md, _ := metadata.FromIncomingContext(stream.Context())
			f.grpcSide.record(mtlsCall{method: method, client: p.AuthInfo.(credentials.TLSInfo).State.PeerCertificates[0].Subject.CommonName,
				auth: strings.Join(md.Get("authorization"), ",")})
			out := []byte("ok " + method)
			return stream.SendMsg(&out)
		}))
	grpcListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(grpcListener) }()
	t.Cleanup(srv.Stop)

	rest := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.restSide.record(mtlsCall{method: r.URL.Path, client: r.TLS.PeerCertificates[0].Subject.CommonName, auth: r.Header.Get("Authorization"),
			chain: intermediates(r.TLS.PeerCertificates)})
		_, _ = io.WriteString(w, "hello")
	}))
	rest.TLS = requireClientCert(serverCA.Server(t, "rest.example.com", "nocert.example.com"))
	rest.StartTLS()
	t.Cleanup(rest.Close)

	catalog, err := httpcatalog.Parse([]byte(`{"entries":[
	  {"name":"temporal-read","host":"temporal.example.com","port":7233,"http2":true,"pathPrefixes":[` + quotedReads() + `],"methods":["POST"],
	   "clientCertificate":{"mount":"gatehouse","path":"vendors/temporal-read"},"pools":["pool-agent"]},
	  {"name":"rest-read","host":"rest.example.com","pathPrefixes":["/v1/"],"methods":["GET"],
	   "header":"Authorization","scheme":"Bearer","placeholder":"__vault_REST_KEY__","key":{"mount":"gatehouse","path":"vendors/rest","field":"key"},
	   "clientCertificate":{"mount":"gatehouse","path":"vendors/rest-read"},"pools":["pool-agent"]},
	  {"name":"nocert","host":"nocert.example.com","pathPrefixes":["/v1/"],"methods":["GET"],
	   "header":"Authorization","scheme":"Bearer","placeholder":"__vault_NOCERT_KEY__","key":{"mount":"gatehouse","path":"vendors/nocert","field":"key"},
	   "pools":["pool-agent"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	certs := &httpcatalog.ClientCertificates{Vault: f.vault, Now: func() time.Time { return time.Unix(0, f.now.Load()) }}
	adapter := &HeaderAdapter{Catalog: catalog, Keys: f.keys, Audit: f.audit, ClientCertificates: certs}
	for _, option := range options {
		option(adapter)
	}
	sessions := &scopeResolver{scope: &brokercore.ProxyScope{VaultID: "vault-1", AgentID: "agent-uuid-1", Pool: "pool-agent", WorkloadID: "pod-uid-1", VaultRole: "proxy"}}
	proxyURL, roots, p := setupProxy(t, sessions, &fakeCredProvider{}, func(o *Options) {
		o.StrictCredentialProxy = true
		o.HeaderAdapter = adapter
	})
	p.upstream.TLSClientConfig.RootCAs = serverCA.Pool()
	f.routes.Store("temporal.example.com:7233", grpcListener.Addr().String())
	f.routes.Store("rest.example.com:443", rest.Listener.Addr().String())
	f.routes.Store("nocert.example.com:443", rest.Listener.Addr().String())
	p.upstream.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		to, ok := f.routes.Load(addr)
		if !ok {
			return nil, fmt.Errorf("no route to %s", addr)
		}
		return (&net.Dialer{}).DialContext(ctx, network, to.(string))
	}
	f.proxy = p
	f.grpc = &grpcFixture{proxyURL: proxyURL, roots: roots, proxy: p}
	f.http = newTrustingClient(proxyURL, url.User("workload-token"), roots)
	t.Cleanup(f.http.CloseIdleConnections)
	return f
}

func quotedReads() string {
	quoted := make([]string, len(temporalReads))
	for i, m := range temporalReads {
		quoted[i] = strconv.Quote(workflowService + m)
	}
	return strings.Join(quoted, ",")
}

// temporal is a stock grpc-go client for the Temporal host through the
// broker. Like a Temporal SDK pointed at the broker, it trusts only the
// broker's CA and holds no client certificate or key of its own.
func (f *clientCertFixture) temporal(t *testing.T) *grpc.ClientConn {
	t.Helper()
	cc, err := grpc.NewClient("passthrough:///temporal.example.com:7233", grpc.WithNoProxy(), grpc.WithContextDialer(f.grpc.connect),
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{RootCAs: f.grpc.roots, MinVersion: tls.VersionTLS12})),
		grpc.WithDefaultCallOptions(grpc.ForceCodec(rawCodec{})))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cc.Close() })
	return cc
}

func (f *clientCertFixture) call(t *testing.T, cc *grpc.ClientConn, method string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	in, out := []byte(`{"namespace":"example"}`), []byte(nil)
	err := cc.Invoke(ctx, workflowService+method, &in, &out)
	return string(out), err
}

func (f *clientCertFixture) advance(d time.Duration) { f.now.Add(int64(d)) }

func (f *clientCertFixture) get(t *testing.T, host string) (int, string) {
	t.Helper()
	r, _ := http.NewRequest(http.MethodGet, "https://"+host+"/v1/rows", nil)
	r.Header.Set("Authorization", "Bearer __vault_REST_KEY__")
	if host == "nocert.example.com" {
		r.Header.Set("Authorization", "Bearer __vault_NOCERT_KEY__")
	}
	resp, err := f.http.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header.Get(RefusalHeader) + string(body)
}

// Each listed read reaches an upstream that accepts only client certificates,
// presenting the entry's certificate; the worker holds none and sends no
// credential, and nothing from the certificate or key reaches it or the
// audit trail.
func TestClientCertificateReadsReachAnMTLSUpstream(t *testing.T) {
	f := newClientCertFixture(t)
	cc := f.temporal(t)
	for _, method := range temporalReads {
		out, err := f.call(t, cc, method)
		if err != nil || out != "ok "+workflowService+method {
			t.Fatalf("%s: %q %v", method, out, err)
		}
	}
	calls := f.grpcSide.all()
	if len(calls) != len(temporalReads) {
		t.Fatalf("upstream took %d calls", len(calls))
	}
	for _, c := range calls {
		if c.client != "factory-reader" || c.auth != "" {
			t.Fatalf("upstream saw client %q and authorization %q", c.client, c.auth)
		}
	}
	var rows []auditchain.Event
	for _, e := range f.audit.all() {
		if e.Binding == "temporal-read" {
			rows = append(rows, e)
		}
	}
	if len(rows) != 2*len(temporalReads) || rows[1].Outcome != "completed" || rows[1].Path != workflowService+"GetSystemInfo" {
		t.Fatalf("audit rows: %+v", rows)
	}
	if strings.Contains(fmt.Sprintf("%+v", f.audit.all()), "BEGIN") {
		t.Fatal("a certificate or key reached the audit trail")
	}
}

// Read-only is enforced by the broker: a method the entry does not list,
// such as starting, signalling or terminating a workflow, is refused with
// PERMISSION_DENIED and never reaches the upstream.
func TestClientCertificateEntryRefusesUnlistedMethods(t *testing.T) {
	f := newClientCertFixture(t)
	cc := f.temporal(t)
	for _, method := range []string{"StartWorkflowExecution", "SignalWorkflowExecution", "SignalWithStartWorkflowExecution", "TerminateWorkflowExecution",
		"RequestCancelWorkflowExecution", "ResetWorkflowExecution", "DeleteWorkflowExecution", "UpdateNamespace", "ListWorkflowExecutionsX"} {
		_, err := f.call(t, cc, method)
		if status.Code(err) != codes.PermissionDenied || !strings.Contains(status.Convert(err).Message(), "gatehouse refused: unlisted") {
			t.Fatalf("%s: %v", method, err)
		}
		if last := f.audit.last(); last.Outcome != "unlisted" || last.Path != workflowService+method {
			t.Fatalf("%s row: %+v", method, last)
		}
	}
	if calls := f.grpcSide.all(); len(calls) != 0 {
		t.Fatalf("refused methods reached the upstream: %+v", calls)
	}
	// Another service on the same host is refused the same way.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	in, out := []byte("x"), []byte(nil)
	if err := cc.Invoke(ctx, "/temporal.api.operatorservice.v1.OperatorService/DeleteNamespace", &in, &out); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("operator service: %v", err)
	}
}

// A new certificate in Vault is presented once the cache's minute passes,
// with no restart, on a new connection; the upstream refusing a certificate
// drops it at once.
func TestClientCertificateRotatesWithoutRestart(t *testing.T) {
	f := newClientCertFixture(t)
	cc := f.temporal(t)
	if _, err := f.call(t, cc, "GetSystemInfo"); err != nil || f.grpcSide.last().client != "factory-reader" {
		t.Fatalf("first call: %v %+v", err, f.grpcSide.last())
	}
	f.vault.at(temporalPath)(f.clientCA.ValidClient(t, "factory-reader-rotated"))
	if _, err := f.call(t, cc, "ListWorkflowExecutions"); err != nil || f.grpcSide.last().client != "factory-reader" {
		t.Fatalf("inside the minute: %v %+v", err, f.grpcSide.last())
	}
	f.advance(61 * time.Second)
	if _, err := f.call(t, cc, "ListWorkflowExecutions"); err != nil || f.grpcSide.last().client != "factory-reader-rotated" {
		t.Fatalf("after the minute: %v %+v", err, f.grpcSide.last())
	}
	// The worker's own tunnel never closed: one connection carried all three.
	if out, err := f.call(t, cc, "CountWorkflowExecutions"); err != nil || out == "" {
		t.Fatalf("after rotation: %v", err)
	}
}

// A renewed intermediate under the same leaf and key is a rotation too: the
// next connection after the cache's minute presents the new chain, with no
// restart. Reading the same chain again keeps its transport.
func TestClientCertificateChainRotatesUnderTheSameLeaf(t *testing.T) {
	f := newClientCertFixture(t)
	issuing := f.clientCA.Intermediate(t, "client-issuing-ca")
	leaf, key := issuing.ValidClient(t, "chained-reader")
	f.vault.at(restPath)(leaf+issuing.PEM(), key)
	transport := func() *http.Transport {
		f.proxy.certificatesMu.Lock()
		defer f.proxy.certificatesMu.Unlock()
		return f.proxy.certificateTransports[certificateTransportKey{ref: httpcatalog.ClientCertificateRef{Mount: "gatehouse", Path: "vendors/rest-read"}}].transport
	}
	presents := func(when, chain string) {
		t.Helper()
		if code, body := f.get(t, "rest.example.com"); code != http.StatusOK || body != "hello" {
			t.Fatalf("%s: %d %q", when, code, body)
		}
		if last := f.restSide.last(); last.client != "chained-reader" || last.chain != chain {
			t.Fatalf("%s: upstream saw client %q with intermediates %q, want %q", when, last.client, last.chain, chain)
		}
	}
	presents("first", issuing.Cert.SerialNumber.String())
	first := transport()
	f.advance(61 * time.Second)
	presents("same chain re-read", issuing.Cert.SerialNumber.String())
	if transport() != first {
		t.Fatal("an unchanged chain replaced its transport")
	}
	renewed := f.clientCA.Reissue(t, issuing)
	f.vault.at(restPath)(leaf+renewed.PEM(), key)
	f.advance(61 * time.Second)
	presents("after the intermediate's renewal", renewed.Cert.SerialNumber.String())
}

// Certificates that cannot be presented are refused before the upstream is
// contacted, each with a status a gRPC client acts on.
func TestClientCertificateRefusals(t *testing.T) {
	other := clientcerttest.NewCA(t, "some-other-ca")
	now := time.Now()
	for _, tc := range []struct {
		name    string
		store   func(f *clientCertFixture)
		code    codes.Code
		outcome string
		reached bool
	}{
		{"expired", func(f *clientCertFixture) {
			f.vault.at(temporalPath)(f.clientCA.Client(t, "old", now.Add(-48*time.Hour), now.Add(-time.Hour)))
		}, codes.FailedPrecondition, "client_cert_expired", false},
		{"deleted", func(f *clientCertFixture) { f.vault.remove(temporalPath) }, codes.FailedPrecondition, "client_cert_deleted", false},
		{"a CA as the certificate", func(f *clientCertFixture) {
			f.vault.at(temporalPath)(f.clientCA.PEM(), f.clientCA.KeyPEM(t))
		}, codes.FailedPrecondition, "client_cert_invalid", false},
		{"Vault down", func(f *clientCertFixture) {
			f.vault.mu.Lock()
			f.vault.err = errors.New("connection refused")
			f.vault.mu.Unlock()
		}, codes.Unavailable, "client_cert_unavailable", false},
		// Signed by a CA the upstream does not trust: the upstream refuses
		// it in the handshake.
		{"refused by the upstream", func(f *clientCertFixture) {
			f.vault.at(temporalPath)(other.ValidClient(t, "stranger"))
		}, codes.FailedPrecondition, "client_cert_rejected", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newClientCertFixture(t)
			tc.store(f)
			_, err := f.call(t, f.temporal(t), "GetSystemInfo")
			if status.Code(err) != tc.code || !strings.Contains(status.Convert(err).Message(), "gatehouse refused: "+tc.outcome) {
				t.Fatalf("got %v", err)
			}
			if last := f.audit.last(); last.Outcome != tc.outcome || last.Binding != "temporal-read" {
				t.Fatalf("row: %+v", last)
			}
			if calls := f.grpcSide.all(); len(calls) != 0 {
				t.Fatalf("upstream took %+v", calls)
			}
		})
	}
	// A refused certificate is dropped from the cache, so a rotated one is
	// read on the next call, not a minute later.
	f := newClientCertFixture(t)
	f.vault.at(temporalPath)(other.ValidClient(t, "stranger"))
	cc := f.temporal(t)
	if _, err := f.call(t, cc, "GetSystemInfo"); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("stranger: %v", err)
	}
	f.vault.at(temporalPath)(f.clientCA.ValidClient(t, "fixed"))
	if _, err := f.call(t, cc, "GetSystemInfo"); err != nil || f.grpcSide.last().client != "fixed" {
		t.Fatalf("after the fix: %v %+v", err, f.grpcSide.last())
	}
	// A broker without a certificate reader refuses certificate entries.
	f = newClientCertFixture(t, func(a *HeaderAdapter) { a.ClientCertificates = nil })
	if _, err := f.call(t, f.temporal(t), "GetSystemInfo"); status.Code(err) != codes.FailedPrecondition ||
		!strings.Contains(status.Convert(err).Message(), "broker_misconfigured") {
		t.Fatalf("no reader: %v", err)
	}
}

// Over HTTP/1.1 too, and per entry: each host gets its own entry's
// certificate, and a host whose entry names none gets none, even beside
// entries that do.
func TestClientCertificatePerEntryOverHTTP1(t *testing.T) {
	f := newClientCertFixture(t)
	if code, body := f.get(t, "rest.example.com"); code != http.StatusOK || body != "hello" {
		t.Fatalf("rest: %d %q", code, body)
	}
	if last := f.restSide.last(); last.client != "rest-reader" || last.auth != "Bearer "+grpcKey {
		t.Fatalf("rest upstream saw client %q, key injected %v", last.client, last.auth == "Bearer "+grpcKey)
	}
	if _, err := f.call(t, f.temporal(t), "GetSystemInfo"); err != nil || f.grpcSide.last().client != "factory-reader" {
		t.Fatalf("temporal: %v", err)
	}
	// The upstream requires a certificate and the entry has none to give.
	if code, _ := f.get(t, "nocert.example.com"); code != http.StatusBadGateway {
		t.Fatalf("nocert: %d", code)
	}
	if last := f.audit.last(); last.Binding != "nocert" || last.Outcome != "upstream_error" || last.Cause != "tls_handshake" {
		t.Fatalf("nocert row: %+v", last)
	}
	for _, c := range f.restSide.all() {
		if c.client != "rest-reader" {
			t.Fatalf("rest upstream saw %q", c.client)
		}
	}
	// HTTP/1.1 reads Vault once a minute too, not once per request.
	reads := f.vault.readsOf(restPath)
	for range 3 {
		if code, _ := f.get(t, "rest.example.com"); code != http.StatusOK {
			t.Fatal(code)
		}
	}
	if f.vault.readsOf(restPath) != reads {
		t.Fatalf("Vault read %d more times", f.vault.readsOf(restPath)-reads)
	}
}

// An entry may hold a Basic pair whose user name the client also sends in a
// header of its own, and present a client certificate as well. A client
// holding the stored user name is served with both; another user name is
// refused before the certificate is read or the vendor is called.
func TestClientCertificateWithABasicPairClient(t *testing.T) {
	const publicKey = "pk-synthetic-mtls"
	pair := publicKey + ":" + grpcKey
	catalog, err := httpcatalog.Parse([]byte(`{"entries":[{"name":"pair-read","host":"rest.example.com","pathPrefixes":["/v1/"],"methods":["GET"],
	  "header":"Authorization","basicPair":true,"pairUserHeader":"X-Example-Public-Key","placeholder":"__vault_PAIR_KEY__",
	  "key":{"mount":"gatehouse","path":"vendors/pair","field":"key"},
	  "clientCertificate":{"mount":"gatehouse","path":"vendors/rest-read"},"pools":["pool-agent"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	f := newClientCertFixture(t, func(a *HeaderAdapter) { a.Catalog = catalog })
	f.keys.mu.Lock()
	f.keys.value = pair
	f.keys.mu.Unlock()
	basic := func(s string) string { return "Basic " + base64.StdEncoding.EncodeToString([]byte(s)) }
	get := func(user string) (int, string) {
		r, _ := http.NewRequest(http.MethodGet, "https://rest.example.com/v1/rows", nil)
		r.Header.Set("Authorization", basic(user+":__vault_PAIR_KEY__"))
		r.Header.Set("X-Example-Public-Key", user)
		resp, err := f.http.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, resp.Header.Get(RefusalHeader) + string(body)
	}

	reads := f.vault.readsOf(restPath)
	if code, body := get("pk-worker-own"); code != http.StatusBadRequest || !strings.HasPrefix(body, "credential_header") {
		t.Fatalf("another user: %d %q", code, body)
	}
	if len(f.restSide.all()) != 0 || f.vault.readsOf(restPath) != reads {
		t.Fatalf("a refused user reached the vendor (%d calls) or read the certificate", len(f.restSide.all()))
	}
	if code, body := get(publicKey); code != http.StatusOK || body != "hello" {
		t.Fatalf("stored user: %d %q", code, body)
	}
	if last := f.restSide.last(); last.client != "rest-reader" || last.auth != basic(pair) {
		t.Fatalf("vendor saw client %q, stored pair injected %v", last.client, last.auth == basic(pair))
	}
}
