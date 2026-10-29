package httpcatalog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	vaultapi "github.com/hashicorp/vault/api"

	"github.com/Infisical/agent-vault/internal/httpcatalog/clientcerttest"
)

// certVault answers like a KV version 2 mount holding client certificates.
type certVault struct {
	mu      sync.Mutex
	secrets map[string]map[string]interface{} // by "<mount>/data/<path>"
	version map[string]int
	err     error
	reads   int
}

func newCertVault() *certVault {
	return &certVault{secrets: map[string]map[string]interface{}{}, version: map[string]int{}}
}

func (v *certVault) put(path, certPEM, keyPEM string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.version[path]++
	v.secrets[path] = map[string]interface{}{ClientCertificateField: certPEM, ClientCertificateKeyField: keyPEM}
}

func (v *certVault) setFields(path string, fields map[string]interface{}) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.version[path]++
	v.secrets[path] = fields
}

func (v *certVault) fail(err error) {
	v.mu.Lock()
	v.err = err
	v.mu.Unlock()
}

func (v *certVault) ReadWithDataWithContext(_ context.Context, path string, _ map[string][]string) (*vaultapi.Secret, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.reads++
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

const certPath = "gatehouse/data/vendors/example-mtls"

var certRef = ClientCertificateRef{Mount: "gatehouse", Path: "vendors/example-mtls"}

func TestClientCertificateEntries(t *testing.T) {
	entry := func(fields string) string {
		return `{"entries":[{"name":"reads","host":"rpc.example.com","http2":true,"pathPrefixes":["/example.v1.Reads/Get"],"methods":["POST"],` +
			fields + `,"pools":["pool-agent"]}]}`
	}
	cert := `"clientCertificate":{"mount":"gatehouse","path":"vendors/example-mtls"}`
	header := `"header":"Authorization","scheme":"Bearer","placeholder":"__vault_RPC_KEY__","key":{"mount":"gatehouse","path":"vendors/rpc","field":"key"}`
	c, err := Parse([]byte(entry(cert)))
	if err != nil {
		t.Fatalf("a certificate-only entry: %v", err)
	}
	e := c.Entries()[0]
	if e.HeaderCredential() || *e.ClientCertificate != certRef {
		t.Fatalf("parsed %+v", e)
	}
	c, err = Parse([]byte(entry(cert + "," + header)))
	if err != nil || !c.Entries()[0].HeaderCredential() {
		t.Fatalf("a certificate and a header key: %v", err)
	}
	for name, fields := range map[string]string{
		"no credential at all":     `"forwardHeaders":["X-Example"]`,
		"placeholder, no header":   cert + `,"placeholder":"__vault_RPC_KEY__"`,
		"key, no header":           cert + `,"key":{"mount":"gatehouse","path":"vendors/rpc","field":"key"}`,
		"scheme, no header":        cert + `,"scheme":"Bearer"`,
		"basicUser, no header":     cert + `,"basicUser":true`,
		"path outside vendors/":    `"clientCertificate":{"mount":"gatehouse","path":"secrets/example"}`,
		"no path":                  `"clientCertificate":{"mount":"gatehouse"}`,
		"bad mount":                `"clientCertificate":{"mount":"Gatehouse!","path":"vendors/example"}`,
		"field names are fixed":    `"clientCertificate":{"mount":"gatehouse","path":"vendors/example","field":"cert"}`,
		"header without the rest":  cert + `,"header":"Authorization"`,
		"empty certificate object": `"clientCertificate":{}`,
	} {
		if _, err := Parse([]byte(entry(fields))); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	gcp := `{"entries":[{"name":"g","kind":"gcp","host":"bigquery.googleapis.com","pathPrefixes":["/bigquery/v2/"],"methods":["GET"],` +
		`"placeholder":"__vault_GCP__","gcp":{"serviceAccount":"reader@example-project.iam.gserviceaccount.com","scopes":["https://www.googleapis.com/auth/bigquery.readonly"]},` +
		cert + `,"pools":["pool-agent"]}]}`
	if _, err := Parse([]byte(gcp)); err == nil || !strings.Contains(err.Error(), "clientCertificate") {
		t.Errorf("a gcp entry with a client certificate: %v", err)
	}
}

func TestClientCertificatesReadRotateAndRevoke(t *testing.T) {
	ca := clientcerttest.NewCA(t, "example-ca")
	vault := newCertVault()
	certPEM, keyPEM := ca.ValidClient(t, "first")
	vault.put(certPath, certPEM, keyPEM)
	now := time.Now()
	certs := &ClientCertificates{Vault: vault, Now: func() time.Time { return now }}
	ctx := context.Background()

	first, err := certs.Get(ctx, certRef)
	if err != nil || first.Version != 1 || first.Usable(now) != nil {
		t.Fatalf("first read: %v %v", first, err)
	}
	if leaf := first.TLSCertificate().Leaf; leaf == nil || leaf.Subject.CommonName != "first" {
		t.Fatal("the leaf is not the stored certificate")
	}
	// Printing never shows the key.
	for _, printed := range []string{fmt.Sprint(first), fmt.Sprintf("%+v", first), fmt.Sprintf("%#v", *first), fmt.Sprintf("%v", []*ClientCertificate{first})} {
		if strings.Contains(printed, "PRIVATE") || !strings.Contains(printed, "client-certificate(v1") {
			t.Fatalf("printed as %q", printed)
		}
	}

	// A new version is presented within the TTL, without a restart.
	secondPEM, secondKey := ca.ValidClient(t, "second")
	vault.put(certPath, secondPEM, secondKey)
	if again, _ := certs.Get(ctx, certRef); again.ChainFingerprint != first.ChainFingerprint {
		t.Fatal("re-read inside the TTL")
	}
	now = now.Add(61 * time.Second)
	second, err := certs.Get(ctx, certRef)
	if err != nil || second.Version != 2 || second.ChainFingerprint == first.ChainFingerprint {
		t.Fatalf("after the TTL: %v %v", second, err)
	}

	// Vault down: the cached certificate serves for MaxStale past its TTL.
	vault.fail(errors.New("connection refused"))
	now = now.Add(4 * time.Minute)
	if stale, err := certs.Get(ctx, certRef); err != nil || stale.ChainFingerprint != second.ChainFingerprint {
		t.Fatalf("stale: %v", err)
	}
	now = now.Add(3 * time.Minute)
	if _, err := certs.Get(ctx, certRef); !errors.Is(err, ErrClientCertificateUnavailable) || errors.Is(err, ErrClientCertificateDeleted) {
		t.Fatalf("past MaxStale: %v", err)
	}
	vault.fail(nil)

	// Removing a field revokes it from the next read; no stale copy.
	vault.setFields(certPath, map[string]interface{}{ClientCertificateField: secondPEM})
	now = now.Add(61 * time.Second)
	if _, err := certs.Get(ctx, certRef); !errors.Is(err, ErrClientCertificateDeleted) || errors.Is(err, ErrClientCertificateInvalid) {
		t.Fatalf("key removed: %v", err)
	}
	vault.fail(errors.New("sealed"))
	if _, err := certs.Get(ctx, certRef); !errors.Is(err, ErrClientCertificateDeleted) {
		t.Fatalf("a deleted certificate came back while Vault was down: %v", err)
	}
	vault.fail(nil)

	// Invalidate re-reads at once, at most every 30 seconds.
	vault.put(certPath, certPEM, keyPEM)
	certs.Invalidate(certRef)
	if back, err := certs.Get(ctx, certRef); err != nil || back.ChainFingerprint != first.ChainFingerprint {
		t.Fatalf("after Invalidate: %v", err)
	}
	vault.put(certPath, secondPEM, secondKey)
	certs.Invalidate(certRef)
	if same, _ := certs.Get(ctx, certRef); same.ChainFingerprint != first.ChainFingerprint {
		t.Fatal("a second Invalidate inside 30 seconds re-read")
	}
}

func TestClientCertificateValues(t *testing.T) {
	ca := clientcerttest.NewCA(t, "example-ca")
	other := clientcerttest.NewCA(t, "other-ca")
	certPEM, keyPEM := ca.ValidClient(t, "client")
	_, otherKey := other.ValidClient(t, "other")
	now := time.Now()
	for name, pair := range map[string][2]string{
		"not PEM":                   {"not a certificate", keyPEM},
		"key for another cert":      {certPEM, otherKey},
		"a CA as the certificate":   {ca.PEM(), ca.KeyPEM(t)},
		"key in the cert field":     {keyPEM, keyPEM},
		"certificate over the size": {certPEM + strings.Repeat("#", maxClientCertificateBytes), keyPEM},
	} {
		if _, err := ParseClientCertificate(pair[0], pair[1]); !errors.Is(err, ErrClientCertificateInvalid) || !errors.Is(err, ErrClientCertificateDeleted) {
			t.Errorf("%s: %v", name, err)
		} else if strings.Contains(err.Error(), "BEGIN") {
			t.Errorf("%s: the error quotes the value", name)
		}
	}
	// A chain, leaf first, is presented whole.
	cert, err := ParseClientCertificate(certPEM+ca.PEM(), keyPEM)
	if err != nil || len(cert.TLSCertificate().Certificate) != 2 {
		t.Fatalf("chain: %v", err)
	}
	// ChainFingerprint follows the whole chain: one leaf under a renewed
	// intermediate is a new one, the same chain read again is not.
	issuing := ca.Intermediate(t, "issuing-ca")
	leafPEM, leafKey := issuing.ValidClient(t, "chained")
	first, err := ParseClientCertificate(leafPEM+issuing.PEM(), leafKey)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := ParseClientCertificate(leafPEM+issuing.PEM(), leafKey)
	renewed, err := ParseClientCertificate(leafPEM+ca.Reissue(t, issuing).PEM(), leafKey)
	leafOnly, _ := ParseClientCertificate(leafPEM, leafKey)
	if err != nil || again.ChainFingerprint != first.ChainFingerprint || renewed.ChainFingerprint == first.ChainFingerprint || leafOnly.ChainFingerprint == first.ChainFingerprint {
		t.Fatalf("chain fingerprints: %v", err)
	}
	expired, expiredKey := ca.Client(t, "expired", now.Add(-2*time.Hour), now.Add(-time.Hour))
	early, earlyKey := ca.Client(t, "early", now.Add(time.Hour), now.Add(2*time.Hour))
	for name, pair := range map[string][2]string{"expired": {expired, expiredKey}, "not yet valid": {early, earlyKey}} {
		cert, err := ParseClientCertificate(pair[0], pair[1])
		if err != nil || !errors.Is(cert.Usable(now), ErrClientCertificateExpired) {
			t.Errorf("%s: %v %v", name, err, cert)
		}
	}
}
