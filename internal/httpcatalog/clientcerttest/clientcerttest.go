// Package clientcerttest issues throwaway certificates for client certificate
// tests: a CA made for one test, and end-entity client and server
// certificates it signs. Nothing here is a real credential.
package clientcerttest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// CA is a throwaway certificate authority.
type CA struct {
	Cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// NewCA makes a CA named name, valid for a day either side of now.
func NewCA(t testing.TB, name string) *CA {
	t.Helper()
	key := newKey(t)
	template := &x509.Certificate{SerialNumber: serial(t), Subject: pkix.Name{CommonName: name, Organization: []string{name}},
		NotBefore: time.Now().Add(-24 * time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &CA{Cert: cert, key: key}
}

// Intermediate issues an intermediate CA named name under ca. A client
// certificate it issues verifies against ca only when presented with it.
func (ca *CA) Intermediate(t testing.TB, name string) *CA {
	t.Helper()
	return ca.issueCA(t, name, newKey(t))
}

// Reissue signs intermediate again under ca with a new serial, keeping its
// name and key, as a renewal does: what it issued still verifies under it.
func (ca *CA) Reissue(t testing.TB, intermediate *CA) *CA {
	t.Helper()
	return ca.issueCA(t, intermediate.Cert.Subject.CommonName, intermediate.key)
}

func (ca *CA) issueCA(t testing.TB, name string, key *ecdsa.PrivateKey) *CA {
	t.Helper()
	template := &x509.Certificate{SerialNumber: serial(t), Subject: pkix.Name{CommonName: name, Organization: []string{name}},
		NotBefore: time.Now().Add(-24 * time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.Cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &CA{Cert: cert, key: key}
}

// Pool trusts this CA only.
func (ca *CA) Pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	return pool
}

// PEM is the CA certificate, and KeyPEM its key: stored together as a client
// certificate, they are the CA-as-leaf mistake the broker refuses.
func (ca *CA) PEM() string { return encode("CERTIFICATE", ca.Cert.Raw) }

func (ca *CA) KeyPEM(t testing.TB) string { return keyPEMOf(t, ca.key) }

// Client issues an end-entity client certificate valid from notBefore to
// notAfter, as PEM certificate and key.
func (ca *CA) Client(t testing.TB, name string, notBefore, notAfter time.Time) (certPEM, keyPEM string) {
	t.Helper()
	key := newKey(t)
	template := &x509.Certificate{SerialNumber: serial(t), Subject: pkix.Name{CommonName: name}, NotBefore: notBefore, NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, BasicConstraintsValid: true}
	return ca.sign(t, template, key), keyPEMOf(t, key)
}

// ValidClient is Client valid for an hour either side of now.
func (ca *CA) ValidClient(t testing.TB, name string) (certPEM, keyPEM string) {
	return ca.Client(t, name, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
}

// Server issues a server certificate for hosts.
func (ca *CA) Server(t testing.TB, hosts ...string) tls.Certificate {
	t.Helper()
	key := newKey(t)
	template := &x509.Certificate{SerialNumber: serial(t), Subject: pkix.Name{CommonName: hosts[0]}, DNSNames: hosts,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	pair, err := tls.X509KeyPair([]byte(ca.sign(t, template, key)), []byte(keyPEMOf(t, key)))
	if err != nil {
		t.Fatal(err)
	}
	return pair
}

func (ca *CA) sign(t testing.TB, template *x509.Certificate, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, template, ca.Cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return encode("CERTIFICATE", der)
}

func newKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func keyPEMOf(t testing.TB, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return encode("PRIVATE KEY", der)
}

func serial(t testing.TB) *big.Int {
	t.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func encode(kind string, der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der}))
}
