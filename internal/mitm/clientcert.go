package mitm

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Infisical/agent-vault/internal/httpcatalog"
)

// Client certificates: an entry's certificate and key come from Vault through a one-minute cache; the key signs the handshake in the broker and goes nowhere else.
// Each certificate has its own transports, so a connection never carries a request meant for another certificate.

type clientCertificateKey struct{}

type presentedCertificate struct {
	ref  httpcatalog.ClientCertificateRef
	cert *httpcatalog.ClientCertificate
}

func withClientCertificate(ctx context.Context, ref httpcatalog.ClientCertificateRef, cert *httpcatalog.ClientCertificate) context.Context {
	return context.WithValue(ctx, clientCertificateKey{}, presentedCertificate{ref: ref, cert: cert})
}

func clientCertificateFrom(ctx context.Context) (presentedCertificate, bool) {
	presented, ok := ctx.Value(clientCertificateKey{}).(presentedCertificate)
	return presented, ok && presented.cert != nil
}

func (p *Proxy) clientCertificate(ctx context.Context, entry *httpcatalog.Entry) (*httpcatalog.ClientCertificate, string) {
	if p.adapter.ClientCertificates == nil {
		return nil, "broker_misconfigured"
	}
	cert, err := p.adapter.ClientCertificates.Get(ctx, *entry.ClientCertificate)
	if err == nil {
		err = cert.Usable(time.Now())
	}
	if err != nil {
		return nil, clientCertificateOutcome(err)
	}
	return cert, ""
}

func clientCertificateOutcome(err error) string {
	switch {
	case errors.Is(err, httpcatalog.ErrClientCertificateExpired):
		return "client_cert_expired"
	case errors.Is(err, httpcatalog.ErrClientCertificateInvalid):
		return "client_cert_invalid"
	case errors.Is(err, httpcatalog.ErrClientCertificateDeleted):
		return "client_cert_deleted"
	}
	return "client_cert_unavailable"
}

type certificateTransportKey struct {
	ref httpcatalog.ClientCertificateRef
	h2  bool
}

type certificateTransport struct {
	chain     [32]byte // the ChainFingerprint it presents
	transport *http.Transport
}

// certificateUpstream is the transport for requests presenting a client certificate, one per location and protocol; a changed leaf or intermediate replaces it and the old one's idle connections close.
func (p *Proxy) certificateUpstream(presented presentedCertificate, h2 bool) *http.Transport {
	key := certificateTransportKey{ref: presented.ref, h2: h2}
	p.certificatesMu.Lock()
	defer p.certificatesMu.Unlock()
	current, ok := p.certificateTransports[key]
	if ok && current.chain == presented.cert.ChainFingerprint {
		return current.transport
	}
	if ok {
		current.transport.CloseIdleConnections()
	}
	t := p.newUpstream(h2)
	cert := presented.cert.TLSCertificate()
	t.TLSClientConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return cert, nil }
	if p.certificateTransports == nil {
		p.certificateTransports = map[certificateTransportKey]certificateTransport{}
	}
	p.certificateTransports[key] = certificateTransport{chain: presented.cert.ChainFingerprint, transport: t}
	return t
}

func (p *Proxy) closeCertificateUpstreams() {
	p.certificatesMu.Lock()
	defer p.certificatesMu.Unlock()
	for _, t := range p.certificateTransports {
		t.transport.CloseIdleConnections()
	}
}

var certificateAlerts = []string{"bad certificate", "unsupported certificate", "revoked certificate", "expired certificate",
	"unknown certificate", "unknown certificate authority", "access denied", "certificate required"}

// certificateRejected drops the cached certificate when the upstream refuses it with a TLS alert, so a rotated one is read next request.
func (p *Proxy) certificateRejected(out *http.Request, err error) bool {
	presented, ok := clientCertificateFrom(out.Context())
	if !ok || !certificateAlert(err) {
		return false
	}
	if p.adapter != nil && p.adapter.ClientCertificates != nil {
		p.adapter.ClientCertificates.Invalidate(presented.ref)
	}
	return true
}

// certificateAlert checks the error text too, since transports do not always keep crypto/tls's remote error in their chain.
func certificateAlert(err error) bool {
	text := err.Error()
	var op *net.OpError
	if errors.As(err, &op) && op.Op == "remote error" && op.Err != nil {
		text = "remote error: " + op.Err.Error()
	}
	for _, alert := range certificateAlerts {
		if strings.Contains(text, "remote error: tls: "+alert) {
			return true
		}
	}
	return false
}
