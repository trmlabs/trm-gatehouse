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

// Client certificates on the catalog adapter.
//
// An entry with a clientCertificate has the broker present that certificate
// to its upstream in the TLS handshake (mutual TLS). The certificate and key
// come from Vault per request through a one-minute cache, as header keys do;
// the key signs the handshake inside the broker and goes nowhere else. Each
// certificate gets transports of its own (certificateUpstream), so a
// connection opened with one certificate, or with none, never carries a
// request meant for another, and a rotated certificate starts on new
// connections without a restart.

type clientCertificateKey struct{}

// presentedCertificate is the client certificate an upstream request
// presents, and where it came from.
type presentedCertificate struct {
	ref  httpcatalog.ClientCertificateRef
	cert *httpcatalog.ClientCertificate
}

// withClientCertificate marks an upstream request to present cert.
func withClientCertificate(ctx context.Context, ref httpcatalog.ClientCertificateRef, cert *httpcatalog.ClientCertificate) context.Context {
	return context.WithValue(ctx, clientCertificateKey{}, presentedCertificate{ref: ref, cert: cert})
}

func clientCertificateFrom(ctx context.Context) (presentedCertificate, bool) {
	presented, ok := ctx.Value(clientCertificateKey{}).(presentedCertificate)
	return presented, ok && presented.cert != nil
}

// clientCertificate reads the certificate entry presents upstream, or names
// the refusal when it cannot be presented now.
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

// clientCertificateOutcome names a certificate that cannot be presented: one
// only an operator can fix apart from one that could not be read.
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
	fingerprint [32]byte
	transport   *http.Transport
}

// certificateUpstream is the transport for a request that presents a client
// certificate: one per certificate location and protocol, built from the
// broker's own transport (dialer, egress checks, upstream verification) and
// presenting that certificate whenever the upstream asks for one. When the
// certificate at a location changes, a new transport replaces the old one:
// calls in flight on the old one finish, and its idle connections close.
func (p *Proxy) certificateUpstream(presented presentedCertificate, h2 bool) *http.Transport {
	key := certificateTransportKey{ref: presented.ref, h2: h2}
	p.certificatesMu.Lock()
	defer p.certificatesMu.Unlock()
	current, ok := p.certificateTransports[key]
	if ok && current.fingerprint == presented.cert.Fingerprint {
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
	p.certificateTransports[key] = certificateTransport{fingerprint: presented.cert.Fingerprint, transport: t}
	return t
}

// closeCertificateUpstreams closes the idle connections of every client
// certificate transport, at shutdown.
func (p *Proxy) closeCertificateUpstreams() {
	p.certificatesMu.Lock()
	defer p.certificatesMu.Unlock()
	for _, t := range p.certificateTransports {
		t.transport.CloseIdleConnections()
	}
}

// certificateAlerts are the TLS alerts an upstream sends when it refuses a
// client certificate, as crypto/tls words them.
var certificateAlerts = []string{"bad certificate", "unsupported certificate", "revoked certificate", "expired certificate",
	"unknown certificate", "unknown certificate authority", "access denied", "certificate required"}

// certificateRejected reports whether a failed upstream request presented a
// client certificate and the upstream refused it with a TLS alert. It drops
// the cached certificate, so a rotated one is read on the next request.
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

// certificateAlert reports whether err carries a TLS alert from the peer that
// refuses a certificate. crypto/tls reports one as a net.OpError with Op
// "remote error"; transports do not always keep that error in their chain, so
// its text is checked too.
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
