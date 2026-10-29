package mitm

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"strings"
	"syscall"
)

// splitOutcome separates an outcome from the failure cause a relay may append
// as "outcome/cause".
func splitOutcome(outcome string) (string, string) {
	outcome, cause, _ := strings.Cut(outcome, "/")
	return outcome, cause
}

// upstreamFailed is the outcome of a failed upstream call, naming why.
func upstreamFailed(err error) string { return "upstream_error/" + upstreamCause(err) }

// upstreamCause names a failed upstream call from the fixed list in
// auditchain.Causes, never from the error's text.
func upstreamCause(err error) string {
	var dns *net.DNSError
	var opErr *net.OpError
	var certErr *tls.CertificateVerificationError
	var unknownAuthority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	switch {
	case errors.As(err, &dns):
		return "dns"
	case errors.As(err, &certErr), errors.As(err, &unknownAuthority), errors.As(err, &hostname), errors.As(err, &invalid):
		return "tls_certificate"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "conn_refused"
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.EPIPE), errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return "conn_reset"
	case strings.Contains(err.Error(), "TLS handshake timeout"):
		return "tls_handshake"
	case strings.Contains(err.Error(), "timeout awaiting response headers"):
		return "response_timeout"
	case errors.As(err, &opErr) && opErr.Op == "dial" && opErr.Timeout():
		return "dial_timeout"
	case errors.As(err, &opErr) && opErr.Op == "remote error":
		return "tls_handshake"
	}
	return "other"
}
