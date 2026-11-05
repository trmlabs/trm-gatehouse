package httpcatalog

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// maxPinnedCABytes bounds a database entry's pinned CA; the catalog is held in memory and in every Vault entry document.
const maxPinnedCABytes = 32 << 10

// validPinnedCA accepts only PEM CERTIFICATE blocks, each a CA or self-signed: pinning a leaf another CA issued would trust nothing the handshake can check.
func validPinnedCA(text string) error {
	if len(text) > maxPinnedCABytes {
		return fmt.Errorf("postgres ca is over %d bytes", maxPinnedCABytes)
	}
	rest := []byte(text)
	count := 0
	for {
		rest = bytes.TrimLeft(rest, " \t\r\n")
		if len(rest) == 0 {
			break
		}
		block, next := pem.Decode(rest)
		if block == nil || !bytes.HasPrefix(rest, []byte("-----BEGIN ")) {
			return errors.New("postgres ca has text that is not a PEM certificate")
		}
		rest = next
		if block.Type != "CERTIFICATE" {
			return errors.New("postgres ca holds a PEM block that is not a CERTIFICATE")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("postgres ca certificate %d: %w", count+1, err)
		}
		if (!cert.BasicConstraintsValid || !cert.IsCA) && !selfSigned(cert) {
			return fmt.Errorf("postgres ca certificate %d (%s) is neither a CA nor self-signed", count+1, cert.Subject)
		}
		count++
	}
	if count == 0 {
		return errors.New("postgres ca has no PEM certificate")
	}
	return nil
}

// selfSigned checks the signature against the certificate's own key without CheckSignatureFrom's CA constraint, since Citus's certificate has no extensions.
func selfSigned(cert *x509.Certificate) bool {
	return bytes.Equal(cert.RawIssuer, cert.RawSubject) &&
		cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) == nil
}
