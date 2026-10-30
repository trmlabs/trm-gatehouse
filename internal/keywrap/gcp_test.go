package keywrap

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/googleapis/gax-go/v2"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// fakeGCP checks request checksums as Cloud KMS does and "encrypts" by reversing; the flags corrupt what it returns.
type fakeGCP struct {
	encryptReq         *kmspb.EncryptRequest
	decryptReq         *kmspb.DecryptRequest
	unverified         bool // Encrypt reports the plaintext checksum as not verified
	badCiphertextSum   bool // Encrypt returns a wrong ciphertext checksum
	noCiphertextSum    bool // Encrypt returns no ciphertext checksum
	badPlaintextSum    bool // Decrypt returns a wrong plaintext checksum
	noPlaintextSum     bool // Decrypt returns no plaintext checksum
	lastDecryptedBytes []byte
}

func reversed(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[len(b)-1-i] = b[i]
	}
	return out
}

func (f *fakeGCP) Encrypt(_ context.Context, req *kmspb.EncryptRequest, _ ...gax.CallOption) (*kmspb.EncryptResponse, error) {
	f.encryptReq = req
	ct := reversed(req.Plaintext)
	resp := &kmspb.EncryptResponse{
		Ciphertext:              ct,
		CiphertextCrc32C:        crc32c(ct),
		VerifiedPlaintextCrc32C: checksumMatches(req.Plaintext, req.PlaintextCrc32C) && !f.unverified,
	}
	if f.badCiphertextSum {
		resp.CiphertextCrc32C = wrapperspb.Int64(resp.CiphertextCrc32C.Value + 1)
	}
	if f.noCiphertextSum {
		resp.CiphertextCrc32C = nil
	}
	return resp, nil
}

func (f *fakeGCP) Decrypt(_ context.Context, req *kmspb.DecryptRequest, _ ...gax.CallOption) (*kmspb.DecryptResponse, error) {
	f.decryptReq = req
	if req.CiphertextCrc32C != nil && !checksumMatches(req.Ciphertext, req.CiphertextCrc32C) {
		return nil, errors.New("rpc error: code = InvalidArgument desc = ciphertext checksum mismatch")
	}
	pt := reversed(req.Ciphertext)
	f.lastDecryptedBytes = pt
	resp := &kmspb.DecryptResponse{Plaintext: pt, PlaintextCrc32C: crc32c(pt)}
	if f.badPlaintextSum {
		resp.PlaintextCrc32C = wrapperspb.Int64(resp.PlaintextCrc32C.Value + 1)
	}
	if f.noPlaintextSum {
		resp.PlaintextCrc32C = nil
	}
	return resp, nil
}

func newFakeGCPWrapper(f *fakeGCP) *gcpWrapper {
	return &gcpWrapper{client: f, name: schemeGCP + "projects/my-project-1/locations/global/keyRings/r/cryptoKeys/k"}
}

func TestGCPSendsAndChecksCRC32C(t *testing.T) {
	f := &fakeGCP{}
	w := newFakeGCPWrapper(f)
	dek := []byte("a 32-byte data encryption key...")
	ct, err := w.Wrap(context.Background(), dek, "vault-1")
	if err != nil {
		t.Fatal(err)
	}
	if !checksumMatches(dek, f.encryptReq.PlaintextCrc32C) {
		t.Fatalf("Encrypt was sent no or a wrong plaintext checksum: %v", f.encryptReq.PlaintextCrc32C)
	}
	got, err := w.Unwrap(context.Background(), ct, "vault-1")
	if err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("round trip: %q, %v", got, err)
	}
	if !checksumMatches(ct, f.decryptReq.CiphertextCrc32C) {
		t.Fatalf("Decrypt was sent no or a wrong ciphertext checksum: %v", f.decryptReq.CiphertextCrc32C)
	}
}

func TestCRC32CIsCastagnoli(t *testing.T) {
	// The CRC32C check value from RFC 3720 appendix B.4.
	if got := crc32c([]byte("123456789")).GetValue(); got != 0xe3069283 {
		t.Fatalf("crc32c(123456789) = %#x, want 0xe3069283", got)
	}
}

func TestGCPWrapFailsClosedOnAChecksumMismatch(t *testing.T) {
	for name, f := range map[string]*fakeGCP{
		"plaintext not verified": {unverified: true},
		"wrong ciphertext sum":   {badCiphertextSum: true},
		"no ciphertext sum":      {noCiphertextSum: true},
	} {
		ct, err := newFakeGCPWrapper(f).Wrap(context.Background(), []byte("dek"), "vault-1")
		if err == nil || ct != nil || !strings.Contains(err.Error(), "corrupted in transit") {
			t.Errorf("%s: want a refusal, got %q, %v", name, ct, err)
		}
	}
}

func TestGCPUnwrapFailsClosedOnAChecksumMismatch(t *testing.T) {
	for name, f := range map[string]*fakeGCP{
		"wrong plaintext sum": {badPlaintextSum: true},
		"no plaintext sum":    {noPlaintextSum: true},
	} {
		pt, err := newFakeGCPWrapper(f).Unwrap(context.Background(), []byte("ked"), "vault-1")
		if err == nil || pt != nil || !strings.Contains(err.Error(), "corrupted in transit") {
			t.Errorf("%s: want a refusal, got %q, %v", name, pt, err)
		}
		if !bytes.Equal(f.lastDecryptedBytes, make([]byte, 3)) {
			t.Errorf("%s: the rejected plaintext was not wiped: %q", name, f.lastDecryptedBytes)
		}
	}
}
