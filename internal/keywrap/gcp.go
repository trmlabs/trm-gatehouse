package keywrap

import (
	"context"
	"errors"
	"fmt"
	"hash/crc32"
	"strings"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/googleapis/gax-go/v2"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// gcpClient is the part of the Cloud KMS client used here; tests replace it with a fake.
type gcpClient interface {
	Encrypt(context.Context, *kmspb.EncryptRequest, ...gax.CallOption) (*kmspb.EncryptResponse, error)
	Decrypt(context.Context, *kmspb.DecryptRequest, ...gax.CallOption) (*kmspb.DecryptResponse, error)
}

type gcpWrapper struct {
	client gcpClient
	name   string // the full configured value
}

// newGCP uses Application Default Credentials, so Workload Identity works.
func newGCP(ctx context.Context, value string) (Wrapper, error) {
	client, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("creating Google Cloud KMS client: %w", err)
	}
	return &gcpWrapper{client: client, name: value}, nil
}

func (w *gcpWrapper) KeyName() string { return w.name }

func (w *gcpWrapper) resource() string { return strings.TrimPrefix(w.name, schemeGCP) }

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// crc32c is the CRC32C checksum Cloud KMS uses to detect corruption in transit.
func crc32c(b []byte) *wrapperspb.Int64Value {
	return wrapperspb.Int64(int64(crc32.Checksum(b, castagnoli)))
}

// checksumMatches fails closed when the service returned no checksum.
func checksumMatches(b []byte, sum *wrapperspb.Int64Value) bool {
	return sum != nil && sum.GetValue() == crc32c(b).GetValue()
}

func (w *gcpWrapper) Wrap(ctx context.Context, plaintext []byte, binding string) ([]byte, error) {
	resp, err := w.client.Encrypt(ctx, &kmspb.EncryptRequest{
		Name:                        w.resource(),
		Plaintext:                   plaintext,
		PlaintextCrc32C:             crc32c(plaintext),
		AdditionalAuthenticatedData: []byte(contextLabel + ":" + binding),
	})
	if err != nil {
		return nil, fmt.Errorf("gcp kms encrypt: %w", err)
	}
	if !resp.GetVerifiedPlaintextCrc32C() {
		return nil, errors.New("gcp kms encrypt: the service did not verify the plaintext checksum; the request may have been corrupted in transit")
	}
	if !checksumMatches(resp.GetCiphertext(), resp.GetCiphertextCrc32C()) {
		return nil, errors.New("gcp kms encrypt: the ciphertext checksum does not match; the response may have been corrupted in transit")
	}
	return resp.Ciphertext, nil
}

func (w *gcpWrapper) Unwrap(ctx context.Context, ciphertext []byte, binding string) ([]byte, error) {
	resp, err := w.client.Decrypt(ctx, &kmspb.DecryptRequest{
		Name:                        w.resource(),
		Ciphertext:                  ciphertext,
		CiphertextCrc32C:            crc32c(ciphertext),
		AdditionalAuthenticatedData: []byte(contextLabel + ":" + binding),
	})
	if err != nil {
		return nil, fmt.Errorf("gcp kms decrypt: %w", err)
	}
	if !checksumMatches(resp.GetPlaintext(), resp.GetPlaintextCrc32C()) {
		clear(resp.Plaintext)
		return nil, errors.New("gcp kms decrypt: the plaintext checksum does not match; the response may have been corrupted in transit")
	}
	return resp.Plaintext, nil
}
