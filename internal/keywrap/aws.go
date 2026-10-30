package keywrap

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

type awsWrapper struct {
	client *kms.Client
	name   string // the full configured value
}

// awsFIPS reports whether to use the FIPS endpoint: always in us-gov regions, otherwise only when forced.
func awsFIPS(region string, force bool) bool {
	return force || strings.HasPrefix(region, "us-gov-")
}

// newAWS uses the default credential chain, so EKS service-account roles work.
func newAWS(ctx context.Context, value, region string, forceFIPS bool) (Wrapper, error) {
	opts := []func(*config.LoadOptions) error{config.WithRegion(region)}
	if awsFIPS(region, forceFIPS) {
		opts = append(opts, config.WithUseFIPSEndpoint(aws.FIPSEndpointStateEnabled))
	}
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("loading AWS configuration: %w", err)
	}
	return &awsWrapper{client: kms.NewFromConfig(cfg), name: value}, nil
}

func (w *awsWrapper) KeyName() string { return w.name }

func (w *awsWrapper) arn() string { return strings.TrimPrefix(w.name, schemeAWS) }

func (w *awsWrapper) encryptionContext(binding string) map[string]string {
	return map[string]string{"purpose": contextLabel, "vault": binding}
}

func (w *awsWrapper) Wrap(ctx context.Context, plaintext []byte, binding string) ([]byte, error) {
	out, err := w.client.Encrypt(ctx, &kms.EncryptInput{
		KeyId:             aws.String(w.arn()),
		Plaintext:         plaintext,
		EncryptionContext: w.encryptionContext(binding),
	})
	if err != nil {
		return nil, fmt.Errorf("AWS KMS encrypt: %w", err)
	}
	return out.CiphertextBlob, nil
}

func (w *awsWrapper) Unwrap(ctx context.Context, ciphertext []byte, binding string) ([]byte, error) {
	out, err := w.client.Decrypt(ctx, &kms.DecryptInput{
		KeyId:             aws.String(w.arn()),
		CiphertextBlob:    ciphertext,
		EncryptionContext: w.encryptionContext(binding),
	})
	if err != nil {
		return nil, fmt.Errorf("AWS KMS decrypt: %w", err)
	}
	return out.Plaintext, nil
}
