package keywrap

import (
	"context"
	"strings"
	"testing"
)

func TestValidateGCPKey(t *testing.T) {
	good := "projects/my-project-1/locations/europe-west1/keyRings/r/cryptoKeys/k"
	for _, ok := range []string{good, "projects/123456789012/locations/global/keyRings/ring_1/cryptoKeys/key-2"} {
		if err := validateGCPKey(ok); err != nil {
			t.Fatalf("valid key %q rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"",
		good + "/cryptoKeyVersions/1",
		"projects/my-project-1/locations/l/keyRings/r",
		"projects//locations/l/keyRings/r/cryptoKeys/k",
		"projects/my-project-1/locations/l/keyrings/r/cryptoKeys/k",
		"projects/p/locations/l/keyRings/r/cryptoKeys/k",
		good + "?x=1",
		good + "#frag",
		good + "/",
		"projects/my-project-1@evil/locations/l/keyRings/r/cryptoKeys/k",
		"projects/my-project-1/locations/l.attacker.example/keyRings/r/cryptoKeys/k",
		"projects/my-project-1/locations/l/keyRings/r/cryptoKeys/k\n",
	} {
		if err := validateGCPKey(bad); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
}

func TestAWSKeyRegion(t *testing.T) {
	const uuid = "1234abcd-12ab-34cd-56ef-1234567890ab"
	for arn, region := range map[string]string{
		"arn:aws-us-gov:kms:us-gov-west-1:123456789012:key/" + uuid:                   "us-gov-west-1",
		"arn:aws-us-gov:kms:us-gov-east-1:123456789012:key/" + uuid:                   "us-gov-east-1",
		"arn:aws:kms:ap-southeast-2:123456789012:key/" + uuid:                         "ap-southeast-2",
		"arn:aws:kms:us-east-1:123456789012:key/mrk-1234abcd12ab34cd56ef1234567890ab": "us-east-1",
	} {
		got, err := awsKeyRegion(arn)
		if err != nil || got != region {
			t.Errorf("%s: got %q, %v", arn, got, err)
		}
	}
	for _, bad := range []string{
		"",
		uuid,
		"arn:aws:s3:::bucket",
		"arn:aws:kms:us-east-1:123456789012:key/",
		"arn:aws:kms:us-east-1:123456789012:key/not-a-uuid",
		"arn:aws:kms:us-east-1:123456789012:grant/abc",
		"arn:aws:kms::123456789012:key/" + uuid,
		"arn:aws:kms:attacker.example/x?:1:key/a",
		"arn:aws:kms:us-gov-west-1.attacker.example:123456789012:key/" + uuid,
		"arn:aws-us-gov:kms:us-gov-west-1.attacker.example:123456789012:key/" + uuid,
		"arn:aws:kms:us-gov-west-1:123456789012:key/" + uuid,
		"arn:aws-us-gov:kms:us-east-1:123456789012:key/" + uuid,
		"arn:aws-cn:kms:cn-north-1:123456789012:key/" + uuid,
		"arn:evil:kms:us-east-1:123456789012:key/" + uuid,
		"arn:aws:kms:us-east-1:12345678901:key/" + uuid,
		"arn:aws:kms:us-east-1:1234567890123:key/" + uuid,
		"arn:aws:kms:us-east-1:12345678901a:key/" + uuid,
		"arn:aws:kms:us-east-1:123456789012:key/" + uuid + "?x=1",
		"arn:aws:kms:us-east-1:123456789012:key/" + uuid + "#f",
		"arn:aws:kms:us-east-1:123456789012:key/" + uuid + "/extra",
		"arn:aws:kms:us-east-1:123456789012:key/" + uuid + "@host",
		"arn:aws:kms:us-east-1:123456789012:alias/a/b",
		"arn:aws:kms:us-east-1:123456789012:alias/",
		"arn:aws:kms:eu-west-2:123456789012:alias/agent-vault",
		"arn:aws-us-gov:kms:us-gov-east-1:123456789012:alias/agent-vault",
		"arn:aws-us-gov:kms:us-gov-west-1:123456789012:alias/aws/kms",
		"arn:aws:kms:us-east-1:123456789012:key/" + uuid + ":x",
		"arn:aws:kms:us-east-1:123456789012:key/" + uuid + "\n",
		"arn:aws:kms:US-EAST-1:123456789012:key/" + uuid,
	} {
		if _, err := awsKeyRegion(bad); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
}

func TestAWSAliasIsRefusedWithAClearError(t *testing.T) {
	for _, alias := range []string{
		"awskms://arn:aws-us-gov:kms:us-gov-west-1:123456789012:alias/agent-vault",
		"awskms://arn:aws:kms:us-east-1:123456789012:alias/agent-vault",
	} {
		_, err := New(context.Background(), alias, false)
		if err == nil || !strings.Contains(err.Error(), "not an alias") || !strings.Contains(err.Error(), EnvKMS) {
			t.Errorf("%s: want an alias refusal naming %s, got %v", alias, EnvKMS, err)
		}
	}
}

func TestAWSFIPSEndpointChoice(t *testing.T) {
	for _, tc := range []struct {
		region string
		force  bool
		want   bool
	}{
		{"us-gov-west-1", false, true},
		{"us-gov-east-1", false, true},
		{"us-east-1", false, false},
		{"eu-west-2", false, false},
		{"us-east-1", true, true},
	} {
		if got := awsFIPS(tc.region, tc.force); got != tc.want {
			t.Errorf("awsFIPS(%q, %v) = %v, want %v", tc.region, tc.force, got, tc.want)
		}
	}
}

func TestNewAWSAppliesTheFIPSEndpoint(t *testing.T) {
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	for _, tc := range []struct {
		arn   string
		force bool
		want  bool
	}{
		{"arn:aws-us-gov:kms:us-gov-west-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab", false, true},
		{"arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab", false, false},
		{"arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab", true, true},
	} {
		w, err := New(context.Background(), schemeAWS+tc.arn, tc.force)
		if err != nil {
			t.Fatal(err)
		}
		aw := w.(*awsWrapper)
		if got := aw.client.Options().EndpointOptions.UseFIPSEndpoint == 1; got != tc.want {
			t.Errorf("%s force=%v: FIPS endpoint = %v, want %v", tc.arn, tc.force, got, tc.want)
		}
		if aw.KeyName() != schemeAWS+tc.arn {
			t.Errorf("KeyName = %q", aw.KeyName())
		}
	}
}

func TestNewRejectsUnknownSchemesAndMalformedKeys(t *testing.T) {
	for _, bad := range []string{"", "vault://x", "gcpkms://projects/my-project-1", "awskms://not-an-arn",
		"awskms://arn:aws:kms:attacker.example/x?:1:key/a",
		"awskms://arn:aws-us-gov:kms:us-gov-west-1.attacker.example:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab"} {
		if _, err := New(context.Background(), bad, false); err == nil {
			t.Errorf("%q should be rejected", bad)
		} else if !strings.Contains(err.Error(), EnvKMS) {
			t.Errorf("%q: error should name %s: %v", bad, EnvKMS, err)
		}
	}
}
