package ca

import (
	"testing"
)

// TestValidateSNI_HostDockerInternal locks in that MintLeaf accepts SNI=host.docker.internal, which container isolation needs.
func TestValidateSNI_HostDockerInternal(t *testing.T) {
	isIP, err := validateSNI("host.docker.internal")
	if err != nil {
		t.Fatalf("validateSNI(host.docker.internal) = err %v, want nil", err)
	}
	if isIP {
		t.Error("host.docker.internal should validate as a DNS name, not an IP")
	}
}
