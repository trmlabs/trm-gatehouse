package cmd

import (
	"testing"

	"github.com/Infisical/agent-vault/internal/auditchain"
	"github.com/Infisical/agent-vault/internal/hashicorp"
)

func TestRevokeRefusalRowsAreValidAuditEvents(t *testing.T) {
	for _, kind := range []string{hashicorp.RevokeKindLease, hashicorp.RevokeKindSession} {
		e := revokeRefusalEvent(kind)
		if err := e.Validate(); err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		if e.Event != auditchain.EventDenied || e.Outcome != "not_minted" || e.Operation != "revoke_"+kind {
			t.Errorf("%s: row %+v", kind, e)
		}
	}
}
