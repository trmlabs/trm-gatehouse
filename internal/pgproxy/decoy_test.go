package pgproxy

import (
	"strings"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/auditchain"
	"github.com/Infisical/agent-vault/internal/decoy"
)

// A synthetic decoy database password; never a real credential.
const decoyPassword = "synthetic-decoy-db-password-3a7f0c"

// A decoy sent as the password is refused before it reaches the
// authenticator or a credential is minted, with the row naming the decoy and
// the database asked for. The client sees an ordinary authentication failure,
// and an agent token still gets through.
func TestBrokerRefusesADecoyPassword(t *testing.T) {
	lease := newLease()
	upstream := startFakeUpstream(t, authTrust, lease.Password)
	audit := &recordingAudit{}
	auth := &fakeAuth{scope: &AgentScope{VaultID: "vault-1", ActorID: "agent-uuid-1", Pool: "pool-agent", WorkloadID: "pod-uid-1"}}
	minter := &fakeMinter{lease: lease}
	set, rejected := decoy.NewSet(map[string]string{"pool-a/database_password": decoyPassword})
	if len(rejected) > 0 {
		t.Fatal(rejected)
	}
	_, addr := startBroker(t, Options{
		Auth:      auth,
		Databases: &fakeResolver{svc: &DatabaseService{Name: "analytics", Addr: upstream.addr(), Mount: "database", Role: "readonly"}},
		Leases:    minter,
		Audit:     audit,
		Decoys:    decoy.NewSource(set),
	})
	if _, err := runAgentQuery(t, addr, decoyPassword, "appdb", "SELECT 1"); err == nil || !strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("decoy admitted: %v", err)
	}
	auth.mu.Lock()
	reached := auth.gotToken
	auth.mu.Unlock()
	if reached != "" || minter.mintCallCount() != 0 {
		t.Fatalf("decoy reached the authenticator (%v) or minted %d", reached != "", minter.mintCallCount())
	}
	got := audit.recorded()
	if len(got) != 1 || got[0].Event != auditchain.EventDenied || got[0].Outcome != "decoy_credential" || got[0].Binding != "decoy/pool-a/database_password" ||
		got[0].Decision != decoy.SurfacePassword || got[0].Database != "appdb" || got[0].Pool != "" {
		t.Fatalf("decoy row: %+v", got)
	}
	if _, err := runAgentQuery(t, addr, "agent-vault-token-xyz", "appdb", "SELECT 1"); err != nil {
		t.Fatalf("agent token refused: %v", err)
	}
	waitFor(t, 2*time.Second, func() bool { return len(audit.recorded()) == 3 }, "session rows")
}
