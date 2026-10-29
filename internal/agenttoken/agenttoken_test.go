package agenttoken

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/httpcatalog"
)

func catalogWith(t *testing.T, blocks string) httpcatalog.Catalog {
	t.Helper()
	c, err := httpcatalog.Parse([]byte(`{
	 "harnesses":[{"name":"token-agents","identity":{"kind":"static-token"},"path":{"kind":"direct"},
	   "authorization":{"mode":"automation","poolName":"automations"},"client":{"proxyEnv":"EXAMPLE_PROXY","caFileEnv":"EXAMPLE_CA_FILE"}}],
	 "pools":[{"name":"automations","namespace":"n","serviceAccount":"worker","identity":"cursor-automation"}],
	 "entries":[{"name":"open","host":"api.vendor.example","pathPrefixes":["/open/"],"methods":["GET"],"header":"Authorization","placeholder":"__vault_KEY__","key":{"mount":"gatehouse","path":"vendors/p","field":"f"},"pools":["automations"]}],
	 "automations":[` + blocks + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// soon is an expiry a block may carry: inside the longest a token may live.
func soon() time.Time { return time.Now().Add(30 * 24 * time.Hour).UTC().Truncate(time.Second) }

func block(id string, hashes ...string) string {
	return fmt.Sprintf(`{"id":%q,"name":%q,"owner":"platform-team","entries":["open"],"tokenSHA256":["%s"],"expires":%q}`, id, id, strings.Join(hashes, `","`), soon().Format(time.RFC3339))
}

func reason(err error) string { return brokercore.DenialReason(err) }

func TestMintMakesAVerifiableTokenAndNeverRepeats(t *testing.T) {
	token, hash, err := Mint("example-agent")
	if err != nil {
		t.Fatal(err)
	}
	id, ok := Split(token)
	if !ok || id != "example-agent" || !strings.HasPrefix(token, "example-agent.") {
		t.Fatalf("token %q splits to %q %v", token, id, ok)
	}
	// 256 bits is 43 base64url characters after the id and the dot.
	if secret := token[len("example-agent."):]; len(secret) != 43 {
		t.Fatalf("secret is %d characters", len(secret))
	}
	if hash != Hash(token) || len(hash) != 64 {
		t.Fatalf("hash %q", hash)
	}
	again, _, _ := Mint("example-agent")
	if again == token {
		t.Fatal("two mints made one token")
	}
	for _, bad := range []string{"", "a b", "-x", strings.Repeat("a", 129), "a/b"} {
		if _, _, err := Mint(bad); err == nil {
			t.Errorf("minted for id %q", bad)
		}
	}
	// An id with a dot still splits on the last dot, the secret's side.
	dotted, _, err := Mint("team.agent-1")
	if err != nil {
		t.Fatal(err)
	}
	if id, ok := Split(dotted); !ok || id != "team.agent-1" {
		t.Fatalf("dotted id split to %q %v", id, ok)
	}
}

func TestVerifyAdmitsOnlyTheListedToken(t *testing.T) {
	token, hash, _ := Mint("agent-1")
	other, otherHash, _ := Mint("agent-2")
	v := Static{Catalog: catalogWith(t, block("agent-1", hash)+","+block("agent-2", otherHash))}
	s, err := v.Verify(context.Background(), token)
	if err != nil || s.Automation != "agent-1" || s.Pool != "automations" || s.Expires.IsZero() {
		t.Fatalf("%+v %v", s, err)
	}
	// One agent's token is not another's, whichever id it names.
	wrongSecret := "agent-1." + other[len("agent-2."):]
	for name, tc := range map[string]struct {
		token, reason string
	}{
		"another agent's secret under this id": {wrongSecret, ReasonMismatch},
		"an unlisted agent":                    {"agent-9." + token[len("agent-1."):], ReasonUnknown},
		"no secret":                            {"agent-1", ReasonMalformed},
		"a short secret":                       {"agent-1.abc", ReasonMalformed},
		"an empty token":                       {"", ReasonMalformed},
		"a colon":                              {token + ":vault", ReasonMalformed},
		"the secret alone":                     {token[len("agent-1."):], ReasonMalformed},
		"trailing space":                       {token + " ", ReasonMalformed},
	} {
		_, err := v.Verify(context.Background(), tc.token)
		if reason(err) != tc.reason {
			t.Errorf("%s: %q (%v)", name, reason(err), err)
		}
	}
}

// A refusal names the agent id the token claimed, for the audit row, in the
// safe form the broker uses for any attacker-chosen name, and never the token.
func TestRefusalNamesTheClaimedAgentNotTheToken(t *testing.T) {
	token, hash, _ := Mint("agent-1")
	v := Static{Catalog: catalogWith(t, block("agent-1", hash))}
	_, err := v.Verify(context.Background(), "agent-1."+strings.Repeat("A", 43))
	k := brokercore.DenialKey(err)
	if k == nil || k.Kid != "agent-1" || reason(err) != ReasonMismatch {
		t.Fatalf("%+v %v", k, err)
	}
	if strings.Contains(err.Error(), token) || strings.Contains(err.Error(), strings.Repeat("A", 43)) {
		t.Fatalf("the refusal carries the secret: %v", err)
	}
	_, err = v.Verify(context.Background(), "agent-2."+strings.Repeat("A", 43))
	if k := brokercore.DenialKey(err); k == nil || k.Kid != "agent-2" || reason(err) != ReasonUnknown {
		t.Fatalf("%+v %v", k, err)
	}
}

func TestExpiry(t *testing.T) {
	token, hash, _ := Mint("agent-1")
	expires := soon()
	catalog := catalogWith(t, fmt.Sprintf(`{"id":"agent-1","name":"agent-1","owner":"platform-team","entries":["open"],"tokenSHA256":["%s"],"expires":%q}`, hash, expires.Format(time.RFC3339)))
	at := func(n time.Time) Static {
		return Static{Catalog: catalog, Now: func() time.Time { return n }}
	}
	s, err := at(expires.Add(-time.Second)).Verify(context.Background(), token)
	if err != nil || !s.Expires.Equal(expires) {
		t.Fatalf("%+v %v", s, err)
	}
	for _, now := range []time.Time{expires, expires.Add(180 * 24 * time.Hour)} {
		if _, err := at(now).Verify(context.Background(), token); reason(err) != ReasonExpired {
			t.Errorf("at %s: %v", now, err)
		}
	}
	// A wrong secret learns nothing about the expiry: it is refused as a
	// mismatch, before the clock is read.
	if _, err := at(expires.Add(180*24*time.Hour)).Verify(context.Background(), "agent-1."+strings.Repeat("A", 43)); reason(err) != ReasonMismatch {
		t.Errorf("wrong secret after expiry: %v", err)
	}
}

// A missing expiry fails closed. The catalog refuses a token block without a
// real expiry at load, so no catalog can carry one to Verify; the check is
// driven directly. The zero time is refused at any clock, never read as
// never-expires, and a real expiry still turns at its instant.
func TestZeroExpiryIsRefused(t *testing.T) {
	for _, now := range []time.Time{{}, time.Unix(0, 0), time.Now(), time.Now().Add(100 * 365 * 24 * time.Hour)} {
		if !expired(time.Time{}, now) {
			t.Errorf("the zero expiry was accepted at %s", now)
		}
	}
	exp := soon()
	if expired(exp, exp.Add(-time.Second)) {
		t.Error("a token was refused before its expiry")
	}
	if !expired(exp, exp) {
		t.Error("a token was accepted at its expiry")
	}
}

// Two hashes let a token rotate: both are admitted until the old one is
// removed from the block, which refuses it at the next catalog reload.
func TestRotationOverlapAndRevocation(t *testing.T) {
	oldToken, oldHash, _ := Mint("agent-1")
	newToken, newHash, _ := Mint("agent-1")
	v := Static{Catalog: catalogWith(t, block("agent-1", oldHash, newHash))}
	for _, tok := range []string{oldToken, newToken} {
		if _, err := v.Verify(context.Background(), tok); err != nil {
			t.Errorf("overlap refused a token: %v", err)
		}
	}
	v = Static{Catalog: catalogWith(t, block("agent-1", newHash))}
	if _, err := v.Verify(context.Background(), oldToken); reason(err) != ReasonMismatch {
		t.Errorf("the old token after rotation: %v", err)
	}
	if _, err := v.Verify(context.Background(), newToken); err != nil {
		t.Errorf("the new token after rotation: %v", err)
	}
	// Deleting the block is revocation.
	v = Static{Catalog: catalogWith(t, block("agent-2", newHash))}
	if _, err := v.Verify(context.Background(), newToken); reason(err) != ReasonUnknown {
		t.Errorf("after the block is removed: %v", err)
	}
}

// A block with no token hash is a Cursor Automation: no token, whatever it
// claims, reaches it.
func TestAnAutomationWithNoTokenIsNotReachable(t *testing.T) {
	token, hash, _ := Mint("agent-1")
	cursorOnly := `{"id":"cursor-auto","name":"cursor-auto","owner":"platform-team","entries":["open"]}`
	v := Static{Catalog: catalogWith(t, block("agent-1", hash)+","+cursorOnly)}
	if _, err := v.Verify(context.Background(), "cursor-auto."+token[len("agent-1."):]); reason(err) != ReasonUnknown {
		t.Errorf("%v", err)
	}
}

func TestClaimedAgent(t *testing.T) {
	secret := strings.Repeat("A", 43)
	for tok, want := range map[string]string{
		"agent-1." + secret: "agent-1",
		"a.b." + secret:     "a.b",
		"agent-1.short":     "",
		"":                  "",
		".":                 "",
		"." + secret:        "",
		"bad id." + secret:  "",
	} {
		if got := ClaimedAgent(tok); got != want {
			t.Errorf("%q: %q", tok, got)
		}
	}
}
