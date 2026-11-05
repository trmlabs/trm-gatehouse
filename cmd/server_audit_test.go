package cmd

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/auditchain"
	"github.com/Infisical/agent-vault/internal/store"
	"github.com/Infisical/agent-vault/internal/store/storetest"
)

type breakableOutput struct {
	bytes.Buffer
	broken bool
}

func (o *breakableOutput) Write(p []byte) (int, error) {
	if o.broken {
		return 0, errors.New("output closed")
	}
	return o.Buffer.Write(p)
}

func TestAuditHealthFollowsTheTrail(t *testing.T) {
	old := auditChainNow.Swap(nil)
	t.Cleanup(func() { auditChainNow.Store(old) })
	readiness, liveness := map[string]func() bool{}, map[string]func() bool{}
	attach := func(checks map[string]func() bool) func(string, func() bool) {
		return func(name string, check func() bool) { checks[name] = check }
	}
	// Attached before any chain exists, as at startup.
	auditHealth(attach(readiness), attach(liveness))
	ready, live := readiness["audit-trail"], liveness["audit-trail"]
	if ready == nil || live == nil || !ready() || !live() {
		t.Fatal("no audit trail must leave the copy ready and live")
	}

	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "audit.db")
	storetest.Seed(t, path)
	db, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Unix(1_800_000_000, 0)
	out := &breakableOutput{}
	chain, err := auditchain.New(context.Background(), auditchain.Options{Out: out, Replica: "broker-0",
		Keys: cmdTestKeys{bytes.Repeat([]byte{0x5a}, 32)}, Signer: cmdTestSigner{private}, Boots: db,
		Grace: time.Minute, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if err := chain.Checkpoint(context.Background()); err != nil {
		t.Fatal(err)
	}
	auditChainNow.Store(chain)
	if !ready() || !live() {
		t.Fatal("not ready and live with a fresh checkpoint")
	}
	now = now.Add(2 * time.Minute)
	if chain.Admit() == nil || !ready() || !live() {
		t.Fatal("an overdue checkpoint must refuse sessions and keep the copy ready and live")
	}
	out.broken = true
	if err := chain.Record(auditchain.Event{Event: auditchain.EventSessionOpen, Outcome: "admitted"}); err == nil {
		t.Fatal("recorded to a broken output")
	}
	if ready() || live() {
		t.Fatal("a stopped trail should leave the Service and restart")
	}
}
