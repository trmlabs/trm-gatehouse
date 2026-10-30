package hashicorp

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func refusals(c *Client) *[]string {
	var kinds []string
	c.SetRevokeRefusal(func(kind string) { kinds = append(kinds, kind) })
	return &kinds
}

func TestRevokeLeaseRevokesOnlyWhatTheBrokerMinted(t *testing.T) {
	srv, state := stubDatabaseVault(t, "database", []string{"readonly"}, "")
	c := newClientForServer(t, srv.URL)
	kinds := refusals(c)

	own, err := c.ReadDatabaseCredential(context.Background(), "database", "readonly")
	if err != nil {
		t.Fatal(err)
	}
	if err := c.RevokeLease(context.Background(), own.LeaseID); err != nil {
		t.Fatalf("its own lease: %v", err)
	}
	if _, _, revokes := state.snapshot(); len(revokes) != 1 || revokes[0] != own.LeaseID {
		t.Fatalf("revokes %v", revokes)
	}
	if len(*kinds) != 0 {
		t.Fatalf("a refusal for its own lease: %v", *kinds)
	}

	// Another client's lease under a shared role: refused before Vault is asked.
	err = c.RevokeLease(context.Background(), "database/creds/shared-readonly/other-clients-lease")
	if !errors.Is(err, ErrNotMinted) {
		t.Fatalf("another client's lease: %v", err)
	}
	if _, _, revokes := state.snapshot(); len(revokes) != 1 {
		t.Fatalf("the refused revoke reached Vault: %v", revokes)
	}
	if len(*kinds) != 1 || (*kinds)[0] != RevokeKindLease {
		t.Fatalf("refusals %v, want one lease refusal", *kinds)
	}
}

func TestRevokeDatabaseLeaseConfirmedRefusesWhatTheBrokerDidNotMint(t *testing.T) {
	srv, state := stubDatabaseVault(t, "database", []string{"readonly"}, "")
	c := newClientForServer(t, srv.URL)
	kinds := refusals(c)

	err := c.RevokeDatabaseLeaseConfirmed(context.Background(), "database/creds/shared-readonly/someone-elses")
	if !errors.Is(err, ErrNotMinted) || errors.Is(err, ErrLeaseRevokeRefused) {
		t.Fatalf("got %v, want ErrNotMinted and not a Vault refusal", err)
	}
	if _, _, revokes := state.snapshot(); len(revokes) != 0 {
		t.Fatalf("reached Vault: %v", revokes)
	}
	if len(*kinds) != 1 {
		t.Fatalf("refusals %v", *kinds)
	}
}

func TestAnAdoptedLeaseFromTheBrokersJournalCanBeRevoked(t *testing.T) {
	srv, state := stubDatabaseVault(t, "database", []string{"readonly"}, "")
	c := newClientForServer(t, srv.URL)
	kinds := refusals(c)
	c.AdoptLease("database/creds/shared-readonly/from-the-journal")
	if err := c.RevokeDatabaseLeaseConfirmed(context.Background(), "database/creds/shared-readonly/from-the-journal"); err != nil &&
		errors.Is(err, ErrNotMinted) {
		t.Fatalf("an adopted lease was refused: %v", err)
	}
	if _, _, revokes := state.snapshot(); len(revokes) != 1 || len(*kinds) != 0 {
		t.Fatalf("revokes %v, refusals %v", revokes, *kinds)
	}
}

func TestALeaseUnderAGatehouseOnlyRoleIsTheBrokersEvenIfItsRequestWasLost(t *testing.T) {
	srv, state := stubDatabaseVault(t, "database", []string{"readonly"}, "")
	c := newClientForServer(t, srv.URL)
	id := "database/creds/gatehouse-staging.us.crunchy.core-readonly/lost-request"
	if err := c.RevokeLease(context.Background(), id); err != nil {
		t.Fatalf("orphan under a Gatehouse-only role: %v", err)
	}
	if _, _, revokes := state.snapshot(); len(revokes) != 1 || revokes[0] != id {
		t.Fatalf("revokes %v", revokes)
	}
	// The name has to start the role: a shared role that merely contains it is not exclusive.
	if err := c.RevokeLease(context.Background(), "database/creds/staging-gatehouse-readonly/x"); !errors.Is(err, ErrNotMinted) {
		t.Fatalf("a shared role named like one: %v", err)
	}
}

func TestRevokeDatabaseSessionRevokesOnlyItsOwnAccessors(t *testing.T) {
	srv, _ := stubDatabaseVault(t, "database", []string{"readonly"}, "")
	c := newClientForServer(t, srv.URL)
	kinds := refusals(c)

	// An accessor nobody here minted, such as a Vault operator's or another service's.
	err := c.RevokeDatabaseSession(context.Background(), "unknown-accessor")
	if !errors.Is(err, ErrNotMinted) {
		t.Fatalf("an unknown accessor: %v", err)
	}
	if len(*kinds) != 1 || (*kinds)[0] != RevokeKindSession {
		t.Fatalf("refusals %v, want one session refusal", *kinds)
	}
}

func TestASessionsLeasesAreTheParentsToRevoke(t *testing.T) {
	policy := DatabaseCredentialPolicyName("database", "reader")
	srv, rec := childSessionVault(t, policy)
	c := newClientForServer(t, srv.URL)
	kinds := refusals(c)
	session, err := c.NewDatabaseSession(context.Background(), "database", "reader", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	cred, err := session.ReadCredential(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := c.RevokeLease(context.Background(), cred.LeaseID); err != nil {
		t.Fatalf("its session's lease: %v", err)
	}
	if err := c.RevokeDatabaseSession(context.Background(), session.Accessor); err != nil {
		t.Fatalf("its session's token: %v", err)
	}
	if len(*kinds) != 0 || rec.revoked.Load() != 1 {
		t.Fatalf("refusals %v, accessor revokes %d", *kinds, rec.revoked.Load())
	}
	// Once revoked, the accessor is no longer the broker's to revoke again.
	if err := c.RevokeDatabaseSession(context.Background(), session.Accessor); !errors.Is(err, ErrNotMinted) {
		t.Fatalf("a second revoke of the same accessor: %v", err)
	}
}

// Fails only under -race (as CI runs it): a revoke check raced the first mint's lazy map creation.
func TestARevokeCheckDuringTheFirstMintDoesNotRace(t *testing.T) {
	for range 50 {
		c := &Client{}
		var wg sync.WaitGroup
		wg.Go(func() {
			c.noteLease("database/creds/shared-readonly/first")
			c.noteSession("first-accessor")
		})
		wg.Go(func() {
			for range 100 {
				_ = c.allowLeaseRevoke("database/creds/shared-readonly/first")
				_ = c.allowSessionRevoke("first-accessor")
				c.forgetLease("database/creds/shared-readonly/other")
				c.forgetSession("other-accessor")
			}
		})
		wg.Wait()
	}
}
