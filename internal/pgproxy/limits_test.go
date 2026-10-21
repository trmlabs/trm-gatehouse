package pgproxy

import (
	"sync/atomic"
	"testing"
)

// With pooling, client sessions hold no database connection of their own, so
// their caps default to fleet scale; unpooled, each session is a database
// connection, and each database's ceiling comes from its catalog maxConns.
func TestSessionCapDefaultsFollowPooling(t *testing.T) {
	pooled := New("127.0.0.1:0", Options{Pool: &PoolOptions{}})
	if o := pooled.opts; o.MaxConns != 10000 || o.MaxPendingConns != 10000 || o.MaxLeasesPerActor != 1024 || o.MaxLeasesPerAgent != 10000-1024 {
		t.Fatalf("pooled defaults %d %d %d %d", o.MaxConns, o.MaxPendingConns, o.MaxLeasesPerActor, o.MaxLeasesPerAgent)
	}
	if q := (&PoolOptions{}).withDefaults().QueueFactor; q != 200 {
		t.Fatalf("queue factor %d", q)
	}
	if b := (&PoolOptions{}).withDefaults().DefaultBudget; b != 50 {
		t.Fatalf("pool fallback budget %d", b)
	}
	unpooled := New("127.0.0.1:0", Options{})
	if o := unpooled.opts; o.MaxConns != 10000 || o.MaxPendingConns != 10000 || o.MaxLeasesPerActor != 16 || o.DefaultDatabaseConns != 50 {
		t.Fatalf("unpooled defaults %d %d %d %d", o.MaxConns, o.MaxPendingConns, o.MaxLeasesPerActor, o.DefaultDatabaseConns)
	}
	// Explicit settings still win, at any size.
	set := New("127.0.0.1:0", Options{Pool: &PoolOptions{}, MaxConns: 50000, MaxPendingConns: 70000, MaxLeasesPerActor: 4000})
	if o := set.opts; o.MaxConns != 50000 || o.MaxPendingConns != 70000 || o.MaxLeasesPerActor != 4000 {
		t.Fatalf("explicit settings %d %d %d", o.MaxConns, o.MaxPendingConns, o.MaxLeasesPerActor)
	}
}

// Unpooled, a database's ceiling is its catalog maxConns, at any size; only a
// database without one falls back to the default.
func TestUnpooledDatabaseCeilingComesFromTheCatalog(t *testing.T) {
	b := New("127.0.0.1:0", Options{})
	sized := &DatabaseService{Addr: "big.example:5432", MaxConns: 2000}
	unsized := &DatabaseService{Addr: "small.example:5432"}
	for i := 0; i < 2000; i++ {
		if !b.acquireUpstreamSlot(sized, 1) {
			t.Fatalf("refused at %d of 2000", i)
		}
	}
	if b.acquireUpstreamSlot(sized, 1) {
		t.Fatal("past the catalog's maxConns")
	}
	for i := 0; i < 50; i++ {
		if !b.acquireUpstreamSlot(unsized, 1) {
			t.Fatalf("refused at %d of 50", i)
		}
	}
	if b.acquireUpstreamSlot(unsized, 1) {
		t.Fatal("past the fallback for a database without maxConns")
	}
	set := New("127.0.0.1:0", Options{DefaultDatabaseConns: 300})
	for i := 0; i < 300; i++ {
		if !set.acquireUpstreamSlot(unsized, 1) {
			t.Fatalf("refused at %d of an overridden 300", i)
		}
	}
}

// An operator who set MaxConns keeps it as the ceiling for databases without
// maxConns; the pooled budget fallback is separate.
func TestExplicitMaxConnsIsTheUnsizedFallback(t *testing.T) {
	if o := New("127.0.0.1:0", Options{MaxConns: 128}).opts; o.DefaultDatabaseConns != 128 {
		t.Fatalf("unpooled fallback %d, want 128", o.DefaultDatabaseConns)
	}
	if o := New("127.0.0.1:0", Options{MaxConns: 128, DefaultDatabaseConns: 20}).opts; o.DefaultDatabaseConns != 20 {
		t.Fatalf("explicit fallback %d, want 20", o.DefaultDatabaseConns)
	}
	if o := New("127.0.0.1:0", Options{Pool: &PoolOptions{}, MaxConns: 128}).opts; o.DefaultDatabaseConns != 50 {
		t.Fatalf("pooled fallback %d, want 50", o.DefaultDatabaseConns)
	}
}

// fleetMinter is a fakeMinter on a replica that sees live peers, as the
// durable cleanup journal reports them.
type fleetMinter struct {
	*fakeMinter
	live atomic.Int64
}

func (f *fleetMinter) LiveReplicas() int { return int(f.live.Load()) }

func newFleetMinter(lease *Lease, live int) *fleetMinter {
	m := &fleetMinter{fakeMinter: &fakeMinter{lease: lease}}
	m.live.Store(int64(live))
	return m
}

// In session mode a database's budget is the whole fleet's: each replica
// takes it divided by the live replica count, rounded down, so the shares
// never add up to more than the budget. With more replicas than the budget
// every share is 0.
func TestSessionDatabaseShareDividesTheBudget(t *testing.T) {
	b := New("127.0.0.1:0", Options{})
	for _, c := range []struct{ budget, replicas, want int }{
		{16, 1, 16}, {16, 2, 8}, {16, 5, 3}, {16, 12, 1}, {16, 16, 1},
		{16, 17, 0}, {16, 120, 0}, {1, 2, 0}, {16, 0, 16},
	} {
		if got := b.databaseLimit(&DatabaseService{MaxConns: c.budget}, c.replicas); got != c.want {
			t.Errorf("budget %d over %d replicas: share %d, want %d", c.budget, c.replicas, got, c.want)
		}
	}
	for budget := 1; budget <= 64; budget++ {
		for replicas := 1; replicas <= 130; replicas++ {
			if share := b.databaseLimit(&DatabaseService{MaxConns: budget}, replicas); share*replicas > budget {
				t.Fatalf("%d replicas x share %d exceeds budget %d", replicas, share, budget)
			}
		}
	}
	// The default for an entry without maxConns divides too, and MaxConns
	// still caps one replica.
	if got := b.databaseLimit(&DatabaseService{}, 4); got != 12 {
		t.Fatalf("default budget 50 over 4 replicas: %d, want 12", got)
	}
	if got := New("127.0.0.1:0", Options{MaxConns: 5}).databaseLimit(&DatabaseService{MaxConns: 40}, 2); got != 5 {
		t.Fatalf("MaxConns cap: %d, want 5", got)
	}
}

// The replica count comes from the lease minter's live owner rows; a minter
// without them, or one reporting none, is a fleet of one.
func TestSessionReplicaCountComesFromTheMinter(t *testing.T) {
	if n := New("127.0.0.1:0", Options{Leases: &fakeMinter{}}).liveReplicas(); n != 1 {
		t.Fatalf("no live count: %d replicas, want 1", n)
	}
	if n := New("127.0.0.1:0", Options{Leases: newFleetMinter(nil, 0)}).liveReplicas(); n != 1 {
		t.Fatalf("zero live count: %d replicas, want 1", n)
	}
	if n := New("127.0.0.1:0", Options{Leases: newFleetMinter(nil, 3)}).liveReplicas(); n != 3 {
		t.Fatalf("live count 3: %d replicas", n)
	}
}

// When replicas join, sessions already open stay open, and new ones wait
// until occupancy falls below the smaller share; when replicas leave, the
// larger share admits at once.
func TestSessionShareFollowsReplicaChangesMidSession(t *testing.T) {
	m := newFleetMinter(nil, 1)
	b := New("127.0.0.1:0", Options{Leases: m})
	svc := &DatabaseService{Addr: "db.example:5432", MaxConns: 4}
	acquire := func() bool { return b.acquireUpstreamSlot(svc, b.liveReplicas()) }
	for i := range 4 {
		if !acquire() {
			t.Fatalf("one replica refused at %d of 4", i)
		}
	}
	if acquire() {
		t.Fatal("one replica past the budget")
	}
	m.live.Store(2) // share 2, with 4 open
	b.releaseUpstreamSlot(svc)
	b.releaseUpstreamSlot(svc)
	if acquire() {
		t.Fatal("admitted at the new share of 2 with 2 open")
	}
	b.releaseUpstreamSlot(svc)
	if !acquire() {
		t.Fatal("refused below the new share")
	}
	m.live.Store(5) // share 0: refused while any number are open
	b.releaseUpstreamSlot(svc)
	b.releaseUpstreamSlot(svc)
	if acquire() {
		t.Fatal("admitted with more replicas than the budget")
	}
	m.live.Store(1)
	for i := range 4 {
		if !acquire() {
			t.Fatalf("refused at %d after replicas left", i)
		}
	}
	if acquire() {
		t.Fatal("past the budget after replicas left")
	}
}

// Two brokers that see each other share one database's budget: together
// they open no more upstream connections than its maxConns.
func TestSessionBudgetHoldsAcrossTwoBrokers(t *testing.T) {
	lease := newLease()
	upstream := startFakeUpstream(t, authTrust, lease.Password)
	svc := &DatabaseService{Name: "analytics", Addr: upstream.addr(), Mount: "database", Role: "readonly", SSLMode: "disable", MaxConns: 4}
	var addrs []string
	for range 2 {
		_, addr := startBroker(t, Options{
			Auth:      &fakeAuth{scope: &AgentScope{VaultID: "vault-1", ActorID: "agent-7"}},
			Databases: &fakeResolver{svc: svc},
			Leases:    newFleetMinter(lease, 2),
		})
		addrs = append(addrs, addr)
	}
	for _, addr := range addrs {
		for range 2 {
			s := openAgentSession(t, addr, "agent-vault-token", "appdb")
			t.Cleanup(s.close)
		}
		if code := connectExpectCode(t, addr, "agent-vault-token", "appdb"); code != "53300" {
			t.Fatalf("third session on one replica: %q, want 53300", code)
		}
	}
	upstream.mu.Lock()
	accepted := upstream.accepted
	upstream.mu.Unlock()
	if accepted != 4 {
		t.Fatalf("two replicas opened %d upstream connections, budget 4", accepted)
	}
}
