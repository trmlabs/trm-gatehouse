package pgproxy

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Infisical/agent-vault/internal/hashicorp"
	"github.com/Infisical/agent-vault/internal/store"
)

// CleanupJournal is the store's per-replica cleanup journal. Owner expiry is
// written and compared by the database clock inside these methods.
type CleanupJournal interface {
	CheckDatabaseCleanupOwner(context.Context, string) error
	ClaimDatabaseCleanupOwner(context.Context, string, time.Duration) error
	RenewDatabaseCleanupOwner(context.Context, string, time.Duration) error
	ReleaseDatabaseCleanupOwner(context.Context, string) error
	ClaimOrphanedDatabaseCleanup(context.Context, string) (int, error)
	LiveDatabaseCleanupOwners(context.Context) (int, error)
	AddDatabaseCleanup(context.Context, string, store.DatabaseCleanup) error
	SetDatabaseCleanupLease(context.Context, string, string, string) error
	MarkDatabaseCleanupTokenRevoked(context.Context, string, string) error
	AdoptDatabaseCleanup(context.Context, string, string, string, string, time.Duration) error
	SettledDatabaseCleanup(context.Context, string, time.Duration) ([]store.DatabaseCleanup, error)
	QuarantineDatabaseCleanup(context.Context, string, string) error
	ReleaseDatabaseCleanupQuarantine(context.Context, string, string) error
	DatabaseBindingQuarantined(context.Context, string) (bool, error)
	ListDatabaseCleanup(context.Context) ([]store.DatabaseCleanup, error)
	ListOwnedDatabaseCleanup(context.Context, string) ([]store.DatabaseCleanup, error)
	DeleteDatabaseCleanup(context.Context, string) error
	ConfirmDatabaseCleanup(context.Context, string, string, string) error
}

type DurableLeaseOptions struct {
	TokenTTL      time.Duration
	RetryInterval time.Duration
	// OwnerTTL is the takeover delay: survivors may claim this replica's
	// records once this long has passed, by the database clock, since its last
	// renewal. Default 30s.
	OwnerTTL time.Duration
	// FenceAfter stops this replica when no renewal has succeeded for this long
	// since the renewal was sent. It is shorter than OwnerTTL, so sessions are
	// closed before any survivor can claim. Default two thirds of OwnerTTL.
	FenceAfter time.Duration
	// Heartbeat is the renewal interval. Default one sixth of OwnerTTL.
	Heartbeat time.Duration
	// Replica names the broker in owner IDs, for operators. Each process adds a
	// random suffix, so a restarted Pod never inherits its predecessor's records.
	Replica string
	// Logger names a refused start or a duplicate-name fence. Default discard.
	Logger *slog.Logger
	// IssueTimeout bounds one issuance from child token to journaled lease.
	// Neither its caller leaving nor a graceful Close cuts it short, only this
	// bound or a fence: abandoned between the credential read and the lease
	// write, it would leave an unknown issuance. Default 15s, the handshake's.
	IssueTimeout time.Duration
	// UnknownSettle is how long an unknown issuance's child token must have
	// been dead, by the database clock, before Vault's lease list is read to
	// clear it. It must exceed Vault's max_request_duration (90s by default)
	// plus clock skew, so no request made with the token can still register a
	// lease. Default 3 minutes.
	UnknownSettle time.Duration
	// UnknownRecheck spaces automatic checks of one unknown issuance that
	// could not be cleared. Default 30s.
	UnknownRecheck time.Duration
	// SharedRoleMaxTTL closes a shared role's unknown issuance once its token has
	// been dead this long (at least the role's max_ttl). Default 768h, Vault's system max.
	SharedRoleMaxTTL time.Duration
	// SharedWarnEvery spaces the warning for one open shared-role record. Default 1h.
	SharedWarnEvery time.Duration
}

type durableLease struct {
	accessor string
	expires  time.Time
	session  *hashicorp.DatabaseSession // revokes itself while this process holds it
}

// DurableLeaseMinter journals a child-token accessor before credential issuance.
// Known leases are reconciled automatically. An interrupted response without a
// lease ID stays recorded, without closing its binding, until Vault's lease
// list proves no credential from it remains (checkUnknowns). Only an orphan
// lease Vault refuses to revoke on two checks in a row closes the binding,
// fleet-wide.
// Each replica owns the records it wrote; a survivor claims a dead replica's
// records and revokes them. A replica that cannot renew fences itself before
// its records become claimable.
type DurableLeaseMinter struct {
	client   *hashicorp.Client
	journal  CleanupJournal
	opts     DurableLeaseOptions
	owner    string
	ctx      context.Context
	cancel   context.CancelFunc
	done     chan struct{}
	mu       sync.Mutex
	activeMu sync.Mutex
	active   map[string]durableLease
	closed   bool
	closeErr error

	releaseOnce sync.Once
	releaseErr  error

	renewMu   sync.Mutex
	lastRenew time.Time // send time of the last successful renewal
	fenced    atomic.Bool
	live      atomic.Int64
	kick      chan struct{}

	draining atomic.Bool // shutdown has begun: no new issuance starts

	checkMu sync.Mutex           // one pass of unknown-issuance checks at a time
	checked map[string]time.Time // last check per unknown issuance; under checkMu
	refused map[string]int       // checks in a row whose orphan revoke Vault refused; under checkMu
	warned  map[string]time.Time // last shared-role warning per unknown issuance; under checkMu
}

func NewDurableLeaseMinter(ctx context.Context, client *hashicorp.Client, journal CleanupJournal, opts DurableLeaseOptions) (*DurableLeaseMinter, error) {
	if client == nil || journal == nil {
		return nil, fmt.Errorf("database cleanup requires Vault and durable storage")
	}
	if opts.TokenTTL <= 0 {
		opts.TokenTTL = time.Hour
	}
	if opts.RetryInterval <= 0 {
		opts.RetryInterval = time.Second
	}
	if opts.OwnerTTL <= 0 {
		opts.OwnerTTL = 30 * time.Second
	}
	if opts.FenceAfter <= 0 {
		opts.FenceAfter = opts.OwnerTTL * 2 / 3
	}
	if opts.Heartbeat <= 0 {
		opts.Heartbeat = opts.OwnerTTL / 6
	}
	if opts.IssueTimeout <= 0 {
		opts.IssueTimeout = defaultHandshakeTimeout
	}
	if opts.UnknownSettle <= 0 {
		opts.UnknownSettle = 3 * time.Minute
	}
	if opts.SharedRoleMaxTTL <= 0 {
		opts.SharedRoleMaxTTL = 768 * time.Hour
	}
	if opts.SharedWarnEvery <= 0 {
		opts.SharedWarnEvery = time.Hour
	}
	if opts.UnknownRecheck <= 0 {
		opts.UnknownRecheck = 30 * time.Second
	}
	if opts.OwnerTTL < 3*time.Second || opts.TokenTTL < time.Second || opts.TokenTTL > 24*time.Hour ||
		opts.Heartbeat >= opts.FenceAfter || opts.FenceAfter >= opts.OwnerTTL {
		return nil, fmt.Errorf("invalid database lifecycle timing")
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, err
	}
	owner := fmt.Sprintf("%x", random)
	if opts.Replica != "" {
		owner = opts.Replica + "/" + owner
	}
	m := &DurableLeaseMinter{client: client, journal: journal, opts: opts, owner: owner, done: make(chan struct{}), active: make(map[string]durableLease), kick: make(chan struct{}, 1), checked: make(map[string]time.Time), refused: make(map[string]int), warned: make(map[string]time.Time)}
	m.ctx, m.cancel = context.WithCancel(ctx)
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
		m.opts.Logger = opts.Logger
	}
	sent, err := claimOwner(ctx, journal, m.owner, opts)
	if err != nil {
		m.cancel()
		return nil, err
	}
	m.lastRenew = sent
	m.live.Store(1)
	if n, err := journal.LiveDatabaseCleanupOwners(ctx); err == nil && n > 0 {
		m.live.Store(int64(n))
	}
	// A restart takes over expired predecessors at once rather than a heartbeat later.
	if claimed, err := journal.ClaimOrphanedDatabaseCleanup(ctx, m.owner); err == nil && claimed > 0 {
		m.kick <- struct{}{}
	}
	go m.run()
	return m, nil
}

// claimOwner registers this process. Another process under the same replica
// name may be a crashed predecessor whose row has not expired yet, so the
// claim is retried until a row that stopped renewing would have expired; a
// name still held after that belongs to a live process, and this one refuses
// to start.
func claimOwner(ctx context.Context, journal CleanupJournal, owner string, opts DurableLeaseOptions) (time.Time, error) {
	deadline := time.Now().Add(opts.OwnerTTL + opts.Heartbeat)
	for {
		sent := time.Now()
		err := journal.ClaimDatabaseCleanupOwner(ctx, owner, opts.OwnerTTL)
		if !errors.Is(err, store.ErrReplicaNameInUse) {
			return sent, err
		}
		if time.Now().After(deadline) {
			opts.Logger.Error("pgproxy: replica name held by another live broker; refusing to start", slog.String("replica", opts.Replica))
			return time.Time{}, fmt.Errorf("%w: replica %q (each broker needs its own AGENT_VAULT_REPLICA)", store.ErrReplicaNameInUse, opts.Replica)
		}
		select {
		case <-ctx.Done():
			return time.Time{}, ctx.Err()
		case <-time.After(opts.Heartbeat):
		}
	}
}

// AuthorityDone closes when this replica fences itself or closes. The broker
// then stops accepting and closes every session.
func (m *DurableLeaseMinter) AuthorityDone() <-chan struct{} { return m.ctx.Done() }

// Owner is this process's owner ID in the journal, for session rows.
func (m *DurableLeaseMinter) Owner() string { return m.owner }

// Fenced reports that this replica lost or could not renew its owner row.
func (m *DurableLeaseMinter) Fenced() bool { return m.fenced.Load() }

// Ready reports a fresh owner row: claimed at start or renewed within half the
// fence deadline. A restarted process is ready only once it holds its own new
// row, and a replica whose renewals are failing stops taking new sessions
// before it fences.
func (m *DurableLeaseMinter) Ready() bool {
	return !m.fenced.Load() && !m.draining.Load() && m.ctx.Err() == nil && m.untilFence(time.Now()) > m.opts.FenceAfter/2
}

// LiveReplicas is the number of live owner rows at the last heartbeat,
// including this replica.
func (m *DurableLeaseMinter) LiveReplicas() int { return int(max(1, m.live.Load())) }

// untilFence is the time left before this replica must stop. It counts both
// monotonic and wall time since the last renewal was sent: the monotonic clock
// can stop while a host is suspended, and the larger reading wins.
func (m *DurableLeaseMinter) untilFence(now time.Time) time.Duration {
	m.renewMu.Lock()
	last := m.lastRenew
	m.renewMu.Unlock()
	elapsed := max(now.Sub(last), now.Round(0).Sub(last.Round(0)))
	return m.opts.FenceAfter - elapsed
}

func (m *DurableLeaseMinter) fence() {
	m.fenced.Store(true)
	m.cancel()
}

// heartbeat renews the owner row, then claims orphaned records. It returns
// false when this replica must fence: ownership is lost, or the fence deadline
// passed. A failed renewal is retried on the next tick until the deadline.
func (m *DurableLeaseMinter) heartbeat() bool {
	sent := time.Now()
	remaining := m.untilFence(sent)
	if remaining <= 0 {
		return false
	}
	ctx, cancel := context.WithTimeout(m.ctx, min(m.opts.Heartbeat, remaining))
	defer cancel()
	err := m.journal.RenewDatabaseCleanupOwner(ctx, m.owner, m.opts.OwnerTTL)
	if errors.Is(err, store.ErrReplicaNameInUse) {
		m.opts.Logger.Error("pgproxy: replica name held by another live broker; fencing", slog.String("replica", m.opts.Replica))
		return false
	}
	if errors.Is(err, store.ErrDatabaseCleanupOwnershipLost) {
		return false
	}
	if err != nil {
		return m.untilFence(time.Now()) > 0
	}
	m.renewMu.Lock()
	m.lastRenew = sent
	m.renewMu.Unlock()
	if n, err := m.journal.LiveDatabaseCleanupOwners(ctx); err == nil && n > 0 {
		m.live.Store(int64(n))
	}
	if claimed, err := m.journal.ClaimOrphanedDatabaseCleanup(ctx, m.owner); err == nil && claimed > 0 {
		select {
		case m.kick <- struct{}{}:
		default:
		}
	}
	return true
}

func (m *DurableLeaseMinter) lock(ctx context.Context) error {
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if m.mu.TryLock() {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// ConfirmDatabaseCleanup serializes operator attestation with issuance and
// reconciliation. A response that arrived while the operator was investigating
// must remain a known lease, never an acknowledged unknown issuance.
func (m *DurableLeaseMinter) ConfirmDatabaseCleanup(ctx context.Context, accessor, evidence string) error {
	if err := m.lock(ctx); err != nil {
		return err
	}
	defer m.mu.Unlock()
	if m.ctx.Err() != nil || m.closed || m.untilFence(time.Now()) <= 0 {
		return fmt.Errorf("database cleanup authority unavailable")
	}
	if err := m.journal.CheckDatabaseCleanupOwner(ctx, m.owner); err != nil {
		return fmt.Errorf("database cleanup authority unavailable")
	}
	records, err := m.journal.ListDatabaseCleanup(ctx)
	if err != nil {
		return err
	}
	unknown := false
	for _, record := range records {
		if record.Accessor == accessor {
			unknown = record.LeaseID == ""
			break
		}
	}
	if !unknown {
		return fmt.Errorf("unknown-issuance record not found")
	}
	// The record's child token is not revoked here: its value died with the
	// process that held it, and it expires within its TTL, revoking any lease
	// it issued. The operator's database evidence is what reopens the binding.
	return m.journal.ConfirmDatabaseCleanup(ctx, m.owner, accessor, evidence)
}

func (m *DurableLeaseMinter) run() {
	defer close(m.done)
	heartbeat := time.NewTicker(m.opts.Heartbeat)
	defer heartbeat.Stop()
	retry := time.NewTicker(m.opts.RetryInterval)
	defer retry.Stop()
	fence := time.NewTimer(m.untilFence(time.Now()))
	defer fence.Stop()
	// Heartbeats must continue while a failed external cleanup is timing out.
	var cleanup sync.WaitGroup
	defer cleanup.Wait()
	busy := make(chan struct{}, 1)
	for {
		reconcile := false
		select {
		case <-m.ctx.Done():
			return
		case <-fence.C:
			m.fence()
			return
		case <-heartbeat.C:
			if !m.heartbeat() {
				m.fence()
				return
			}
			fence.Reset(m.untilFence(time.Now()))
		case <-retry.C:
			reconcile = true
		case <-m.kick:
			reconcile = true
		}
		if reconcile {
			select {
			case busy <- struct{}{}:
				cleanup.Add(1)
				go func() {
					defer cleanup.Done()
					defer func() { <-busy }()
					m.reconcilePass()
					// Unknown issuances are checked outside m.mu, so a slow
					// Vault never holds up an issuance.
					m.checkUnknowns()
				}()
			default:
			}
		}
	}
}

// reconcilePass revokes known leases no session holds, when no issuance is
// under way.
func (m *DurableLeaseMinter) reconcilePass() {
	if !m.mu.TryLock() {
		return
	}
	defer m.mu.Unlock()
	ctx, cancel := context.WithTimeout(m.ctx, leaseRevokeTimeout)
	defer cancel()
	// Claim on every pass, not only on heartbeats, so a dead replica's records
	// move within a second of its expiry.
	if m.untilFence(time.Now()) > 0 {
		_, _ = m.journal.ClaimOrphanedDatabaseCleanup(ctx, m.owner)
	}
	_ = m.reconcile(ctx, "")
}

func databaseBinding(vaultID string, svc *DatabaseService) string {
	// A reconfigured binding retains its identity so unresolved old credentials
	// prevent reopening the same service under a different mount or role.
	return vaultID + "/" + svc.Name
}

// reconcile revokes this replica's records that no live session holds,
// including records claimed from dead replicas. Revocation is idempotent, so a
// record revoked twice after a contested takeover is harmless. Unknown
// issuances are left to checkUnknowns; here a binding's quarantine mark is only
// honored, never set or lifted, so neither an issuance nor Close reopens it.
func (m *DurableLeaseMinter) reconcile(ctx context.Context, binding string) error {
	if err := m.journal.CheckDatabaseCleanupOwner(ctx, m.owner); err != nil {
		return err
	}
	records, err := m.journal.ListOwnedDatabaseCleanup(ctx, m.owner)
	if err != nil {
		return err
	}
	m.activeMu.Lock()
	active := make(map[string]bool, len(m.active))
	for _, lease := range m.active {
		active[lease.accessor] = true
	}
	m.activeMu.Unlock()
	var failure error
	for _, record := range records {
		if active[record.Accessor] || record.LeaseID == "" || (binding != "" && binding != record.Binding) {
			continue
		}
		if err := m.journal.CheckDatabaseCleanupOwner(ctx, m.owner); err != nil {
			return err
		}
		// A record no live session holds belongs to a dead or retired session:
		// its credential is revoked by path. Its child token is not revoked by
		// accessor, a right no policy could limit to the broker's own tokens;
		// only that session's process ever held the token, and it expires
		// within its TTL.
		// The journal is the broker's own record of what it minted, so a replica
		// that restarted since may still revoke it.
		m.client.AdoptLease(record.LeaseID)
		cleanupCtx, cancel := context.WithTimeout(ctx, leaseRevokeTimeout)
		err := m.client.RevokeDatabaseLeaseConfirmed(cleanupCtx, record.LeaseID)
		cancel()
		if err == nil {
			err = m.journal.DeleteDatabaseCleanup(ctx, record.Accessor)
		}
		if err != nil {
			failure = fmt.Errorf("database binding cleanup incomplete: %w", err)
		}
	}
	if failure == nil && binding != "" {
		// An unknown issuance whose orphan Vault cannot revoke, held by any
		// replica, closes the binding.
		if quarantined, err := m.journal.DatabaseBindingQuarantined(ctx, binding); err != nil || quarantined {
			failure = errors.New("database binding cleanup incomplete: Vault cannot revoke an orphan lease under this role")
		}
	}
	return failure
}

// unknownState is where one check left an unknown issuance.
type unknownState int

const (
	// unknownUnavailable: the check could not finish (a journal or Vault
	// call failed or timed out, or the minter is stopping), or Vault refused
	// an orphan's revocation for the first time. Nothing changes: an open
	// binding stays open and a closed one stays closed.
	unknownUnavailable unknownState = iota
	// unknownPending: a complete check found no orphan Vault refuses to
	// revoke, but leases the journal does not account for yet. The record
	// stays; a closed binding reopens.
	unknownPending
	// unknownCleared: Vault holds no credential from it; the record is closed.
	unknownCleared
	// unknownStuck: Vault refused to revoke an orphan lease under the role on
	// two checks in a row, a database fault. Only this closes the binding.
	unknownStuck
)

// orphanAge is how old an unaccounted lease must be, by Vault's clock, before
// the broker treats it as an orphan rather than another replica's issuance
// still on its way to the journal: the issuance limit plus a minute of skew.
func (m *DurableLeaseMinter) orphanAge() time.Duration { return m.opts.IssueTimeout + time.Minute }

// credentialPath is one mount and role whose unknown issuances share a check.
type credentialPath struct{ mount, role string }

// pathCheck is the outcome of one check of a credential path, shared by every
// unknown issuance under it.
type pathCheck struct {
	listed, unaccounted, young, refused int
	unavailable                         bool
	shared                              bool // not a Gatehouse role: never listed
}

// gatehouseRolePrefix names the Vault roles only Gatehouse uses. Orphan
// listing and revocation touch no other role, whatever Vault's policy allows:
// a shared role's list holds other clients' leases, and revoking one as an
// orphan would end that client's sessions.
const gatehouseRolePrefix = "gatehouse-"

func gatehouseRole(role string) bool { return strings.HasPrefix(role, gatehouseRolePrefix) }

// state is where this check leaves an issuance that Vault refused to revoke
// an orphan for on refusals checks in a row (zero when it did not refuse).
func (c pathCheck) state(refusals int) unknownState {
	switch {
	case refusals >= 2:
		return unknownStuck
	case refusals == 1 || c.unavailable || c.shared:
		return unknownUnavailable
	case c.unaccounted > 0:
		return unknownPending
	}
	return unknownCleared
}

// checkUnknowns runs one pass of the automatic check of this replica's unknown
// issuances (lost credential responses). It proves, without an operator, that
// no credential from one remains:
//
//  1. its child token has been dead, revoked by this process or past its
//     maximum lifetime, for UnknownSettle by the database clock, so no request
//     made with it can still register a lease; and
//  2. Vault's lease list for the record's credential path, read after that,
//     holds no lease the fleet's journal does not account for.
//
// Vault deletes a lease only after the database engine has removed its user,
// and keeps a failing or irrevocable revocation listed, so a credential from
// this issuance that still exists would be listed and unaccounted. Vault
// returns a credential only after registering its lease, so one that was never
// registered was never handed to anyone. Token revocation success alone proves
// nothing (Vault queues lease revocation) and neither does elapsed lifetime;
// both only decide when the list is worth reading.
//
// An unaccounted lease older than orphanAge under the role is an orphan: every
// live session's lease is journaled before it is returned. The broker revokes
// it by path. Vault refusing that revocation on two checks in a row means the
// database refuses to drop the role: the state is unknownStuck and the binding
// closes. A timeout, a transport error or an overloaded Vault is a blip and
// changes nothing. A younger lease may be another replica's issuance, so the
// check waits. Only roles named gatehouse-* are ever listed or revoked, in
// code as well as in Vault's policy, so no other client's lease is revoked
// here even if the policy is widened.
//
// Each journal or Vault call of a check runs on its own deadline, so a slow
// call cannot use up the others' time; a fence or Close still ends it. The
// work per pass does not grow with the square of the backlog: one read
// of the settled set, one lease list per mount and role, one read of the
// fleet's journal, and per issuance only its own state change. A closed
// binding reopens only after a complete check, never on an error or a stop.
//
// An unresolved record does not close its binding: the lost credential's
// password reached no agent and no session, so reopening grants no one access
// to it. It is logged on every check until it clears. It runs outside m.mu:
// the list comes before the journal read, so a lease a live session issues
// meanwhile is either journaled or too young to revoke, on this replica as on
// any other.
func (m *DurableLeaseMinter) checkUnknowns() {
	m.checkMu.Lock()
	defer m.checkMu.Unlock()
	if m.ctx.Err() != nil || m.untilFence(time.Now()) <= 0 {
		return
	}
	ctx, cancel := context.WithTimeout(m.ctx, leaseRevokeTimeout)
	err := m.journal.CheckDatabaseCleanupOwner(ctx, m.owner)
	var records []store.DatabaseCleanup
	if err == nil {
		records, err = m.journal.ListOwnedDatabaseCleanup(ctx, m.owner)
	}
	cancel()
	if err != nil {
		return
	}
	now := time.Now()
	current := make(map[string]bool)
	var due []store.DatabaseCleanup
	for _, record := range records {
		if record.LeaseID != "" {
			continue
		}
		current[record.Accessor] = true
		if record.Mount == "" || record.Role == "" {
			// A mark an older build wrote for any unknown issuance. Such a
			// record cannot be checked until a request for its binding adopts
			// a mount and role, and an unknown issuance alone never closes a
			// binding.
			if record.Quarantined {
				ctx, cancel := context.WithTimeout(m.ctx, leaseRevokeTimeout)
				_ = m.journal.ReleaseDatabaseCleanupQuarantine(ctx, m.owner, record.Accessor)
				cancel()
			}
			continue
		}
		if last, ok := m.checked[record.Accessor]; !ok || now.Sub(last) >= m.opts.UnknownRecheck {
			due = append(due, record)
		}
	}
	for accessor := range m.checked {
		if !current[accessor] {
			delete(m.checked, accessor)
		}
	}
	for accessor := range m.refused {
		if !current[accessor] {
			delete(m.refused, accessor)
		}
	}
	if len(due) == 0 {
		return
	}
	ctx, cancel = context.WithTimeout(m.ctx, leaseRevokeTimeout)
	settled, err := m.journal.SettledDatabaseCleanup(ctx, m.owner, m.opts.UnknownSettle)
	cancel()
	if err != nil {
		return
	}
	ready := make(map[string]bool, len(settled))
	for _, record := range settled {
		ready[record.Accessor] = true
	}
	groups := make(map[credentialPath][]store.DatabaseCleanup)
	var paths []credentialPath
	for _, record := range due {
		if !ready[record.Accessor] {
			continue
		}
		m.checked[record.Accessor] = now
		path := credentialPath{record.Mount, record.Role}
		if _, ok := groups[path]; !ok {
			paths = append(paths, path)
		}
		groups[path] = append(groups[path], record)
	}
	if len(paths) == 0 {
		return
	}
	// Every list comes before the journal read: a lease issued meanwhile by
	// a live session is then either journaled or still unaccounted.
	listed := make(map[credentialPath][]string, len(paths))
	failed := make(map[credentialPath]bool)
	for _, path := range paths {
		if !gatehouseRole(path.role) {
			continue
		}
		ctx, cancel := context.WithTimeout(m.ctx, leaseRevokeTimeout)
		leases, err := m.client.ListDatabaseLeases(ctx, path.mount, path.role)
		cancel()
		if err != nil {
			failed[path] = true
			continue
		}
		listed[path] = leases
	}
	known := make(map[string]bool)
	ctx, cancel = context.WithTimeout(m.ctx, leaseRevokeTimeout)
	fleet, err := m.journal.ListDatabaseCleanup(ctx)
	cancel()
	if err != nil {
		return
	}
	for _, other := range fleet {
		if other.LeaseID != "" {
			known[other.LeaseID] = true
		}
	}
	expired := m.expiredShared(paths)
	for _, path := range paths {
		var check pathCheck
		switch {
		case !gatehouseRole(path.role):
			check.shared = true
		case failed[path]:
			check.unavailable = true
		default:
			check = m.checkPath(path, listed[path], known)
		}
		m.settlePath(path, groups[path], check, expired, now)
	}
}

// expiredShared returns the accessors whose token died at least SharedRoleMaxTTL ago, when a shared role is among paths.
func (m *DurableLeaseMinter) expiredShared(paths []credentialPath) map[string]bool {
	if !slices.ContainsFunc(paths, func(p credentialPath) bool { return !gatehouseRole(p.role) }) {
		return nil
	}
	ctx, cancel := context.WithTimeout(m.ctx, leaseRevokeTimeout)
	defer cancel()
	records, err := m.journal.SettledDatabaseCleanup(ctx, m.owner, m.opts.SharedRoleMaxTTL)
	if err != nil {
		return nil
	}
	out := make(map[string]bool, len(records))
	for _, record := range records {
		out[record.Accessor] = true
	}
	return out
}

// checkPath revokes the orphans among a credential path's unaccounted leases,
// each on its own deadline.
func (m *DurableLeaseMinter) checkPath(path credentialPath, leases []string, known map[string]bool) pathCheck {
	check := pathCheck{listed: len(leases)}
	prefix, err := hashicorp.DatabaseLeasePrefix(path.mount, path.role)
	if err != nil || !gatehouseRole(path.role) {
		return pathCheck{shared: true}
	}
	for _, lease := range leases {
		if known[lease] || !strings.HasPrefix(lease, prefix) {
			continue
		}
		check.unaccounted++
		ctx, cancel := context.WithTimeout(m.ctx, leaseRevokeTimeout)
		issued, err := m.client.DatabaseLeaseIssued(ctx, lease)
		cancel()
		switch {
		case errors.Is(err, hashicorp.ErrLeaseGone):
			continue
		case err != nil:
			check.unavailable = true
			continue
		case time.Since(issued) < m.orphanAge():
			check.young++
			continue
		}
		ctx, cancel = context.WithTimeout(m.ctx, leaseRevokeTimeout)
		err = m.client.RevokeDatabaseLeaseConfirmed(ctx, lease)
		cancel()
		switch {
		case errors.Is(err, hashicorp.ErrLeaseRevokeRefused):
			check.refused++
		case err != nil:
			check.unavailable = true
		}
	}
	return check
}

// settlePath applies one credential path's check to each unknown issuance
// under it.
func (m *DurableLeaseMinter) settlePath(path credentialPath, records []store.DatabaseCleanup, check pathCheck, expired map[string]bool, now time.Time) {
	prefix, _ := hashicorp.DatabaseLeasePrefix(path.mount, path.role)
	log := m.opts.Logger.With(slog.String("lease_prefix", prefix), slog.Int("unknown_issuances", len(records)))
	counts := make(map[unknownState]int)
	warnDue := 0
	for _, record := range records {
		refusals := 0
		if check.refused > 0 {
			m.refused[record.Accessor]++
			refusals = m.refused[record.Accessor]
		} else if !check.unavailable {
			delete(m.refused, record.Accessor)
		}
		state := check.state(refusals)
		if check.shared && expired[record.Accessor] {
			state = unknownCleared
		}
		ctx, cancel := context.WithTimeout(m.ctx, leaseRevokeTimeout)
		switch state {
		case unknownStuck:
			if !record.Quarantined && m.journal.QuarantineDatabaseCleanup(ctx, m.owner, record.Accessor) != nil {
				state = unknownUnavailable
			}
		case unknownPending:
			if record.Quarantined && m.journal.ReleaseDatabaseCleanupQuarantine(ctx, m.owner, record.Accessor) != nil {
				state = unknownUnavailable
			}
		case unknownCleared:
			verification := "automated_vault_lease_absence"
			if check.shared {
				verification = "shared_role_max_ttl_elapsed"
			}
			fields := map[string]any{
				"verification": verification, "checked_at": now.UTC().Format(time.RFC3339Nano),
				"lease_prefix": prefix, "settle_seconds": int(m.opts.UnknownSettle / time.Second),
			}
			if check.shared {
				fields["max_ttl_seconds"] = int(m.opts.SharedRoleMaxTTL / time.Second)
			} else {
				fields["listed_leases"] = check.listed
			}
			evidence, _ := json.Marshal(fields)
			if m.journal.ConfirmDatabaseCleanup(ctx, m.owner, record.Accessor, string(evidence)) != nil {
				state = unknownUnavailable
			} else {
				delete(m.checked, record.Accessor)
				delete(m.refused, record.Accessor)
			}
		}
		cancel()
		counts[state]++
		if state == unknownCleared {
			delete(m.warned, record.Accessor)
		} else if check.shared && now.Sub(m.warned[record.Accessor]) >= m.opts.SharedWarnEvery {
			m.warned[record.Accessor] = now
			warnDue++
		}
	}
	switch {
	case counts[unknownStuck] > 0:
		log.Error("pgproxy: unknown database issuance stuck: Vault refused to revoke an orphan lease under this role on two checks in a row; the database refuses to drop it",
			slog.Int("unrevocable", check.refused), slog.Int("closed", counts[unknownStuck]))
	case check.refused > 0:
		log.Warn("pgproxy: unknown database issuance unresolved: Vault refused to revoke an orphan lease under this role; the database closes if the next check is refused too",
			slog.Int("unrevocable", check.refused))
	case check.shared && warnDue > 0:
		log.Warn("pgproxy: unknown database issuance unresolved: the role is not a Gatehouse role (" + gatehouseRolePrefix + "*), so the broker never lists or revokes its leases; the record closes by itself once the shared role's maximum lease lifetime has passed")
	case check.unavailable:
		log.Warn("pgproxy: unknown database issuance unresolved: Vault or the journal did not answer; nothing changes until a check completes")
	case check.unaccounted > 0:
		log.Warn("pgproxy: unknown database issuance unresolved: Vault holds leases the journal does not account for yet",
			slog.Int("unaccounted", check.unaccounted), slog.Int("too_young_to_revoke", check.young))
	}
	if counts[unknownCleared] > 0 {
		why := "Vault holds no unaccounted lease for it"
		if check.shared {
			why = "the shared role's maximum lease lifetime has passed"
		}
		log.Info("pgproxy: unknown database issuance cleared: "+why, slog.Int("cleared", counts[unknownCleared]))
	}
}

// errDraining refuses an issuance once Close has begun.
var errDraining = errors.New("database broker is stopping")

func (m *DurableLeaseMinter) Mint(ctx context.Context, scope AgentScope, svc *DatabaseService) (*Lease, error) {
	if svc == nil || scope.VaultID == "" || svc.Name == "" {
		return nil, fmt.Errorf("database binding is required")
	}
	// A drain refuses with errDraining, never with the cancellation Close
	// causes: Close cancels m.ctx after it begins the drain, and AfterFunc
	// may already have canceled ctx by the time the lock is tried.
	if m.draining.Load() {
		return nil, errDraining
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(m.ctx, cancel)
	defer stop()
	if err := m.lock(ctx); err != nil {
		if m.draining.Load() {
			return nil, errDraining
		}
		return nil, err
	}
	defer m.mu.Unlock()
	if m.draining.Load() {
		return nil, errDraining
	}
	if m.ctx.Err() != nil || m.untilFence(time.Now()) <= 0 {
		return nil, fmt.Errorf("database cleanup authority unavailable")
	}
	binding := databaseBinding(scope.VaultID, svc)
	m.adoptLegacy(ctx, binding, svc)
	if err := m.reconcile(ctx, binding); err != nil {
		return nil, err
	}
	return m.issue(ctx, scope, svc, binding)
}

// adoptLegacy brings this binding's unknown issuances from before records kept
// their credential path into the automatic check. They take the binding's
// current mount and role, and a token expiry of now plus TokenTTL: the record
// already existed, so its child token was created before now, and no child
// token can outlive TokenTTL, the lifetime every build has requested and the
// one the Vault policy admits. If the binding had moved to another role between
// the lost request and now, a lease under the old role would not be seen; Vault
// revokes that lease when its child token expires, so only a lease whose
// revocation also failed could remain, held by no one. Requires m.mu.
func (m *DurableLeaseMinter) adoptLegacy(ctx context.Context, binding string, svc *DatabaseService) {
	if svc.Mount == "" || svc.Role == "" {
		return
	}
	records, err := m.journal.ListOwnedDatabaseCleanup(ctx, m.owner)
	if err != nil {
		return
	}
	for _, record := range records {
		if record.Binding != binding || record.LeaseID != "" || record.Mount != "" {
			continue
		}
		if m.journal.AdoptDatabaseCleanup(ctx, m.owner, record.Accessor, svc.Mount, svc.Role, m.opts.TokenTTL) == nil {
			m.opts.Logger.Info("pgproxy: unknown database issuance from an older build adopted for the automatic check",
				slog.String("binding", binding), slog.Time("check_after", time.Now().Add(m.opts.TokenTTL+m.opts.UnknownSettle)))
		}
	}
}

// issue runs one issuance, from child token to journaled lease, under its own
// deadline. A caller that leaves partway, or a graceful Close, does not cut it
// short: stopped between the credential read and the lease write, it would
// leave an unknown issuance that closes the binding for everyone. Only
// IssueTimeout or a fence ends it early. If the caller left in the meantime,
// the credential it no longer wants is revoked here. Requires m.mu.
func (m *DurableLeaseMinter) issue(caller context.Context, scope AgentScope, svc *DatabaseService, binding string) (*Lease, error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(caller), m.opts.IssueTimeout)
	defer cancel()
	stop := context.AfterFunc(m.ctx, cancel)
	defer stop()
	session, err := m.client.NewDatabaseSession(ctx, svc.Mount, svc.Role, m.opts.TokenTTL)
	if err != nil {
		return nil, err
	}
	record := store.DatabaseCleanup{Accessor: session.Accessor, Binding: binding, ActorID: scope.ActorID, WorkloadID: scope.WorkloadID,
		Mount: svc.Mount, Role: svc.Role, TokenTTL: m.opts.TokenTTL}
	if err := m.journal.AddDatabaseCleanup(ctx, m.owner, record); err != nil {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), leaseRevokeTimeout)
		defer cleanupCancel()
		_ = session.Revoke(cleanupCtx)
		return nil, fmt.Errorf("persist database cleanup before issuance: %w", err)
	}
	issued := time.Now()
	credential, err := session.ReadCredential(ctx)
	if err != nil {
		// Vault may have issued a credential whose response was lost. This
		// process still holds the child token, and revoking it with its own
		// token revokes every lease it issued, that one included. The durable
		// record stays, so the binding is quarantined until Vault's lease list
		// or an operator shows that no issued credential remains. A confirmed
		// revocation starts the settle wait now rather than at token expiry.
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), leaseRevokeTimeout)
		defer cleanupCancel()
		if session.Revoke(cleanupCtx) == nil {
			_ = m.journal.MarkDatabaseCleanupTokenRevoked(cleanupCtx, m.owner, session.Accessor)
		}
		// Vault refused the read before creating anything, so no credential
		// can remain: the record closes now, shared role or not. Its child
		// token lived only in this process and is dropped here.
		var refused *hashicorp.CredentialReadError
		if errors.Is(err, hashicorp.ErrCredentialNotIssued) && errors.As(err, &refused) {
			evidence, _ := json.Marshal(map[string]any{
				"verification": "vault_refused_issuance", "checked_at": time.Now().UTC().Format(time.RFC3339Nano),
				"vault_status": refused.Status,
			})
			_ = m.journal.ConfirmDatabaseCleanup(cleanupCtx, m.owner, session.Accessor, string(evidence))
		}
		_ = m.reconcile(cleanupCtx, binding)
		return nil, err
	}
	if err := m.journal.SetDatabaseCleanupLease(ctx, m.owner, session.Accessor, credential.LeaseID); err != nil {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), leaseRevokeTimeout)
		defer cleanupCancel()
		_ = m.client.RevokeDatabaseLeaseConfirmed(cleanupCtx, credential.LeaseID)
		_ = session.Revoke(cleanupCtx)
		return nil, fmt.Errorf("persist issued database lease: %w", err)
	}
	if err := caller.Err(); err != nil {
		// The lease is journaled, so a failed revoke here is retried by path.
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), leaseRevokeTimeout)
		defer cleanupCancel()
		if m.client.RevokeDatabaseLeaseConfirmed(cleanupCtx, credential.LeaseID) == nil {
			_ = session.Revoke(cleanupCtx)
			_ = m.journal.DeleteDatabaseCleanup(cleanupCtx, session.Accessor)
		}
		return nil, err
	}
	expiry := credential.ExpiresAt(issued)
	if expiry.After(session.ExpiresAt) {
		expiry = session.ExpiresAt
	}
	m.activeMu.Lock()
	m.active[credential.LeaseID] = durableLease{accessor: session.Accessor, expires: session.ExpiresAt, session: session}
	m.activeMu.Unlock()
	return &Lease{ID: credential.LeaseID, Username: credential.Username, Password: credential.Password, ExpiresAt: expiry, Renewable: credential.Renewable}, nil
}

func (m *DurableLeaseMinter) Renew(ctx context.Context, id string, increment time.Duration) (time.Time, error) {
	m.activeMu.Lock()
	lease, ok := m.active[id]
	m.activeMu.Unlock()
	if !ok || m.ctx.Err() != nil || m.untilFence(time.Now()) <= 0 || !time.Now().Before(lease.expires) {
		return time.Time{}, fmt.Errorf("database session unavailable")
	}
	started := time.Now()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(m.ctx, cancel)
	defer stop()
	ttl, err := m.client.RenewLease(ctx, id, increment)
	if err != nil {
		return time.Time{}, err
	}
	expiry := started.Add(ttl)
	if expiry.After(lease.expires) {
		expiry = lease.expires
	}
	return expiry, nil
}

func (m *DurableLeaseMinter) Revoke(ctx context.Context, id string) error {
	m.activeMu.Lock()
	lease, ok := m.active[id]
	if !ok {
		m.activeMu.Unlock()
		return fmt.Errorf("database session is not active")
	}
	delete(m.active, id)
	m.activeMu.Unlock()
	// Retirement cannot wait for external cleanup: even a timed-out caller must
	// leave this durable record visible to reconciliation and binding admission.
	if err := m.lock(ctx); err != nil {
		return err
	}
	defer m.mu.Unlock()
	if err := m.client.RevokeDatabaseLeaseConfirmed(ctx, id); err != nil {
		return err
	}
	// The credential is gone; ending the child token is tidiness, not a
	// condition for clearing the record (see DatabaseSession.Revoke).
	if lease.session != nil {
		_ = lease.session.Revoke(ctx)
	}
	return m.journal.DeleteDatabaseCleanup(ctx, lease.accessor)
}

// BeginDrain starts the drain at the start of shutdown: readiness turns false
// and no new issuance starts, while one under way finishes. Close drains too.
func (m *DurableLeaseMinter) BeginDrain() { m.draining.Store(true) }

// Close runs after the broker stops sessions. Failed records remain durable for
// the next owner. Caller context bounds waiting and all shutdown cleanup.
// However that goes, the owner row is released last, on its own short
// deadline, so a planned restart under the same replica name registers at
// once instead of waiting out the row; records still held become claimable.
func (m *DurableLeaseMinter) Close(ctx context.Context) error {
	defer func() { _ = m.release() }()
	// Drain: no new issuance starts, and one under way finishes and journals
	// its lease before authority ends. Canceling it mid-read is what leaves an
	// unknown issuance behind.
	m.BeginDrain()
	if err := m.lock(ctx); err == nil {
		m.mu.Unlock()
	}
	m.cancel()
	select {
	case <-m.done:
	case <-ctx.Done():
		return ctx.Err()
	}
	if err := m.lock(ctx); err != nil {
		return err
	}
	defer m.mu.Unlock()
	if m.closed {
		return m.closeErr
	}
	m.closed = true
	m.activeMu.Lock()
	m.active = make(map[string]durableLease)
	m.activeMu.Unlock()
	err := m.reconcile(ctx, "")
	if releaseErr := m.release(); err == nil {
		err = releaseErr
	}
	m.closeErr = err
	return err
}

// release gives up the owner row once, even after the caller's deadline.
func (m *DurableLeaseMinter) release() error {
	m.releaseOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), leaseRevokeTimeout)
		defer cancel()
		m.releaseErr = m.journal.ReleaseDatabaseCleanupOwner(ctx, m.owner)
	})
	return m.releaseErr
}
