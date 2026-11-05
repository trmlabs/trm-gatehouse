package cmd

import (
	"context"
	"fmt"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Infisical/agent-vault/internal/auditchain"
	"github.com/Infisical/agent-vault/internal/auditchain/cloudlog"
	"github.com/Infisical/agent-vault/internal/hashicorp"
)

const (
	auditCheckpointInterval = time.Minute
	auditKeyRefresh         = 5 * time.Minute
)

// auditChainNow is the started chain, read by probes without waiting on sharedAudit.
var auditChainNow atomic.Pointer[auditchain.Chain]

var sharedAudit struct {
	sync.Mutex
	chain   *auditchain.Chain
	sink    *cloudlog.Sink // Cloud Logging mirror, nil when off
	stop    context.CancelFunc
	stopped chan struct{} // closed when the checkpoint loop has returned
	started bool
}

// sharedAuditChain gives both brokers one chain per process, so a replica has a single sequence and boot.
func sharedAuditChain(ctx context.Context, client *hashicorp.Client, db any, getenv func(string) string, logger *slog.Logger) (*auditchain.Chain, error) {
	sharedAudit.Lock()
	defer sharedAudit.Unlock()
	if sharedAudit.started {
		return sharedAudit.chain, nil
	}
	chain, sink, stop, stopped, err := startAuditChain(ctx, client, db, getenv, logger)
	if err != nil {
		return nil, err
	}
	sharedAudit.chain, sharedAudit.sink, sharedAudit.stop, sharedAudit.stopped, sharedAudit.started = chain, sink, stop, stopped, true
	auditChainNow.Store(chain)
	if chain != nil && client != nil {
		client.SetRevokeRefusal(func(kind string) { _ = chain.Record(revokeRefusalEvent(kind)) })
	}
	return chain, nil
}

// auditHealth takes a copy whose audit trail stopped for good out of the Service and restarts it; an overdue checkpoint is shared by every copy, so it keeps the retryable refusal.
// Both read the chain at probe time, so any start order sees one made later.
func auditHealth(ready, live func(string, func() bool)) {
	stopped := func() bool {
		chain := auditChainNow.Load()
		if chain == nil {
			return false
		}
		select {
		case <-chain.Failed():
			return true
		default:
			return false
		}
	}
	ready("audit-trail", func() bool { return !stopped() })
	live("audit-trail", func() bool { return !stopped() })
}

// revokeRefusalEvent is the audit row for a Vault revocation the broker refused
// because it did not mint the lease or token (hashicorp.ErrNotMinted).
func revokeRefusalEvent(kind string) auditchain.Event {
	return auditchain.Event{Event: auditchain.EventDenied, Outcome: "not_minted", Operation: "revoke_" + kind}
}

// newAuditChain is auditchain.New, replaced in tests.
var newAuditChain = auditchain.New

// startAuditChain starts the signed audit trail when AGENT_VAULT_AUDIT_CHAIN is set; incomplete settings fail startup rather than serve unaudited. It also returns the Cloud Logging copy to close and the checkpoint loop's stop and done handles.
func startAuditChain(ctx context.Context, client *hashicorp.Client, db any, getenv func(string) string, logger *slog.Logger) (*auditchain.Chain, *cloudlog.Sink, context.CancelFunc, chan struct{}, error) {
	if !boolEnvValue("AGENT_VAULT_AUDIT_CHAIN") {
		logger.Warn("pgproxy: signed audit trail is off (AGENT_VAULT_AUDIT_CHAIN unset); database sessions are not audited")
		return nil, nil, nil, nil, nil
	}
	setting := func(name, fallback string) string {
		if v := getenv(name); v != "" {
			return v
		}
		return fallback
	}
	// A stable name lets each boot link to the last. Brokers sharing a store must set AGENT_VAULT_REPLICA;
	// a single broker may use AGENT_VAULT_AUDIT_REPLICA. There is no hostname fallback.
	replica, err := brokercore.FleetReplicaName(getenv)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if getenv("AGENT_VAULT_REPLICA") == "" && getenv("AGENT_VAULT_AUDIT_REPLICA") == "" {
		return nil, nil, nil, nil, fmt.Errorf("audit chain requires AGENT_VAULT_REPLICA or AGENT_VAULT_AUDIT_REPLICA, a stable replica name such as the Pod name")
	}
	mount, err := kvMount(getenv)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	keys := auditchain.KVKeys{Mount: setting("AGENT_VAULT_AUDIT_HMAC_MOUNT", mount), Path: getenv("AGENT_VAULT_AUDIT_HMAC_PATH"), Field: setting("AGENT_VAULT_AUDIT_HMAC_FIELD", "key")}
	signer := auditchain.TransitSigner{Mount: setting("AGENT_VAULT_AUDIT_TRANSIT_MOUNT", "transit"), Key: getenv("AGENT_VAULT_AUDIT_TRANSIT_KEY")}
	boots, ok := db.(auditchain.BootStore)
	if client == nil || !ok || keys.Path == "" || signer.Key == "" {
		return nil, nil, nil, nil, fmt.Errorf("audit chain requires a Vault client, the SQL store, AGENT_VAULT_AUDIT_HMAC_PATH and AGENT_VAULT_AUDIT_TRANSIT_KEY")
	}
	keys.Vault, signer.Vault = client.Logical(), client.Logical()
	out, sink, err := auditOutput(ctx, os.Stdout, getenv, logger)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	// Reading the audit key needs Vault: retry a blip for the startup window.
	var chain *auditchain.Chain
	err = retryAtStartup(logger, "audit trail", func() error {
		attemptCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		chain, err = newAuditChain(attemptCtx, auditchain.Options{Out: out, Replica: replica, Keys: keys, Signer: signer, Boots: boots})
		return err
	})
	if err != nil {
		closeSink(sink)
		return nil, nil, nil, nil, err
	}
	// Sign a first checkpoint now so the chain is verifiable from boot.
	signCtx, cancel := context.WithTimeout(ctx, auditCheckpointInterval/2)
	_ = chain.Checkpoint(signCtx)
	cancel()
	runCtx, stop := context.WithCancel(ctx) //nolint:gosec // stop is returned and the loop goroutine calls it
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		defer stop()
		chain.Run(runCtx, auditCheckpointInterval, auditKeyRefresh)
	}()
	return chain, sink, stop, stopped, nil
}

// closeSink flushes a Cloud Logging mirror that is on.
func closeSink(sink *cloudlog.Sink) {
	if sink == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), auditCloudLogFlush)
	defer cancel()
	_ = sink.Close(ctx)
}
