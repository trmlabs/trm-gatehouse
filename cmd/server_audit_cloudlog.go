package cmd

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"cloud.google.com/go/compute/metadata"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/Infisical/agent-vault/internal/auditchain/cloudlog"
)

// auditCloudLogFlush bounds the last delivery at shutdown.
const auditCloudLogFlush = 5 * time.Second

// auditCloudLogTokenTimeout bounds one OAuth token refresh.
const auditCloudLogTokenTimeout = 10 * time.Second

// defaultAuditCloudLogID is the log name rows are written under.
const defaultAuditCloudLogID = "gatehouse-audit-broker"

// newAuditCloudLog builds the Cloud Logging sink, replaced in tests.
var newAuditCloudLog = buildAuditCloudLog

// auditOutput is stdout, plus a Cloud Logging copy when set; unusable settings fail startup.
func auditOutput(ctx context.Context, stdout io.Writer, getenv func(string) string, logger *slog.Logger) (io.Writer, *cloudlog.Sink, error) {
	enabled := false
	if raw := getenv("AGENT_VAULT_AUDIT_CLOUD_LOGGING"); raw != "" {
		var err error
		if enabled, err = strconv.ParseBool(raw); err != nil {
			return nil, nil, fmt.Errorf("AGENT_VAULT_AUDIT_CLOUD_LOGGING must be true or false")
		}
	}
	if !enabled {
		return stdout, nil, nil
	}
	sink, err := newAuditCloudLog(ctx, getenv, logger)
	if err != nil {
		return nil, nil, err
	}
	return cloudlog.Tee(stdout, sink), sink, nil
}

// buildAuditCloudLog reads the settings and credentials; project, cluster and location may come from metadata.
func buildAuditCloudLog(ctx context.Context, getenv func(string) string, logger *slog.Logger) (*cloudlog.Sink, error) {
	res := cloudlog.Resource{
		ProjectID:   getenv("AGENT_VAULT_AUDIT_CLOUD_LOGGING_PROJECT"),
		Location:    getenv("AGENT_VAULT_AUDIT_CLOUD_LOGGING_LOCATION"),
		ClusterName: getenv("AGENT_VAULT_AUDIT_CLOUD_LOGGING_CLUSTER"),
		Namespace:   getenv("AGENT_VAULT_AUDIT_CLOUD_LOGGING_NAMESPACE"),
		Pod:         getenv("AGENT_VAULT_AUDIT_CLOUD_LOGGING_POD"),
		Container:   getenv("AGENT_VAULT_AUDIT_CLOUD_LOGGING_CONTAINER"),
	}
	if res.Namespace == "" || res.Pod == "" || res.Container == "" {
		return nil, fmt.Errorf("audit Cloud Logging requires AGENT_VAULT_AUDIT_CLOUD_LOGGING_NAMESPACE, _POD and _CONTAINER")
	}
	// Token refreshes outlive the startup deadline, so they get their own client with a timeout.
	authCtx := context.WithValue(context.WithoutCancel(ctx), oauth2.HTTPClient, &http.Client{Timeout: auditCloudLogTokenTimeout})
	creds, err := google.FindDefaultCredentials(authCtx, cloudlog.Scope)
	if err != nil {
		return nil, fmt.Errorf("audit Cloud Logging has no usable Google credentials: %w", err)
	}
	if res.ProjectID == "" {
		res.ProjectID = creds.ProjectID
	}
	attrs := func(name string) string {
		lookup, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		v, _ := metadata.InstanceAttributeValueWithContext(lookup, name)
		return v
	}
	if res.ClusterName == "" {
		res.ClusterName = attrs("cluster-name")
	}
	if res.Location == "" {
		res.Location = attrs("cluster-location")
	}
	if !res.Valid() {
		return nil, fmt.Errorf("audit Cloud Logging needs the project, cluster and location: set AGENT_VAULT_AUDIT_CLOUD_LOGGING_PROJECT, _CLUSTER and _LOCATION")
	}
	logID := getenv("AGENT_VAULT_AUDIT_CLOUD_LOGGING_LOG")
	if logID == "" {
		logID = defaultAuditCloudLogID
	}
	base := http.DefaultTransport
	if raw := getenv("AGENT_VAULT_AUDIT_CLOUD_LOGGING_DIAL_ADDRESS"); raw != "" {
		if base, err = dialTransport(raw); err != nil {
			return nil, err
		}
	}
	// The dial address applies to entries.write only; token refreshes keep their own client.
	client := &http.Client{Transport: &oauth2.Transport{Source: creds.TokenSource, Base: base}}
	return cloudlog.New(cloudlog.Options{LogID: logID, Resource: res, Client: client, Logger: logger})
}

// dialTransport connects to a fixed IP:port while the request, Host and certificate check stay on the URL's host.
func dialTransport(raw string) (*http.Transport, error) {
	dial, err := netip.ParseAddrPort(raw)
	if err != nil || dial.Port() == 0 || dial.Addr().IsUnspecified() {
		return nil, fmt.Errorf("AGENT_VAULT_AUDIT_CLOUD_LOGGING_DIAL_ADDRESS must be an IP address and port")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// A fixed dial address is a direct connection, so a proxy setting must not apply.
	transport.Proxy = nil
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, dial.String())
	}
	return transport, nil
}

// stopAuditCheckpoints ends the checkpoint loop and waits for it, so no checkpoint is signed once Vault is closing.
func stopAuditCheckpoints() {
	sharedAudit.Lock()
	stop, stopped := sharedAudit.stop, sharedAudit.stopped
	sharedAudit.Unlock()
	if stop == nil {
		return
	}
	stop()
	<-stopped
}

// closeAuditCloudLog delivers the rows still queued, within auditCloudLogFlush.
func closeAuditCloudLog() {
	sharedAudit.Lock()
	sink := sharedAudit.sink
	sharedAudit.Unlock()
	closeSink(sink)
}
