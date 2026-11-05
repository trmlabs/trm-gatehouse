// Package taskrelay keeps workload proofs outside an untrusted task sandbox; network isolation must stop the sandbox bypassing the relay.
package taskrelay

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Infisical/agent-vault/internal/workloadidentity"
)

// FixedConfig is operator-owned; no field may come from requests.
type FixedConfig struct {
	TaskID           string           `json:"taskID"`
	Deadline         time.Time        `json:"deadline"`
	Sandbox          SandboxConfig    `json:"sandbox"`
	Kubernetes       KubernetesConfig `json:"kubernetes"`
	TLSCertFile      string           `json:"tlsCertFile"`
	TLSKeyFile       string           `json:"tlsKeyFile"`
	AuditFile        string           `json:"auditFile"`
	Connect          *ConnectConfig   `json:"connect,omitempty"`
	Postgres         *PostgresConfig  `json:"postgres,omitempty"`
	PostgresBindings []PostgresConfig `json:"postgresBindings,omitempty"`
	// PostgresListener, shared mode only: one port for every catalog database.
	PostgresListener *PostgresListenerConfig `json:"postgresListener,omitempty"`
	// PostgresListeners, self mode only: routed loopback PostgreSQL ports, each with its own upstream.
	PostgresListeners []PostgresListenerConfig `json:"postgresListeners,omitempty"`
	// MaxPostgresListeners bounds PostgresListeners (self mode only; default 10000, up to 65535).
	MaxPostgresListeners int                  `json:"maxPostgresListeners,omitempty"`
	Browser              *BrowserConfig       `json:"browser,omitempty"`
	BoltListeners        []BoltListenerConfig `json:"boltListeners,omitempty"`
	// Self runs the relay as a sidecar: loopback plaintext listeners only and no Kubernetes pairing, since the broker verifies the Pod's token and address.
	Self bool `json:"self,omitempty"`
	// MaxConnections bounds a sidecar's open connections (default 32); a shared proxy uses shared.maxConnections.
	MaxConnections int `json:"maxConnections,omitempty"`
	// HandshakeSeconds bounds each connection's setup (default 10, 1 to 300).
	HandshakeSeconds int           `json:"handshakeSeconds,omitempty"`
	Shared           *SharedConfig `json:"shared,omitempty"`
	// TLS, shared mode only, serves every listener but AdminListen.
	TLS *ServingTLSConfig `json:"tls,omitempty"`
	// AdminListen, shared mode only, serves GET /v1/activity in plaintext; a network policy must admit only the janitor.
	AdminListen string `json:"adminListen,omitempty"`
	// ActivityRetentionSeconds defaults to a day; the janitor refuses a retention shorter than its idle time.
	ActivityRetentionSeconds int64 `json:"activityRetentionSeconds,omitempty"`
	// DurableActivity keeps activity in the broker's shared store; see DurableActivityConfig.
	DurableActivity *DurableActivityConfig `json:"durableActivity,omitempty"`
	// AutomationSettings writes a Cursor run's Automation settings where its shells read them (self mode); see AutomationSettingsConfig.
	AutomationSettings *AutomationSettingsConfig `json:"automationSettings,omitempty"`
}
type SandboxConfig struct {
	Namespace     string `json:"namespace"`
	Name          string `json:"name"`
	UID           string `json:"uid"`
	PodIP         string `json:"podIP"`
	ContainerName string `json:"containerName"`
}
type KubernetesConfig struct {
	APIURL            string `json:"apiURL"`
	CAFile            string `json:"caFile"`
	ReviewerTokenFile string `json:"reviewerTokenFile"`
}
type UpstreamConfig struct {
	Address    string `json:"address"`
	ServerName string `json:"serverName"`
	CAFile     string `json:"caFile"`
	ProofFile  string `json:"proofFile"`
	Audience   string `json:"audience"`
	// SessionFile, self mode: the Claude runner's session token, sent to the broker on each connection; a missing or empty file sends nothing.
	SessionFile string `json:"sessionFile,omitempty"`
	// SessionSocketDir, self mode instead of SessionFile: the Cursor identity socket directory; no claim or several sockets sends nothing.
	SessionSocketDir string `json:"sessionSocketDir,omitempty"`
	SessionAudience  string `json:"sessionAudience,omitempty"`
}

func (u UpstreamConfig) hasSession() bool {
	return u.SessionFile != "" || u.SessionSocketDir != "" || u.SessionAudience != ""
}

// validSession needs one absolute source, and an audience exactly when it is a Cursor socket directory.
func (u UpstreamConfig) validSession() bool {
	if u.SessionFile != "" && u.SessionSocketDir != "" {
		return false
	}
	if u.SessionFile != "" && !strings.HasPrefix(u.SessionFile, "/") {
		return false
	}
	if u.SessionSocketDir == "" {
		return u.SessionAudience == ""
	}
	return strings.HasPrefix(u.SessionSocketDir, "/") && sessionAudience.MatchString(u.SessionAudience)
}

type ConnectConfig struct {
	Listen         string         `json:"listen"`
	Upstream       UpstreamConfig `json:"upstream"`
	AllowedTargets []string       `json:"allowedTargets"`
	// Routes "broker", shared mode only, replaces AllowedTargets; the broker's catalog refuses unlisted hosts.
	Routes string `json:"routes,omitempty"`
}

// routesBroker must be set explicitly: a config that merely drops its list fails validation.
const routesBroker = "broker"

type PostgresConfig struct {
	Listen      string         `json:"listen"`
	Upstream    UpstreamConfig `json:"upstream"`
	Database    string         `json:"database"`
	User        string         `json:"user"`
	Placeholder string         `json:"placeholder"`
}

// PostgresListenerConfig is one PostgreSQL port routed by the startup packet's database; a name outside Databases is refused before the broker is dialed.
type PostgresListenerConfig struct {
	Listen      string         `json:"listen"`
	Upstream    UpstreamConfig `json:"upstream"`
	Databases   []string       `json:"databases,omitempty"`
	User        string         `json:"user"`
	Placeholder string         `json:"placeholder"`
	// Routes "broker", in place of Databases, leaves refusal of ungranted names to the broker.
	Routes string `json:"routes,omitempty"`
}

func (l *PostgresListenerConfig) route(database string) PostgresConfig {
	return PostgresConfig{Listen: l.Listen, Upstream: l.Upstream, Database: database, User: l.User, Placeholder: l.Placeholder}
}

type BrowserConfig struct {
	Listen   string         `json:"listen"`
	Upstream UpstreamConfig `json:"upstream"`
}

var safeName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,252}$`)
var containerName = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$`)

// sessionAudience matches the broker's AGENT_VAULT_CURSOR_AUDIENCE pattern.
var sessionAudience = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,252}$`)
var errConfig = errors.New("invalid fixed task relay configuration")

const maxConfigBytes = 16 << 20

// LoadConfig rejects unknown fields, trailing data and oversized configuration.
func LoadConfig(path string) (FixedConfig, error) {
	var c FixedConfig
	// The bound is sized for tens of thousands of catalog names.
	b, err := readBoundedFile(path, maxConfigBytes)
	if err != nil {
		return c, errConfig
	}
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.DisallowUnknownFields()
	if d.Decode(&c) != nil || d.Decode(new(any)) != io.EOF {
		return c, errConfig
	}
	// A sidecar's lifetime starts with the container; the broker enforces the Pod's real deadline.
	if c.Self && c.Deadline.IsZero() {
		c.Deadline = time.Now().Add(workloadidentity.DefaultSessionCeiling).Add(-time.Minute)
	}
	// Each agent's deadline comes from its Pod.
	if c.Shared != nil && c.Deadline.IsZero() {
		c.Deadline = time.Now().Add(10 * 365 * 24 * time.Hour)
	}
	return c, c.Validate(time.Now())
}

func (c FixedConfig) Validate(now time.Time) error {
	if (c.AdminListen != "" || c.PostgresListener != nil || c.TLS != nil) && c.Shared == nil {
		return errConfig
	}
	if ((len(c.PostgresListeners) != 0 || c.MaxPostgresListeners != 0) && (!c.Self || c.Shared != nil)) ||
		c.MaxPostgresListeners < 0 || c.MaxPostgresListeners > maxLoopbackPorts {
		return errConfig
	}
	if len(c.BoltListeners) != 0 && (!c.Self || c.Shared != nil) {
		return errConfig
	}
	if d := c.DurableActivity; d != nil && (c.AdminListen == "" || c.Connect == nil || d.PushSeconds < 0 || d.PushSeconds > 3600) {
		return errConfig
	}
	if c.MaxConnections < 0 || c.MaxConnections > 65536 || (c.MaxConnections != 0 && c.Shared != nil) ||
		c.HandshakeSeconds < 0 || c.HandshakeSeconds > 300 {
		return errConfig
	}
	if c.ActivityRetentionSeconds != 0 && (c.AdminListen == "" || c.ActivityRetentionSeconds < 60 || c.ActivityRetentionSeconds > 366*24*3600) {
		return errConfig
	}
	if c.AutomationSettings != nil && c.AutomationSettings.validate(c) != nil {
		return errConfig
	}
	if c.Shared != nil {
		return c.validateShared(now)
	}
	if c.Self {
		return c.validateSelf(now)
	}
	if (c.Connect != nil && c.Connect.Upstream.hasSession()) || c.Browser != nil && c.Browser.Upstream.hasSession() {
		return errConfig // only a sidecar in the session's own Pod forwards its token
	}
	for _, p := range c.postgresBindings() {
		if p.Upstream.hasSession() {
			return errConfig
		}
	}
	if !containerName.MatchString(c.Sandbox.ContainerName) {
		return errConfig
	}
	if !safeName.MatchString(c.TaskID) || !c.Deadline.After(now) || c.Deadline.After(now.Add(workloadidentity.DefaultSessionCeiling)) {
		return errConfig
	}
	for _, v := range []string{c.Sandbox.Namespace, c.Sandbox.Name, c.Sandbox.UID} {
		if !safeName.MatchString(v) {
			return errConfig
		}
	}
	if net.ParseIP(c.Sandbox.PodIP) == nil || c.TLSCertFile == "" || c.TLSKeyFile == "" || c.AuditFile == "" || c.Kubernetes.CAFile == "" || c.Kubernetes.ReviewerTokenFile == "" {
		return errConfig
	}
	u, e := url.Parse(c.Kubernetes.APIURL)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return errConfig
	}
	used := map[string]bool{}
	check := func(listen string, upstream UpstreamConfig) error {
		if !validAddress(listen) || used[listen] || !validAddress(upstream.Address) || upstream.ServerName == "" || upstream.CAFile == "" || upstream.ProofFile == "" || upstream.Audience == "" {
			return errConfig
		}
		used[listen] = true
		return nil
	}
	if c.Connect != nil {
		if check(c.Connect.Listen, c.Connect.Upstream) != nil || c.Connect.Routes != "" || len(c.Connect.AllowedTargets) == 0 {
			return errConfig
		}
		for _, target := range c.Connect.AllowedTargets {
			if !validAddress(target) {
				return errConfig
			}
		}
	}
	if len(c.PostgresBindings) > 8 || (c.Postgres != nil && len(c.PostgresBindings) != 0) {
		return errConfig
	}
	for _, p := range c.postgresBindings() {
		if check(p.Listen, p.Upstream) != nil || !safeName.MatchString(p.Database) || !safeName.MatchString(p.User) || !safeName.MatchString(p.Placeholder) {
			return errConfig
		}
	}
	if c.Browser != nil && check(c.Browser.Listen, c.Browser.Upstream) != nil {
		return errConfig
	}
	if len(used) == 0 {
		return errConfig
	}
	return nil
}

func loopbackAddress(address string) bool {
	host, _, _ := net.SplitHostPort(address)
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// validateSelf allows only loopback listeners, no browser and no pairing input.
func (c FixedConfig) validateSelf(now time.Time) error {
	if c.Connect != nil && !c.Connect.Upstream.validSession() {
		return errConfig
	}
	for _, p := range c.postgresBindings() {
		if !p.Upstream.validSession() {
			return errConfig
		}
	}
	if !safeName.MatchString(c.TaskID) || !c.Deadline.After(now) || c.Deadline.After(now.Add(workloadidentity.DefaultSessionCeiling)) || c.AuditFile == "" || c.Browser != nil ||
		c.Sandbox != (SandboxConfig{}) || c.Kubernetes != (KubernetesConfig{}) || c.TLSCertFile != "" || c.TLSKeyFile != "" {
		return errConfig
	}
	used := map[string]bool{}
	check := func(listen string, upstream UpstreamConfig) error {
		if !validAddress(listen) || !loopbackAddress(listen) || used[listen] || !validAddress(upstream.Address) || upstream.ServerName == "" || upstream.CAFile == "" || upstream.ProofFile == "" || upstream.Audience == "" {
			return errConfig
		}
		used[listen] = true
		return nil
	}
	if c.Connect != nil {
		if check(c.Connect.Listen, c.Connect.Upstream) != nil || c.Connect.Routes != "" || len(c.Connect.AllowedTargets) == 0 {
			return errConfig
		}
		for _, target := range c.Connect.AllowedTargets {
			if !validAddress(target) {
				return errConfig
			}
		}
	}
	if len(c.PostgresBindings) > 8 || (c.Postgres != nil && len(c.PostgresBindings) != 0) {
		return errConfig
	}
	for _, p := range c.postgresBindings() {
		if check(p.Listen, p.Upstream) != nil || !safeName.MatchString(p.Database) || !safeName.MatchString(p.User) || !safeName.MatchString(p.Placeholder) {
			return errConfig
		}
	}
	if len(c.PostgresListeners) > c.postgresListenerLimit() {
		return errConfig
	}
	for _, l := range c.PostgresListeners {
		if !l.Upstream.validSession() || check(l.Listen, l.Upstream) != nil || !l.validRoutes() ||
			!safeName.MatchString(l.User) || !safeName.MatchString(l.Placeholder) {
			return errConfig
		}
	}
	if c.validBolt(check) != nil {
		return errConfig
	}
	if len(used) == 0 {
		return errConfig
	}
	return nil
}

const (
	defaultMaxPostgresListeners = 10000
	maxLoopbackPorts            = 65535
)

func (c FixedConfig) postgresListenerLimit() int {
	if c.MaxPostgresListeners == 0 {
		return defaultMaxPostgresListeners
	}
	return c.MaxPostgresListeners
}

func (l PostgresListenerConfig) validRoutes() bool {
	return validRouteNames(l.Routes, l.Databases)
}

func (c FixedConfig) activityRetention() time.Duration {
	if c.ActivityRetentionSeconds == 0 {
		return defaultActivityRetention
	}
	return time.Duration(c.ActivityRetentionSeconds) * time.Second
}

func (c FixedConfig) postgresBindings() []PostgresConfig {
	if c.Postgres != nil {
		return []PostgresConfig{*c.Postgres}
	}
	return c.PostgresBindings
}

func validAddress(s string) bool {
	host, port, err := net.SplitHostPort(s)
	n, e := strconv.Atoi(port)
	return err == nil && e == nil && n > 0 && n <= 65535 && host != "" && !strings.ContainsAny(host, "\r\n\t /?#@")
}

func readBoundedFile(path string, max int64) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer func() { _ = f.Close() }()
	b, e := io.ReadAll(io.LimitReader(f, max+1))
	if e != nil || int64(len(b)) > max {
		return nil, errConfig
	}
	return b, nil
}

func clientTLS(caFile, serverName string) (*tls.Config, error) {
	pem, e := readBoundedFile(caFile, 1<<20)
	if e != nil {
		return nil, errConfig
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return nil, errConfig
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: serverName}, nil
}
