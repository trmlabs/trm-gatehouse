// Package auditchain writes the broker's HMAC-chained, Transit-checkpointed audit trail and verifies it offline.
package auditchain

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strconv"
)

// RowType tags audit rows so a log sink can select them from other output.
const RowType = "gatehouse.audit.v1"

// Events. The chain writes chain_start, checkpoint, checkpoint_failed and key_rotated itself.
const (
	EventChainStart       = "chain_start"
	EventSessionOpen      = "session_open"
	EventSessionClose     = "session_close"
	EventDenied           = "denied"
	EventCheckpoint       = "checkpoint"
	EventCheckpointFailed = "checkpoint_failed"
	EventKeyRotated       = "key_rotated"
	EventHTTPRequest      = "http_request"        // admitted, before the upstream call
	EventHTTPResponse     = "http_response"       // outcome and status of that call
	EventTransaction      = "transaction"         // one database transaction on a pooled connection
	EventStateLeak        = "state_leak_caught"   // check-in found session state the classifier missed; reset
	EventCertificate      = "proxy_certificate"   // a shared proxy was issued its serving certificate
	EventSettings         = "automation_settings" // a sidecar was served its run's Automation settings
	EventInjection        = "injection_flagged"   // outside text in a response matched a prompt injection rule
)

// Causes are the fixed codes an upstream_error row's cause may carry.
var Causes = []string{"dial_timeout", "tls_handshake", "conn_refused", "conn_reset", "dns", "tls_certificate", "response_timeout", "other"}

// Row is one audit record. It carries identifiers and fixed outcome codes only: never a credential, token or query text.
// UpstreamMessage is the one free-text field and can echo agent-supplied text.
type Row struct {
	Type      string `json:"type"`
	Replica   string `json:"replica"`
	Boot      uint64 `json:"boot"` // per-replica counter persisted in the store
	Seq       uint64 `json:"seq"`
	Time      string `json:"ts"`
	Event     string `json:"event"`
	Pool      string `json:"pool,omitempty"`      // catalog pool name of the worker
	Agent     string `json:"agent,omitempty"`     // broker agent ID (store UUID)
	PodUID    string `json:"podUID,omitempty"`    // verified runtime instance
	Binding   string `json:"binding,omitempty"`   // vault/service
	Session   string `json:"session,omitempty"`   // broker-generated session ID
	Outcome   string `json:"outcome,omitempty"`   // fixed code
	Requester string `json:"requester,omitempty"` // developer identity, only from a verified source
	// On an automation row, requester decides nothing: only tier and decision are recorded, with no groups, cacheAgeSec, requesterOID or requesterDepartment.
	RequesterKind string `json:"requesterKind,omitempty"` // person, agent, workload, automation or none
	RequesterOID  string `json:"requesterOID,omitempty"`  // Entra object ID of the person named by requester
	TokenSHA256   string `json:"tokenSHA256,omitempty"`   // runner session token hash; never the token
	Tier          string `json:"tier,omitempty"`
	Decision      string `json:"decision,omitempty"`
	Groups        string `json:"groups,omitempty"` // required groups checked
	CacheAgeSec   int64  `json:"cacheAgeSec,omitempty"`
	// Kid is the claimed key id ("invalid" plus a 12-hex SHA-256 prefix when not a plain identifier); Peer is the connection's address.
	Kid       string `json:"kid,omitempty"`
	KidSHA256 string `json:"kidSHA256,omitempty"`
	Peer      string `json:"peer,omitempty"`
	// Serial is lower-case hex; NotAfter is RFC 3339 UTC.
	Serial   string `json:"serial,omitempty"`
	NotAfter string `json:"notAfter,omitempty"`
	DNSNames string `json:"dnsNames,omitempty"`
	// Target is the refused host[:port] in canonical form, or "invalid".
	Target string `json:"target,omitempty"`
	// Operation is from the broker's fixed vocabulary, such as "pr.open", "git.push", "graphql",
	// "slack.conversations_history", "groundcover.query_logs", "bolt.session" or "bolt.query".
	Operation string `json:"operation,omitempty"`
	// Branch is the pushed refs (comma-separated, "+N" for any that do not fit) on a push row,
	// or the head branch on a pull request write or CI restart. "invalid" when not a plain name; empty if the lookup failed.
	Branch string `json:"branch,omitempty"`
	// Database is the name a refused PostgreSQL session asked for, or "invalid".
	Database string `json:"database,omitempty"`
	// RequesterDepartment is the Entra department, present only when an entry needed the lookup.
	RequesterDepartment string `json:"requesterDepartment,omitempty"`
	// Source and Automation come from the verified Cursor run token; AutomationName and AutomationOwner from the catalog.
	Source          string `json:"source,omitempty"`
	Automation      string `json:"automation,omitempty"`
	AutomationName  string `json:"automationName,omitempty"`
	AutomationOwner string `json:"automationOwner,omitempty"`
	// PullRequest, Route and GitEntry name the GitHub request's pull request, matched catalog route and authorizing git entry.
	// Cause is why an upstream_error row failed, from the fixed list in Causes: never an error message.
	Cause string `json:"cause,omitempty"`
	// Match is the SHA-256 in lower-case hex of the text an injection_flagged row matched, never the text.
	Match string `json:"match,omitempty"`
	// UpstreamMessage is the message of GitHub's 4xx JSON error body on a route call, bounded by MessageField; it may echo text the agent sent, so treat it as untrusted.
	UpstreamMessage string `json:"upstreamMessage,omitempty"`
	PullRequest     int64  `json:"pullRequest,omitempty"`
	Route           string `json:"route,omitempty"`
	GitEntry        string `json:"gitEntry,omitempty"`
	Method          string `json:"method,omitempty"`     // HTTP rows only
	Status          int    `json:"status,omitempty"`     // HTTP response rows: upstream or broker status
	Duration        int64  `json:"durationMs,omitempty"` // transaction rows: milliseconds from first message to completion; HTTP response rows: from admission to the end of the response, or the length of a refresh-token revocation; session_open rows: from authentication to admission (queues, credential mint and upstream connect)
	SignedSeq       uint64 `json:"signedSeq,omitempty"`  // checkpoint: the chain head it signs
	SignedMAC       string `json:"signedMAC,omitempty"`
	Signature       string `json:"signature,omitempty"` // checkpoint: Transit "vault:vN:..." signature
	PrevKey         int    `json:"prevKeyVersion,omitempty"`
	// Path is the request path an HTTP row is about, without the query; a gRPC call's path names its service and method.
	// Never a query, header or body, and absent on a decoy refusal.
	Path string `json:"path,omitempty"`
	// Settings is the names of the settings served on an automation_settings row, never a value.
	Settings string `json:"settings,omitempty"`
	// GraphQLErrors summarizes a GraphQL response's top-level errors as TYPE@path entries (see GraphQLErrorsField), never a message or data.
	GraphQLErrors string `json:"graphqlErrors,omitempty"`
	// Run is the verified Cursor run's cloud_agent_id.
	Run string `json:"run,omitempty"`
	// ParentRun is the registering run on a subagent row served as an Automation.
	ParentRun string `json:"parentRun,omitempty"`
	// GRPCStatus is the gRPC status code, "0" to "16", a gRPC call's row ended with: the upstream's, or the one the broker sent for a refusal; absent when none was read.
	GRPCStatus string `json:"grpcStatus,omitempty"`
	// chain_start: the previous boot and its last persisted checkpoint row,
	// so a deleted boot or a truncated tail is detectable.
	PrevBoot          uint64 `json:"prevBoot,omitempty"`
	PrevCheckpointSeq uint64 `json:"prevCheckpointSeq,omitempty"`
	PrevCheckpointMAC string `json:"prevCheckpointMAC,omitempty"`
	KeyVersion        int    `json:"keyVersion"`
	Prev              string `json:"prev"`
	// MACVersion selects the MAC input; absent (0) is v1. See macInput.
	MACVersion int    `json:"macVersion,omitempty"`
	MAC        string `json:"mac"`
}

// MACVersionCurrent is the MAC input every new row uses.
const MACVersionCurrent = 15

// macInput encodes every field except MAC with explicit lengths, so no two distinct rows share an input.
// Older versions only verify rows written before them; a row with a field its version does not cover fails (see v2Only through v15Only).
func (r Row) macInput() []byte {
	fields := []string{
		r.Type, r.Replica, strconv.FormatUint(r.Boot, 10), strconv.FormatUint(r.Seq, 10), r.Time, r.Event,
		r.Pool, r.Agent, r.PodUID, r.Binding, r.Session, r.Outcome, r.Requester, r.Method, strconv.Itoa(r.Status), strconv.FormatInt(r.Duration, 10),
		strconv.FormatUint(r.SignedSeq, 10), r.SignedMAC, r.Signature,
		strconv.Itoa(r.PrevKey), strconv.FormatUint(r.PrevBoot, 10), strconv.FormatUint(r.PrevCheckpointSeq, 10), r.PrevCheckpointMAC,
		strconv.Itoa(r.KeyVersion), r.Prev,
	}
	if r.MACVersion < 2 {
		return lengthPrefixed("gatehouse-audit-v1", fields...)
	}
	fields = append(fields, strconv.Itoa(r.MACVersion),
		r.RequesterKind, r.RequesterOID, r.TokenSHA256, r.Tier, r.Decision, r.Groups, strconv.FormatInt(r.CacheAgeSec, 10))
	if r.MACVersion < 3 {
		return lengthPrefixed("gatehouse-audit-v2", fields...)
	}
	fields = append(fields, r.Kid, r.KidSHA256, r.Peer)
	if r.MACVersion < 4 {
		return lengthPrefixed("gatehouse-audit-v3", fields...)
	}
	fields = append(fields, r.Serial, r.NotAfter, r.DNSNames)
	if r.MACVersion < 5 {
		return lengthPrefixed("gatehouse-audit-v4", fields...)
	}
	fields = append(fields, r.Target)
	if r.MACVersion < 6 {
		return lengthPrefixed("gatehouse-audit-v5", fields...)
	}
	fields = append(fields, r.Operation, r.Database, r.RequesterDepartment)
	if r.MACVersion < 7 {
		return lengthPrefixed("gatehouse-audit-v6", fields...)
	}
	fields = append(fields, r.Branch)
	if r.MACVersion < 8 {
		return lengthPrefixed("gatehouse-audit-v7", fields...)
	}
	fields = append(fields, r.Source, r.Automation, r.AutomationName, r.AutomationOwner)
	if r.MACVersion < 9 {
		return lengthPrefixed("gatehouse-audit-v8", fields...)
	}
	fields = append(fields, r.Path)
	if r.MACVersion < 10 {
		return lengthPrefixed("gatehouse-audit-v9", fields...)
	}
	fields = append(fields, r.Settings, r.GraphQLErrors, strconv.FormatInt(r.PullRequest, 10), r.Route, r.GitEntry)
	if r.MACVersion < 11 {
		return lengthPrefixed("gatehouse-audit-v10", fields...)
	}
	fields = append(fields, r.Cause)
	if r.MACVersion < 12 {
		return lengthPrefixed("gatehouse-audit-v11", fields...)
	}
	fields = append(fields, r.Match)
	if r.MACVersion < 13 {
		return lengthPrefixed("gatehouse-audit-v12", fields...)
	}
	fields = append(fields, r.UpstreamMessage)
	if r.MACVersion < 14 {
		return lengthPrefixed("gatehouse-audit-v13", fields...)
	}
	fields = append(fields, r.Run, r.ParentRun)
	if r.MACVersion < 15 {
		return lengthPrefixed("gatehouse-audit-v14", fields...)
	}
	fields = append(fields, r.GRPCStatus)
	return lengthPrefixed("gatehouse-audit-v15", fields...)
}

// v2Only reports whether a row sets a field that only the v2 MAC covers.
func (r Row) v2Only() bool {
	return r.RequesterKind != "" || r.RequesterOID != "" || r.TokenSHA256 != "" || r.Tier != "" ||
		r.Decision != "" || r.Groups != "" || r.CacheAgeSec != 0
}

// v3Only reports whether a row sets a field that only the v3 MAC covers.
func (r Row) v3Only() bool { return r.Kid != "" || r.KidSHA256 != "" || r.Peer != "" }

// v4Only reports whether a row sets a field that only the v4 MAC covers.
func (r Row) v4Only() bool { return r.Serial != "" || r.NotAfter != "" || r.DNSNames != "" }

// v5Only reports whether a row sets a field that only the v5 MAC covers.
func (r Row) v5Only() bool { return r.Target != "" }

// v6Only reports whether a row sets a field that only the v6 MAC covers.
func (r Row) v6Only() bool {
	return r.Operation != "" || r.Database != "" || r.RequesterDepartment != ""
}

// v7Only reports whether a row sets a field that only the v7 MAC covers.
func (r Row) v7Only() bool { return r.Branch != "" }

// v8Only reports whether a row sets a field that only the v8 MAC covers.
func (r Row) v8Only() bool {
	return r.Source != "" || r.Automation != "" || r.AutomationName != "" || r.AutomationOwner != ""
}

// v9Only reports whether a row sets a field that only the v9 MAC covers.
func (r Row) v9Only() bool { return r.Path != "" }

// v10Only reports whether a row sets a field that only the v10 MAC covers.
func (r Row) v10Only() bool {
	return r.Settings != "" || r.GraphQLErrors != "" || r.PullRequest != 0 || r.Route != "" || r.GitEntry != ""
}

// v11Only reports whether a row sets a field that only the v11 MAC covers.
func (r Row) v11Only() bool { return r.Cause != "" }

// v12Only reports whether a row sets a field that only the v12 MAC covers.
func (r Row) v12Only() bool { return r.Match != "" }

// v13Only reports whether a row sets a field that only the v13 MAC covers.
func (r Row) v13Only() bool { return r.UpstreamMessage != "" }

// v14Only reports whether a row sets a field that only the v14 MAC covers.
func (r Row) v14Only() bool { return r.Run != "" || r.ParentRun != "" }

// v15Only reports whether a row sets a field that only the v15 MAC covers.
func (r Row) v15Only() bool { return r.GRPCStatus != "" }

func (r Row) computeMAC(key []byte) string {
	h := hmac.New(sha256.New, key)
	h.Write(r.macInput())
	return hex.EncodeToString(h.Sum(nil))
}

// checkpointInput is what Transit signs: the chain identity and its head.
func checkpointInput(replica string, boot, seq uint64, mac string) []byte {
	return lengthPrefixed("gatehouse-checkpoint-v1", replica, strconv.FormatUint(boot, 10), strconv.FormatUint(seq, 10), mac)
}

func lengthPrefixed(domain string, fields ...string) []byte {
	out := append([]byte(domain), 0)
	var n [4]byte
	for _, f := range fields {
		binary.BigEndian.PutUint32(n[:], uint32(len(f)))
		out = append(out, n[:]...)
		out = append(out, f...)
	}
	return out
}
