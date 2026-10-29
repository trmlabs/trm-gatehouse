package taskrelay

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"time"

	"github.com/Infisical/agent-vault/internal/bolt"
)

// BoltListenerConfig is one Bolt port (Neo4j and Memgraph drivers, bolt://
// and neo4j:// URIs) routed by the user name the client logs in with: the
// user name is the catalog entry's name and the password is Placeholder. The
// relay swaps the placeholder for its proof and forwards to the one upstream,
// which authorizes the entry per pool. Entries is the route table; Routes
// "broker", in its place, forwards any well-formed name and leaves the
// decision to the broker's catalog, so a new entry needs no change here.
type BoltListenerConfig struct {
	Listen      string         `json:"listen"`
	Upstream    UpstreamConfig `json:"upstream"`
	Entries     []string       `json:"entries,omitempty"`
	Routes      string         `json:"routes,omitempty"`
	Placeholder string         `json:"placeholder"`
}

// maxBoltListeners bounds a sidecar's Bolt ports: one per broker it reaches.
const maxBoltListeners = 4

// validBolt checks a sidecar's Bolt ports with the listener check its mode
// applies (loopback and unique in a sidecar).
func (c FixedConfig) validBolt(check func(listen string, upstream UpstreamConfig) error) error {
	if len(c.BoltListeners) > maxBoltListeners {
		return errConfig
	}
	for _, l := range c.BoltListeners {
		if !l.Upstream.validSession() || check(l.Listen, l.Upstream) != nil || !validRouteNames(l.Routes, l.Entries) || !safeName.MatchString(l.Placeholder) {
			return errConfig
		}
	}
	return nil
}

// maxBoltAuthBytes bounds the HELLO and LOGON messages read before
// admission. Real ones are a few hundred bytes.
const maxBoltAuthBytes = 16 << 10

// maxBoltResponseBytes bounds each broker answer to the opening messages.
const maxBoltResponseBytes = 64 << 10

// Bolt failure codes the relay authors, in the broker's Gatehouse family.
// Drivers classify by the second dotted part: a ClientError is not retried, a
// TransientError is.
const (
	boltUnauthorized = "Gatehouse.ClientError.Security.Unauthorized"
	boltProtocol     = "Gatehouse.ClientError.Request.Invalid"
	boltUnavailable  = "Gatehouse.TransientError.General.Unavailable"
	boltNotVerified  = "Gatehouse.TransientError.Security.NotVerified"
	boltEnded        = "Gatehouse.TransientError.General.SessionEnded"
)

// bolt relays one Bolt connection. The relay answers the version handshake
// itself, reads the client's HELLO (and, from Bolt 5.1, LOGON), and checks
// the user name against the route table and the password against the
// placeholder. Only then is the connection admitted, the proof read and the
// broker dialed: the relay sends the session preamble, the client's own
// handshake bytes, the HELLO, and the login with the placeholder replaced by
// the proof, then relays bytes both ways. The worker never sees the proof.
//
// From Bolt 5.1 HELLO carries no login, so the relay answers it at once, as
// the broker does, and a client may wait for that answer before its LOGON.
// The broker's own answer to the forwarded HELLO is then dropped.
func (r *relay) bolt(conn net.Conn, l *BoltListenerConfig, route func(name string) bool) {
	_ = conn.SetDeadline(minTime(r.config.Deadline, time.Now().Add(r.handshake())))
	peer := conn.RemoteAddr().String()
	if !r.pair.peerMatches(peer) {
		if r.foreignPeer.CompareAndSwap(false, true) {
			_ = r.record("bolt", "denied:peer")
		}
		return
	}
	in := bufio.NewReader(conn)
	handshake, e := bolt.ReadHandshake(in, false)
	if e != nil {
		if !errors.Is(e, io.EOF) {
			_ = r.record("bolt", "denied:bad-handshake")
		}
		return
	}
	version, ok := handshake.Choose(bolt.Supported)
	if !ok {
		_ = r.record("bolt", "denied:version")
		_, _ = conn.Write([]byte{0, 0, 0, 0})
		return
	}
	v := version.Bytes()
	if _, e = conn.Write(v[:]); e != nil {
		return
	}
	tell := func(code, message string) { _ = bolt.WriteRaw(conn, bolt.Failure(code, message)) }
	opening, principal, reason := readBoltLogin(in, conn, version, route, l.Placeholder)
	if reason != "" {
		if reason != "eof" {
			_ = r.record("bolt", "denied:"+reason)
			tell(boltRefusals[reason].code, boltRefusals[reason].message)
		}
		return
	}
	if r.admit(r.ctx, peer, "bolt") != nil {
		return
	}
	defer func() { _ = r.record("bolt", "terminal") }()
	if !r.config.Deadline.After(time.Now()) {
		tell(boltEnded, sessionEndedMessage)
		return
	}
	proof, expiry, e := readProof(l.Upstream, r.config.Deadline)
	if e != nil {
		tell(boltNotVerified, notVerifiedMessage)
		return
	}
	login, e := opening.withProof(proof)
	if e != nil {
		tell(boltProtocol, genericRefusalMessage)
		return
	}
	if r.pair.check(r.ctx, peer) != nil {
		return
	}
	dialCtx, cancelDial := context.WithTimeout(r.ctx, r.handshake())
	up, e := dialUpstream(dialCtx, l.Upstream)
	cancelDial()
	r.upstreams.dialed(r.log, l.Upstream.Address, e)
	if e != nil {
		tell(boltUnavailable, unreachableMessage)
		return
	}
	defer func() { _ = up.Close() }()
	stop := context.AfterFunc(r.ctx, func() { _ = up.Close() })
	defer stop()
	_ = up.SetDeadline(minTime(expiry, time.Now().Add(r.handshake())))
	attestation, agent, e := r.attest(peer)
	if e != nil {
		return
	}
	end := &ending{}
	stopWatch := r.watchPeer(peer, agent, func() { end.set(endWithdrawn); _ = conn.Close(); _ = up.Close() })
	defer stopWatch()
	// The preamble lines and the opening go in one write: the broker reads
	// the lines, sees the Bolt magic, and answers the version.
	var out []byte
	if attestation != "" {
		out = append(out, "GHATTS1 "+attestation+"\n"...)
	}
	if session := readSession(r.log, l.Upstream); session != "" {
		out = append(out, "GHSESS1 "+session+"\n"...)
	}
	out = append(out, handshake[:]...)
	if _, e = up.Write(out); e != nil {
		tell(boltUnavailable, unreachableMessage)
		return
	}
	upIn := bufio.NewReader(up)
	agreed, e := bolt.ReadVersion(upIn)
	if e != nil || agreed != version {
		_ = r.record("bolt", "refused:version")
		tell(boltUnavailable, "Gatehouse could not agree a Bolt version with this client; retry")
		return
	}
	if _, e = up.Write(login); e != nil {
		tell(boltUnavailable, unreachableMessage)
		return
	}
	if r.pair.check(r.ctx, peer) != nil {
		return
	}
	// The broker answers each opening message. Hold the answers until every
	// one succeeded, so the established row is written before the worker can
	// use the session; a failure is passed on as the broker worded it.
	var answers []byte
	for i := range opening.messages {
		raw, e := bolt.ReadRaw(upIn, maxBoltResponseBytes)
		if e != nil {
			tell(boltUnavailable, unreachableMessage)
			return
		}
		tag, e := bolt.Tag(raw)
		if e != nil {
			tell(boltProtocol, genericRefusalMessage)
			return
		}
		if tag == bolt.TagSuccess && i != opening.login {
			continue // the HELLO the relay already answered
		}
		answers = append(answers, bolt.Frame(raw)...)
		if tag != bolt.TagSuccess {
			_ = r.record("bolt", "refused:"+boltRefusalReason(raw))
			_, _ = conn.Write(answers)
			return
		}
	}
	if !time.Now().Before(expiry) {
		tell(boltEnded, sessionEndedMessage)
		return
	}
	if r.pair.check(r.ctx, peer) != nil || r.record("bolt", "established") != nil {
		return
	}
	if _, e = conn.Write(answers); e != nil {
		return
	}
	started := time.Now()
	defer func() { r.logClose("bolt", peer, agent, l.Upstream.Address, principal, started, end) }()
	copyTunnel(r.ctx, conn, in, up, upIn, expiry, end)
}

// boltOpening is the client's HELLO and, from Bolt 5.1, its LOGON, as read.
type boltOpening struct {
	messages []*bolt.Structure
	// login is the index of the message that carries the credentials.
	login int
}

// withProof encodes the opening with the placeholder replaced by proof. The
// login carries exactly the scheme, the user name and the proof.
func (o boltOpening) withProof(proof string) ([]byte, error) {
	var out []byte
	for i, m := range o.messages {
		fields := m.Fields
		if i == o.login {
			extra, _ := m.Map(0)
			rewritten := make(map[string]any, len(extra))
			for key, value := range extra {
				if !boltAuthKeys[key] {
					rewritten[key] = value
				}
			}
			rewritten["scheme"], rewritten["principal"], rewritten["credentials"] = "basic", extra["principal"], proof
			fields = append([]any{rewritten}, m.Fields[1:]...)
		}
		raw, e := bolt.Encode(m.Tag, fields...)
		if e != nil {
			return nil, e
		}
		out = append(out, bolt.Frame(raw)...)
	}
	return out, nil
}

// boltAuthKeys are the HELLO and LOGON keys that carry credentials. Only the
// relay's scheme, user name and proof reach the broker.
var boltAuthKeys = map[string]bool{"scheme": true, "principal": true, "credentials": true, "realm": true, "parameters": true}

// readBoltLogin reads the client's opening for version: HELLO with the login
// below Bolt 5.1; HELLO without one, answered on out, then LOGON, from 5.1.
// It returns the opening and the user name, or the reason it was refused
// ("eof" when the client left without sending one).
func readBoltLogin(in io.Reader, out io.Writer, version bolt.Version, route func(string) bool, placeholder string) (boltOpening, string, string) {
	var o boltOpening
	split := version.AtLeast(5, 1)
	want := []byte{bolt.TagHello}
	if split {
		want = append(want, bolt.TagLogon)
	}
	for i, tag := range want {
		raw, e := bolt.ReadRaw(in, maxBoltAuthBytes)
		if e != nil {
			if errors.Is(e, io.EOF) && i == 0 {
				return o, "", "eof"
			}
			return o, "", "bad-opening"
		}
		m, e := bolt.Decode(raw)
		if e != nil || m.Tag != tag || len(m.Fields) == 0 {
			return o, "", "bad-opening"
		}
		extra, e := m.Map(0)
		if e != nil || extra == nil {
			return o, "", "bad-opening"
		}
		o.messages = append(o.messages, m)
		if split && tag == bolt.TagHello {
			// From 5.1 HELLO carries no login; one that does is refused
			// rather than forwarded with a credential the relay did not set.
			for key := range boltAuthKeys {
				if _, present := extra[key]; present {
					return o, "", "bad-opening"
				}
			}
			if bolt.WriteRaw(out, boltHelloAnswer) != nil {
				return o, "", "eof"
			}
			continue
		}
		o.login = i
		scheme, _ := extra["scheme"].(string)
		principal, _ := extra["principal"].(string)
		credentials, _ := extra["credentials"].(string)
		if scheme != "basic" || credentials != placeholder {
			return o, "", "placeholder"
		}
		if !route(principal) {
			return o, "", "no-entry"
		}
		return o, principal, ""
	}
	return o, "", "bad-opening"
}

// boltHelloAnswer is the relay's answer to a HELLO from Bolt 5.1: the same
// server agent the broker names.
var boltHelloAnswer = bolt.Success(map[string]any{"server": "Neo4j/5.2.0 compatible graph database server - Memgraph through Gatehouse", "connection_id": "gatehouse"})

// boltRefusals are the relay's fixed words for a login it refuses before the
// broker is dialed.
var boltRefusals = map[string]refusal{
	"bad-opening": {boltProtocol, "Gatehouse: send HELLO (and LOGON from Bolt 5.1) with basic auth: the catalog entry's name as the user and the placeholder password"},
	"placeholder": {boltUnauthorized, "Gatehouse: wrong placeholder password for this port; use basic auth with the placeholder password"},
	"no-entry":    {boltUnauthorized, "Gatehouse: this user name is not a Gatehouse catalog entry for your pool; use the entry's name as the user"},
}

// boltRefusalReason is a broker refusal's reason for the relay's audit: the
// broker's reason code, or "unknown".
func boltRefusalReason(raw []byte) string {
	m, e := bolt.Decode(raw)
	if e != nil {
		return "unknown"
	}
	metadata, e := m.Map(0)
	if e != nil {
		return "unknown"
	}
	if reason, _ := metadata[boltReasonKey].(string); brokerReason.MatchString(reason) {
		return reason
	}
	return "unknown"
}

// boltReasonKey is the FAILURE metadata key in which the broker names its
// reason for a refusal.
const boltReasonKey = "gatehouse_reason"
