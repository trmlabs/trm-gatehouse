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

// BoltListenerConfig is one Bolt port routed by login user name (the catalog entry) with Placeholder as password.
// Routes "broker" forwards any well-formed name and leaves the decision to the broker's catalog.
type BoltListenerConfig struct {
	Listen      string         `json:"listen"`
	Upstream    UpstreamConfig `json:"upstream"`
	Entries     []string       `json:"entries,omitempty"`
	Routes      string         `json:"routes,omitempty"`
	Placeholder string         `json:"placeholder"`
}

const maxBoltListeners = 4

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

const maxBoltAuthBytes = 16 << 10

const maxBoltResponseBytes = 64 << 10

// Drivers retry a TransientError and not a ClientError (second dotted part).
const (
	boltUnauthorized = "Gatehouse.ClientError.Security.Unauthorized"
	boltProtocol     = "Gatehouse.ClientError.Request.Invalid"
	boltUnavailable  = "Gatehouse.TransientError.General.Unavailable"
	boltNotVerified  = "Gatehouse.TransientError.Security.NotVerified"
	boltEnded        = "Gatehouse.TransientError.General.SessionEnded"
)

// bolt relays one connection: validates the login against routes and the placeholder, then swaps in the proof; the worker never sees it.
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
	// The preamble lines and the opening go in one write so the broker sees the Bolt magic after the lines.
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
	// Hold the answers until all succeed so the established row precedes any worker use.
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

type boltOpening struct {
	messages []*bolt.Structure
	login    int
}

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

// Only the relay's own scheme, user name and proof reach the broker.
var boltAuthKeys = map[string]bool{"scheme": true, "principal": true, "credentials": true, "realm": true, "parameters": true}

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
			// From 5.1 HELLO carries no login; one that does is refused, not forwarded with a credential the relay did not set.
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

var boltHelloAnswer = bolt.Success(map[string]any{"server": "Neo4j/5.2.0 compatible graph database server - Memgraph through Gatehouse", "connection_id": "gatehouse"})

var boltRefusals = map[string]refusal{
	"bad-opening": {boltProtocol, "Gatehouse: send HELLO (and LOGON from Bolt 5.1) with basic auth: the catalog entry's name as the user and the placeholder password"},
	"placeholder": {boltUnauthorized, "Gatehouse: wrong placeholder password for this port; use basic auth with the placeholder password"},
	"no-entry":    {boltUnauthorized, "Gatehouse: this user name is not a Gatehouse catalog entry for your pool; use the entry's name as the user"},
}

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

const boltReasonKey = "gatehouse_reason"
