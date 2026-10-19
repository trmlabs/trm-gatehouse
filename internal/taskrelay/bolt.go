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

// BoltConfig is one graph database (a catalog entry of kind memgraph) on a
// local Bolt port. The worker connects with a stock driver to bolt://Listen
// (or neo4j://) and signs in as User with Placeholder as its password; the
// relay then signs in to the broker as Database, the catalog entry, with the
// worker's identity proof. The worker never holds the proof or the
// database's login.
type BoltConfig struct {
	Listen      string         `json:"listen"`
	Upstream    UpstreamConfig `json:"upstream"`
	Database    string         `json:"database"`
	User        string         `json:"user"`
	Placeholder string         `json:"placeholder"`
}

// maxBoltSignInBytes bounds the worker's HELLO and LOGON, read before
// admission. A sign-in is a few hundred bytes.
const maxBoltSignInBytes = 16 << 10

const boltRelayAgent = "Neo4j/5.2.0 compatible graph database server - Memgraph through Gatehouse"

// boltFailure is a FAILURE the relay authors. Drivers retry a code whose
// second part is TransientError.
func boltFailure(code, message string) []byte {
	return bolt.Frame(bolt.Failure(code, message))
}

var (
	boltUnreachable = boltFailure("Gatehouse.TransientError.General.Unavailable", unreachableMessage)
	boltNotVerified = boltFailure("Gatehouse.TransientError.Security.NotVerified", notVerifiedMessage)
	boltEnded       = boltFailure("Gatehouse.TransientError.General.SessionEnded", sessionEndedMessage)
	boltPlaceholder = boltFailure("Gatehouse.ClientError.Security.Unauthorized", "Gatehouse: wrong user or placeholder password for this binding")
	boltRefused     = boltFailure("Gatehouse.TransientError.General.Refused", genericRefusalMessage)
)

// bolt serves one worker connection on a Bolt binding. As for PostgreSQL,
// nothing reaches the broker, and no proof is read, until everything the
// worker controls has been checked: the peer, the handshake and the
// placeholder sign-in. The relay answers the handshake and HELLO itself, from
// the versions the broker also speaks, then signs in to the broker with the
// same version and relays the broker's answer. After that it copies bytes:
// the broker holds the session to reads and authors its own refusals in
// fixed words, so its FAILURE messages pass through.
func (r *relay) bolt(conn net.Conn, binding BoltConfig) {
	_ = conn.SetDeadline(minTime(r.config.Deadline, time.Now().Add(r.handshake())))
	peer := conn.RemoteAddr().String()
	if !r.pair.peerMatches(peer) {
		if r.foreignPeer.CompareAndSwap(false, true) {
			_ = r.record("bolt", "denied:peer")
		}
		return
	}
	in := bufio.NewReader(conn)
	hs, e := bolt.ReadHandshake(in, false)
	if e != nil {
		if !errors.Is(e, io.EOF) {
			_ = r.record("bolt", "denied:bad-handshake")
		}
		return
	}
	version, ok := hs.Choose(bolt.Supported)
	if !ok {
		_, _ = conn.Write([]byte{0, 0, 0, 0})
		_ = r.record("bolt", "denied:version")
		return
	}
	answer := version.Bytes()
	if _, e = conn.Write(answer[:]); e != nil {
		return
	}
	hello, auth, e := r.boltSignIn(conn, in, version)
	if e != nil {
		_ = r.record("bolt", "denied:bad-startup")
		return
	}
	if scheme, _ := auth["scheme"].(string); scheme != "basic" || auth["principal"] != binding.User || auth["credentials"] != binding.Placeholder {
		_ = r.record("bolt", "denied:placeholder")
		_, _ = conn.Write(boltPlaceholder)
		return
	}
	// Everything the worker can influence has been validated. Admit: live
	// pair check, then the durable "admitted" row, before any proof is read.
	if r.admit(r.ctx, peer, "bolt") != nil {
		return
	}
	defer func() { _ = r.record("bolt", "terminal") }()
	tell := func(frame []byte) { _, _ = conn.Write(frame) }
	if !r.config.Deadline.After(time.Now()) {
		tell(boltEnded)
		return
	}
	proof, expiry, e := readProof(binding.Upstream, r.config.Deadline)
	if e != nil {
		tell(boltNotVerified)
		return
	}
	if r.pair.check(r.ctx, peer) != nil {
		return
	}
	dialCtx, cancelDial := context.WithTimeout(r.ctx, r.handshake())
	up, e := dialUpstream(dialCtx, binding.Upstream)
	cancelDial()
	r.upstreams.dialed(r.log, binding.Upstream.Address, e)
	if e != nil {
		tell(boltUnreachable)
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
	var preamble []byte
	if attestation != "" {
		preamble = append(preamble, "GHATTS1 "+attestation+"\n"...)
	}
	if session := readSession(binding.Upstream); session != "" {
		preamble = append(preamble, "GHSESS1 "+session+"\n"...)
	}
	signIn := map[string]any{"scheme": "basic", "principal": binding.Database, "credentials": proof}
	msgs, e := brokerSignIn(version, hello, signIn)
	if e != nil {
		tell(boltRefused)
		return
	}
	if _, e = up.Write(append(append(preamble, bolt.ClientHandshake(version)...), msgs...)); e != nil {
		tell(boltUnreachable)
		return
	}
	upIn := bufio.NewReader(up)
	got, e := bolt.ReadVersion(upIn)
	if e != nil || got != version {
		tell(boltRefused)
		return
	}
	// On 5.1 and later the broker answers HELLO, which the worker already
	// had from the relay, then LOGON; before 5.1, HELLO alone.
	if version.AtLeast(5, 1) {
		raw, e := bolt.ReadRaw(upIn, maxBoltSignInBytes)
		if tag, _ := bolt.Tag(raw); e != nil || tag != bolt.TagSuccess {
			r.boltRefusal(conn, raw)
			return
		}
	}
	raw, e := bolt.ReadRaw(upIn, maxBoltSignInBytes)
	if e != nil {
		tell(boltRefused)
		return
	}
	if tag, _ := bolt.Tag(raw); tag != bolt.TagSuccess {
		r.boltRefusal(conn, raw)
		return
	}
	if r.pair.check(r.ctx, peer) != nil || r.record("bolt", "established") != nil {
		return
	}
	if !time.Now().Before(expiry) {
		tell(boltEnded)
		return
	}
	if _, e = conn.Write(bolt.Frame(raw)); e != nil {
		return
	}
	started := time.Now()
	defer func() { r.logClose("bolt", peer, agent, binding.Upstream.Address, binding.Database, started, end) }()
	copyTunnel(r.ctx, conn, in, up, upIn, expiry, end)
}

// boltSignIn reads the worker's HELLO, and its LOGON on 5.1 and later (after
// answering HELLO, as a server must), and returns the HELLO's extra and the
// credentials map.
func (r *relay) boltSignIn(conn net.Conn, in *bufio.Reader, v bolt.Version) (map[string]any, map[string]any, error) {
	raw, e := bolt.ReadRaw(in, maxBoltSignInBytes)
	if e != nil {
		return nil, nil, e
	}
	msg, e := bolt.Decode(raw)
	if e != nil || msg.Tag != bolt.TagHello {
		return nil, nil, errDenied
	}
	hello, e := msg.Map(0)
	if e != nil {
		return nil, nil, errDenied
	}
	if !v.AtLeast(5, 1) {
		return hello, hello, nil
	}
	if _, has := hello["credentials"]; has {
		return nil, nil, errDenied
	}
	if _, e = conn.Write(bolt.Frame(bolt.Success(map[string]any{"server": boltRelayAgent, "connection_id": "gatehouse"}))); e != nil {
		return nil, nil, e
	}
	if raw, e = bolt.ReadRaw(in, maxBoltSignInBytes); e != nil {
		return nil, nil, e
	}
	if msg, e = bolt.Decode(raw); e != nil || msg.Tag != bolt.TagLogon {
		return nil, nil, errDenied
	}
	auth, e := msg.Map(0)
	if e != nil || auth == nil {
		return nil, nil, errDenied
	}
	return hello, auth, nil
}

// brokerSignIn builds the relay's own HELLO (and LOGON) to the broker. Of the
// worker's HELLO it keeps only its user agent and the address it dialed,
// which the broker names in its ROUTE answers.
func brokerSignIn(v bolt.Version, workerHello, auth map[string]any) ([]byte, error) {
	hello := map[string]any{"user_agent": "gatehouse-relay/1"}
	if agent, ok := workerHello["user_agent"].(string); ok && len(agent) <= 256 {
		hello["user_agent"] = agent
	}
	if routing, ok := workerHello["routing"].(map[string]any); ok {
		if address, ok := routing["address"].(string); ok && validAddress(address) {
			hello["routing"] = map[string]any{"address": address}
		}
	}
	var out []byte
	if v.AtLeast(5, 1) {
		h, e := bolt.Encode(bolt.TagHello, hello)
		if e != nil {
			return nil, e
		}
		l, e := bolt.Encode(bolt.TagLogon, auth)
		if e != nil {
			return nil, e
		}
		return append(append(out, bolt.Frame(h)...), bolt.Frame(l)...), nil
	}
	for k, value := range auth {
		hello[k] = value
	}
	h, e := bolt.Encode(bolt.TagHello, hello)
	if e != nil {
		return nil, e
	}
	return bolt.Frame(h), nil
}

// boltRefusal relays the broker's FAILURE for a refused sign-in. The broker
// authors it in fixed words; anything else is the relay's generic refusal.
func (r *relay) boltRefusal(conn net.Conn, raw []byte) {
	msg, e := bolt.Decode(raw)
	if e != nil || msg.Tag != bolt.TagFailure {
		_, _ = conn.Write(boltRefused)
		_ = r.record("bolt", "refused:unknown")
		return
	}
	meta, _ := msg.Map(0)
	code, _ := meta["code"].(string)
	reason := "unknown"
	if len(code) <= 128 && validBoltCode(code) {
		reason = code
	}
	_ = r.record("bolt", "refused:"+reason)
	_, _ = conn.Write(bolt.Frame(raw))
}

// validBoltCode is a Gatehouse refusal code: dotted words, safe to journal.
func validBoltCode(code string) bool {
	if len(code) < 10 || code[:10] != "Gatehouse." {
		return false
	}
	for i := 0; i < len(code); i++ {
		c := code[i]
		if c != '.' && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}
