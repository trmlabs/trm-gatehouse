package brokercore

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"sync"
)

// Identity kinds a verified scope carries; each listener admits only the kinds it was opened for.
const (
	// KindPodToken: a Pod's projected token, checked against the live Pod and source address.
	KindPodToken = "pod-token"
	// KindServiceToken: a long-lived service Pod's projected token, checked against the live Pod; no default listener admits it, each must opt in.
	KindServiceToken = "service-token"
	// KindTokenReview: a projected token checked by online TokenReview.
	KindTokenReview = "token-review"
	// KindProxyAttested: a shared proxy's token plus its attestation of the agent Pod.
	KindProxyAttested = "proxy-attested"
	// KindStaticToken: a per-agent bearer token checked against its catalog hash; only the static-token listener admits it, and nothing else.
	KindStaticToken = "static-token"
)

// defaultKinds are what an untagged listener admits; the empty kind is a legacy session token.
var defaultKinds = []string{"", KindPodToken, KindTokenReview}

// KindedConn is a connection from a listener that admits only Kinds; Prefix holds bytes a dispatcher already consumed.
type KindedConn struct {
	net.Conn
	Kinds  []string
	Prefix io.Reader
	// Closed, when set, runs once when the connection is closed.
	Closed    func()
	closeOnce sync.Once
}

func (c *KindedConn) Close() error {
	err := c.Conn.Close()
	if c.Closed != nil {
		c.closeOnce.Do(c.Closed)
	}
	return err
}

func (c *KindedConn) Read(b []byte) (int, error) {
	if c.Prefix != nil {
		n, err := c.Prefix.Read(b)
		if n > 0 || err != io.EOF {
			return n, err
		}
		c.Prefix = nil
	}
	return c.Conn.Read(b)
}

// ConnKinds returns the identity kinds the connection's listener admits.
func ConnKinds(c net.Conn) []string {
	if k, ok := c.(*KindedConn); ok {
		return k.Kinds
	}
	return defaultKinds
}

// KindAdmitted reports whether a scope of this kind may use the listener.
func KindAdmitted(kinds []string, kind string) bool { return slices.Contains(kinds, kind) }

// deniedError is an identity refusal that is ErrInvalidSession to callers; the reason reaches only the broker's log.
type deniedError struct {
	reason      string
	key         *KeyDenial
	unavailable bool // the broker could not complete the check, so the same proof may pass on retry
}

// KeyDenial records a signing-key refusal: a safe key ID and the peer address, never part of the token.
type KeyDenial struct {
	// Kid is "invalid" when not a plain identifier, then KidSHA256 is 12 hex characters of its SHA-256; the kid is attacker-chosen so is never recorded raw.
	Kid       string
	KidSHA256 string
	Peer      string
}

var plainKid = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

func (e deniedError) Error() string {
	s := "workload not admitted: " + e.reason
	if k := e.key; k != nil {
		s += " kid=" + k.Kid
		if k.KidSHA256 != "" {
			s += " kid_sha256=" + k.KidSHA256
		}
		if k.Peer != "" {
			s += " peer=" + k.Peer
		}
	}
	return s
}

func (e deniedError) Is(target error) bool { return target == ErrInvalidSession }

// Denied returns ErrInvalidSession carrying a fixed reason code.
func Denied(reason string) error { return deniedError{reason: reason} }

// Unavailable is Denied for a check the broker could not complete, such as a store or Kubernetes API that did not answer.
func Unavailable(reason string) error { return deniedError{reason: reason, unavailable: true} }

// DenialUnavailable reports whether err is a refusal made because the broker could not complete a check.
func DenialUnavailable(err error) bool {
	var d deniedError
	return errors.As(err, &d) && d.unavailable
}

// DeniedKey is Denied for a signing-key refusal, naming the claimed key ID in safe form.
func DeniedKey(reason, kid string) error {
	k := &KeyDenial{Kid: kid}
	if !plainKid.MatchString(kid) {
		sum := sha256.Sum256([]byte(kid))
		k.Kid, k.KidSHA256 = "invalid", hex.EncodeToString(sum[:])[:12]
	}
	return deniedError{reason: reason, key: k}
}

// WithPeer adds the connection's peer address to a signing-key refusal; any
// other error is returned unchanged.
func WithPeer(err error, peer netip.Addr) error {
	var d deniedError
	if !errors.As(err, &d) || d.key == nil || !peer.IsValid() {
		return err
	}
	k := *d.key
	k.Peer = peer.Unmap().String()
	d.key = &k
	return d
}

// DenialKey returns a signing-key refusal's key ID and peer, or nil.
func DenialKey(err error) *KeyDenial {
	var d deniedError
	if errors.As(err, &d) && d.key != nil {
		k := *d.key
		return &k
	}
	return nil
}

// DenialReason returns the reason code of a refusal, or "".
func DenialReason(err error) string {
	var d deniedError
	if errors.As(err, &d) {
		return d.reason
	}
	return ""
}
