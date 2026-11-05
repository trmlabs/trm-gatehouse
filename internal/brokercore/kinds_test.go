package brokercore

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
)

func TestKindedConnReadsItsPrefixFirst(t *testing.T) {
	client, server := net.Pipe()
	go func() { _, _ = io.WriteString(client, "rest"); _ = client.Close() }()
	c := &KindedConn{Conn: server, Kinds: []string{KindProxyAttested}, Prefix: strings.NewReader("head-")}
	b, err := io.ReadAll(c)
	if err != nil || string(b) != "head-rest" {
		t.Fatalf("read %q %v", b, err)
	}
	if !KindAdmitted(ConnKinds(c), KindProxyAttested) || KindAdmitted(ConnKinds(c), KindPodToken) {
		t.Fatal("tagged connection admits the wrong kinds")
	}
	if KindAdmitted(ConnKinds(server), KindProxyAttested) || !KindAdmitted(ConnKinds(server), KindPodToken) || !KindAdmitted(ConnKinds(nil), "") {
		t.Fatal("untagged connection admits the wrong kinds")
	}
}

// An unfinished check is still a refusal to every caller; only DenialUnavailable tells it apart, and wrapping or a peer keeps the mark.
func TestUnavailableIsARefusalMarkedRetryable(t *testing.T) {
	err := Unavailable("store_unavailable")
	if !errors.Is(err, ErrInvalidSession) || DenialReason(err) != "store_unavailable" || !DenialUnavailable(err) {
		t.Fatalf("unavailable refusal %v", err)
	}
	if wrapped := fmt.Errorf("resolve: %w", err); !DenialUnavailable(wrapped) || !errors.Is(wrapped, ErrInvalidSession) {
		t.Fatal("wrapping lost the mark or the refusal")
	}
	peer := netip.MustParseAddr("10.0.0.1")
	if !DenialUnavailable(WithPeer(err, peer)) {
		t.Fatal("WithPeer lost the mark")
	}
	keyed := WithPeer(DeniedKey("token_signature", "k1"), peer)
	if DenialUnavailable(keyed) || DenialKey(keyed).Peer != "10.0.0.1" {
		t.Fatal("a key refusal became retryable or lost its peer")
	}
	for _, lasting := range []error{nil, Denied("pod_unreadable"), ErrInvalidSession, ErrVaultAccessDenied} {
		if DenialUnavailable(lasting) {
			t.Fatalf("%v marked retryable", lasting)
		}
	}
}
