package mitm

import (
	"net/http"
	"testing"
)

// TestIsLoopbackPeer_CoversForwarderLaundering pins that container CONNECTs arrive with a loopback RemoteAddr, so they skip TierAuth rate limiting.
func TestIsLoopbackPeer_CoversForwarderLaundering(t *testing.T) {
	// RemoteAddr shape matches what net/http reports after Hijack on
	// a loopback-dialed connection: "127.0.0.1:<ephemeral>".
	r := &http.Request{RemoteAddr: "127.0.0.1:48293"}
	if !isLoopbackPeer(r) {
		t.Fatal("forwarder-laundered loopback conn must be recognized as loopback peer")
	}
}
