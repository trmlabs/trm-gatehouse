package isolation

import (
	"net"
	"runtime"
)

// HostBindIP returns the IP the forwarder binds so host.docker.internal resolves to a listener we own.
// On Docker Desktop it binds 0.0.0.0 since the routed interface varies; a vault-scoped session token is still required.
func HostBindIP(n *Network) net.IP {
	if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
		return net.IPv4(0, 0, 0, 0)
	}
	if n == nil || n.GatewayIP == nil {
		return nil
	}
	return n.GatewayIP
}
