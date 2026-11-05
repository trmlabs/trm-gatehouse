package server

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
)

// The static-token listener carries HTTP CONNECT only and tags connections so the HTTP proxy admits them only as a static agent token; no listener admits both this and proxy-attested identities.

// EnableStaticToken opens the listener on 127.0.0.1 behind a same-Pod TLS front that sends a PROXY header. It needs the credential proxy.
func (s *Server) EnableStaticToken(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host != "127.0.0.1" {
		return errors.New("the static-token listener binds 127.0.0.1 only, behind its TLS front")
	}
	if addr == s.crossClusterAddr {
		return errors.New("the static-token listener needs its own port, apart from the cross-cluster listener")
	}
	s.staticTokenAddr = addr
	return nil
}

var staticTokenKinds = []string{brokercore.KindStaticToken}

var errStaticUnrouted = errors.New("static-token connection is not an HTTP CONNECT")

func routeStaticToken(c net.Conn) (net.Conn, error) {
	_ = c.SetReadDeadline(time.Now().Add(crossClusterRouteTimeout))
	defer func() { _ = c.SetReadDeadline(time.Time{}) }()
	var seen bytes.Buffer
	if _, err := brokercore.ReadProxyV1(io.TeeReader(c, &seen), c.RemoteAddr()); err != nil {
		return nil, err
	}
	head := make([]byte, 8)
	if _, err := io.ReadFull(c, head); err != nil {
		return nil, err
	}
	seen.Write(head)
	if string(head) != "CONNECT " {
		return nil, errStaticUnrouted
	}
	return &brokercore.KindedConn{Conn: c, Kinds: staticTokenKinds, Prefix: bytes.NewReader(seen.Bytes())}, nil
}

func serveStaticToken(l net.Listener, httpLn *mergedListener, logger *slog.Logger) error {
	return acceptLoop(l, "static-token", logger, func(c net.Conn) {
		go func() {
			routed, err := routeStaticToken(c)
			if err != nil {
				_ = c.Close()
				return
			}
			httpLn.inject(routed)
		}()
	})
}
