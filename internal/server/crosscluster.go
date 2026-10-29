package server

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
)

// The cross-cluster listener serves agents in another cluster, through the
// shared proxy there and a private link. It admits only proxy-attested
// identities, and carries both protocols on one port: after the TLS front's
// PROXY header, a shared proxy's PostgreSQL stream opens with its
// attestation preamble and its HTTP stream with CONNECT. Every other start is
// closed. Routed connections join the existing HTTP proxy and PostgreSQL
// broker listeners, tagged so those admit them only as proxy-attested.

// EnableCrossCluster opens the cross-cluster listener on 127.0.0.1, behind a
// TLS front in the same Pod that sends a PROXY header. It needs the
// credential proxy.
func (s *Server) EnableCrossCluster(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host != "127.0.0.1" {
		return errors.New("the cross-cluster listener binds 127.0.0.1 only, behind its TLS front")
	}
	s.crossClusterAddr = addr
	return nil
}

var crossClusterKinds = []string{brokercore.KindProxyAttested}

// CrossClusterLimits bounds the cross-cluster listener by what a connection is doing,
// so a flood of one kind cannot starve another; a zero field takes its default.
type CrossClusterLimits struct {
	Pending     int // accepted connections not yet routed
	Open        int // routed HTTP and PostgreSQL connections
	Certificate int // routed certificate requests, counted apart from Open so renewals still get in
}

const (
	defaultCrossClusterPending     = 10000
	defaultCrossClusterOpen        = 10000
	defaultCrossClusterCertificate = 256
)

func (l CrossClusterLimits) withDefaults() CrossClusterLimits {
	if l.Pending <= 0 {
		l.Pending = defaultCrossClusterPending
	}
	if l.Open <= 0 {
		l.Open = defaultCrossClusterOpen
	}
	if l.Certificate <= 0 {
		l.Certificate = defaultCrossClusterCertificate
	}
	return l
}

// SetCrossClusterLimits sets the cross-cluster listener's limits; call it before Start.
func (s *Server) SetCrossClusterLimits(l CrossClusterLimits) error {
	if l.Pending < 0 || l.Open < 0 || l.Certificate < 0 {
		return errors.New("cross-cluster limits must not be negative")
	}
	s.crossClusterLimits = l
	return nil
}

// slots is a counting limit that refuses instead of waiting.
type slots chan struct{}

func (s slots) take() bool {
	select {
	case s <- struct{}{}:
		return true
	default:
		return false
	}
}

func (s slots) release() { <-s }

// refusals logs the connections a limit turns away, at most once a second.
type refusals struct {
	logger *slog.Logger
	last   atomic.Int64
	count  atomic.Int64
}

func (r *refusals) refuse(limit string) {
	n := r.count.Add(1)
	now := time.Now().UnixNano()
	if last := r.last.Load(); now-last >= int64(time.Second) && r.last.CompareAndSwap(last, now) {
		r.logger.Warn("cross-cluster connection refused at its limit", slog.String("limit", limit), slog.Int64("refused_total", n))
	}
}

const crossClusterRouteTimeout = 5 * time.Second

// mergedListener yields the connections of an existing listener plus those a
// dispatcher injects. Closing it closes the existing listener and stops the
// injections.
type mergedListener struct {
	net.Listener
	injected chan net.Conn
	accepted chan acceptResult
	done     chan struct{}
	once     sync.Once
}

type acceptResult struct {
	conn net.Conn
	err  error
}

func newMergedListener(l net.Listener) *mergedListener {
	m := &mergedListener{Listener: l, injected: make(chan net.Conn), accepted: make(chan acceptResult), done: make(chan struct{})}
	go func() {
		for {
			c, err := l.Accept()
			select {
			case m.accepted <- acceptResult{c, err}:
			case <-m.done:
				if c != nil {
					_ = c.Close()
				}
				return
			}
			if err != nil {
				return
			}
		}
	}()
	return m
}

func (m *mergedListener) Accept() (net.Conn, error) {
	select {
	case r := <-m.accepted:
		return r.conn, r.err
	case c := <-m.injected:
		return c, nil
	case <-m.done:
		return nil, net.ErrClosed
	}
}

func (m *mergedListener) Close() error {
	m.once.Do(func() { close(m.done) })
	return m.Listener.Close()
}

// inject hands a routed connection to the listener's server, or closes it
// when the listener has closed.
func (m *mergedListener) inject(c net.Conn) {
	select {
	case m.injected <- c:
	case <-m.done:
		_ = c.Close()
	}
}

var errUnrouted = errors.New("cross-cluster connection is neither attested HTTP nor PostgreSQL")

// The places a cross-cluster connection can go.
const (
	routeHTTP        = "http"
	routePostgres    = "postgres"
	routeCertificate = "certificate"
)

// routeCrossCluster reads the TLS front's PROXY header and the first eight
// bytes after it, without consuming them for the server that gets the
// connection, and says where it goes. A shared proxy's request for its
// serving certificate is an HTTP POST; that server gets the bytes after the
// PROXY header, with the proxy's address as the connection's remote address.
func routeCrossCluster(c net.Conn) (net.Conn, string, error) {
	_ = c.SetReadDeadline(time.Now().Add(crossClusterRouteTimeout))
	defer func() { _ = c.SetReadDeadline(time.Time{}) }()
	var seen bytes.Buffer
	peer, err := brokercore.ReadProxyV1(io.TeeReader(c, &seen), c.RemoteAddr())
	if err != nil {
		return nil, "", err
	}
	head := make([]byte, 8)
	if _, err := io.ReadFull(c, head); err != nil {
		return nil, "", err
	}
	seen.Write(head)
	routed := &brokercore.KindedConn{Conn: c, Kinds: crossClusterKinds, Prefix: bytes.NewReader(seen.Bytes())}
	switch string(head) {
	case "GHATTS1 ":
		return routed, routePostgres, nil
	case "CONNECT ":
		return routed, routeHTTP, nil
	case "POST /v1":
		return &peerConn{Conn: c, prefix: bytes.NewReader(head), peer: &net.TCPAddr{IP: peer.AsSlice()}}, routeCertificate, nil
	}
	return nil, "", errUnrouted
}

// peerConn replays the bytes routing read and reports the address the TLS
// front named as its remote address.
type peerConn struct {
	net.Conn
	prefix io.Reader
	peer   net.Addr
	closed func() // runs once on Close, or nil
	once   sync.Once
}

func (c *peerConn) Close() error {
	err := c.Conn.Close()
	if c.closed != nil {
		c.once.Do(c.closed)
	}
	return err
}

func (c *peerConn) Read(b []byte) (int, error) {
	if c.prefix != nil {
		n, err := c.prefix.Read(b)
		if n > 0 || err != io.EOF {
			return n, err
		}
		c.prefix = nil
	}
	return c.Conn.Read(b)
}

func (c *peerConn) RemoteAddr() net.Addr { return c.peer }

// serveCrossCluster routes each connection of l to the PostgreSQL broker's,
// the HTTP proxy's or the proxy-certificate listener; any may be nil, and its
// traffic is then closed. It returns when l closes, or with the error of an
// accept that will not recover (see acceptLoop).
func serveCrossCluster(l net.Listener, httpLn, pgLn *mergedListener, certLn *injectedListener, limits CrossClusterLimits, logger *slog.Logger) error {
	pending, open, certificate := make(slots, limits.Pending), make(slots, limits.Open), make(slots, limits.Certificate)
	refused := &refusals{logger: logger}
	return acceptLoop(l, "cross-cluster", logger, func(c net.Conn) {
		if !pending.take() {
			refused.refuse("pending")
			_ = c.Close()
			return
		}
		go func() {
			routed, route, err := routeCrossCluster(c)
			pending.release()
			if err != nil {
				_ = c.Close()
				return
			}
			class, name := open, "open"
			if route == routeCertificate {
				class, name = certificate, "certificate"
			}
			if !class.take() {
				refused.refuse(name)
				_ = c.Close()
				return
			}
			routed = onClose(routed, class.release)
			switch {
			case route == routePostgres && pgLn != nil:
				pgLn.inject(routed)
			case route == routeHTTP && httpLn != nil:
				httpLn.inject(routed)
			case route == routeCertificate && certLn != nil:
				certLn.inject(routed)
			default:
				_ = routed.Close()
			}
		}()
	})
}

// onClose makes c run release once when it is closed.
func onClose(c net.Conn, release func()) net.Conn {
	switch v := c.(type) {
	case *brokercore.KindedConn:
		v.Closed = release
	case *peerConn:
		v.closed = release
	}
	return c
}

// injectedListener yields only the connections a dispatcher injects: the
// proxy-certificate server has no listener of its own.
type injectedListener struct {
	addr     net.Addr
	injected chan net.Conn
	done     chan struct{}
	once     sync.Once
}

func newInjectedListener(addr net.Addr) *injectedListener {
	return &injectedListener{addr: addr, injected: make(chan net.Conn), done: make(chan struct{})}
}

func (l *injectedListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.injected:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *injectedListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *injectedListener) Addr() net.Addr { return l.addr }

func (l *injectedListener) inject(c net.Conn) {
	select {
	case l.injected <- c:
	case <-l.done:
		_ = c.Close()
	}
}
