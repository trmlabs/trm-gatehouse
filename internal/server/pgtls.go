package server

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"
)

// The broker can terminate TLS for its PostgreSQL listener itself, in place
// of a TLS front in the same Pod. Each TLS connection joins the PostgreSQL
// broker's loopback listener with the client's own address as its remote
// address, so pool admission sees the worker's address without a PROXY
// header. The handshake runs in the broker's connection handler, under its
// startup deadline, and the broker's pending and serving caps bound these
// connections as they bound the rest: at the pending cap the broker stops
// accepting and new connections wait in the listen backlog.

// pgTLSReloadInterval is how often a handshake may re-read the certificate
// files. A mounted Secret is replaced on rotation, so the next handshake after
// it serves the new certificate without a restart.
const pgTLSReloadInterval = time.Second

// pgTLSAcceptRetryMax caps the wait between retries after a failed accept,
// such as running out of file descriptors, so the listener recovers on its
// own once descriptors free up.
const pgTLSAcceptRetryMax = time.Second

type pgTLSFront struct {
	addr  string
	certs *certificateFiles
}

// EnablePostgresTLS has the broker serve its PostgreSQL listener over TLS on
// addr, with the certificate and key read from certFile and keyFile. Both are
// read now, so a missing or mismatched pair fails startup, and re-read on
// change. It cannot be combined with the cross-cluster listener, whose TLS
// front sends a PROXY header the PostgreSQL broker must then require.
func (s *Server) EnablePostgresTLS(addr, certFile, keyFile string) error {
	if s.crossClusterAddr != "" {
		return errors.New("the PostgreSQL TLS listener cannot be combined with the cross-cluster listener")
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return fmt.Errorf("PostgreSQL TLS listener address: %w", err)
	}
	certs, err := loadCertificateFiles(certFile, keyFile, s.logger)
	if err != nil {
		return err
	}
	s.pgTLS = &pgTLSFront{addr: addr, certs: certs}
	return nil
}

func (f *pgTLSFront) config() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: f.certs.get}
}

// servePostgresTLS accepts TCP connections on l and hands each, wrapped in a
// TLS server connection, to the PostgreSQL broker's listener. Handing off
// blocks while the broker is not accepting, which leaves the next connection
// in the listen backlog. It returns when l closes.
func servePostgresTLS(l net.Listener, pg *mergedListener, config *tls.Config, logger *slog.Logger) error {
	var wait time.Duration
	for {
		c, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			wait = min(max(2*wait, 5*time.Millisecond), pgTLSAcceptRetryMax)
			if logger != nil {
				logger.Warn("pgproxy: TLS accept failed; retrying", slog.String("error", err.Error()))
			}
			time.Sleep(wait)
			continue
		}
		wait = 0
		pg.inject(tls.Server(c, config))
	}
}

// certificateFiles serves a certificate and key pair from files, re-reading
// them at most once per pgTLSReloadInterval. A pair that fails to load keeps
// the last good one in service.
type certificateFiles struct {
	certFile, keyFile string
	logger            *slog.Logger
	now               func() time.Time

	mu        sync.Mutex
	cert      *tls.Certificate
	certPEM   []byte
	keyPEM    []byte
	checkedAt time.Time
}

func loadCertificateFiles(certFile, keyFile string, logger *slog.Logger) (*certificateFiles, error) {
	if certFile == "" || keyFile == "" {
		return nil, errors.New("PostgreSQL TLS listener needs a certificate file and a key file")
	}
	c := &certificateFiles{certFile: certFile, keyFile: keyFile, logger: logger, now: time.Now}
	if err := c.reload(); err != nil {
		return nil, err
	}
	return c, nil
}

// reload reads both files and swaps in the pair when either changed. The
// caller holds mu, or is the constructor.
func (c *certificateFiles) reload() error {
	certPEM, err := os.ReadFile(c.certFile)
	if err != nil {
		return fmt.Errorf("PostgreSQL TLS certificate: %w", err)
	}
	keyPEM, err := os.ReadFile(c.keyFile)
	if err != nil {
		return fmt.Errorf("PostgreSQL TLS key: %w", err)
	}
	if c.cert != nil && bytes.Equal(certPEM, c.certPEM) && bytes.Equal(keyPEM, c.keyPEM) {
		return nil
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("PostgreSQL TLS certificate and key: %w", err)
	}
	c.cert, c.certPEM, c.keyPEM = &pair, certPEM, keyPEM
	return nil
}

func (c *certificateFiles) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if now := c.now(); now.Sub(c.checkedAt) >= pgTLSReloadInterval {
		c.checkedAt = now
		// A half-written rotation can leave a new certificate with the old key
		// for a moment; the last good pair serves until both match.
		if err := c.reload(); err != nil && c.logger != nil {
			c.logger.Warn("pgproxy: TLS certificate reload failed; serving the last good certificate", slog.String("error", err.Error()))
		}
	}
	return c.cert, nil
}
