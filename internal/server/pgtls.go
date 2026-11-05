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

// The broker terminates TLS itself so pool admission sees the worker's own address without a PROXY header; the handshake runs in the connection handler under its startup deadline and pending/serving caps.

const pgTLSReloadInterval = time.Second

const pgTLSAcceptRetryMax = time.Second

type pgTLSFront struct {
	addr  string
	certs *certificateFiles
}

// EnablePostgresTLS reads certFile and keyFile now (a bad pair fails startup) and re-reads on change. It cannot be combined with the cross-cluster listener, whose front sends a PROXY header.
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

// certificateFiles re-reads the pair at most once per pgTLSReloadInterval and keeps the last good pair on a failed load.
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
		// A half-written rotation can pair a new certificate with the old key; the last good pair serves until both match.
		if err := c.reload(); err != nil && c.logger != nil {
			c.logger.Warn("pgproxy: TLS certificate reload failed; serving the last good certificate", slog.String("error", err.Error()))
		}
	}
	return c.cert, nil
}
