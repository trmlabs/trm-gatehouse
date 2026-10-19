package httpcatalog

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"
)

// ClientCertificateRef locates the client certificate an entry presents to
// its upstream in the TLS handshake (mutual TLS): a KV version 2 secret whose
// "cert" field holds the PEM certificate, followed by any intermediates, and
// whose "key" field holds its PEM private key. Both come from one read, so a
// new KV version rotates them together.
type ClientCertificateRef struct {
	Mount string `json:"mount"`
	Path  string `json:"path"`
}

// The fields of a client certificate's secret.
const (
	ClientCertificateField    = "cert"
	ClientCertificateKeyField = "key"
)

func (r ClientCertificateRef) valid() bool {
	return ValidMount(r.Mount) && len(r.Path) <= 127 && vendorKeyPath.MatchString(r.Path)
}

// ClientCertificate is a parsed client certificate and its KV version. It
// prints as its version and expiry only; the private key is reachable only
// through TLSCertificate, for the handshake.
type ClientCertificate struct {
	certificate tls.Certificate
	Version     int
	NotBefore   time.Time
	NotAfter    time.Time
	// Fingerprint is the SHA-256 of the leaf, the certificate the upstream sees.
	Fingerprint [sha256.Size]byte
}

// TLSCertificate is the certificate and key for a tls.Config.
func (c *ClientCertificate) TLSCertificate() *tls.Certificate { return &c.certificate }

func (c ClientCertificate) String() string {
	return fmt.Sprintf("client-certificate(v%d, expires %s)", c.Version, c.NotAfter.UTC().Format(time.RFC3339))
}
func (c ClientCertificate) GoString() string           { return c.String() }
func (c ClientCertificate) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(c.String())) }

// Usable reports whether the certificate may be presented at now: inside its
// validity window. An upstream refuses one outside it anyway; the broker
// refuses first, with a reason an operator can act on.
func (c *ClientCertificate) Usable(now time.Time) error {
	if now.Before(c.NotBefore) || !now.Before(c.NotAfter) {
		return ErrClientCertificateExpired
	}
	return nil
}

var (
	// ErrClientCertificateUnavailable means Vault could not be read.
	ErrClientCertificateUnavailable = errors.New("client certificate unavailable")
	// ErrClientCertificateDeleted means Vault answered without a certificate
	// and key: the secret or its current version is deleted or destroyed, or
	// a field is missing or empty. No cached copy outlives it.
	ErrClientCertificateDeleted = fmt.Errorf("%w: deleted in Vault", ErrClientCertificateUnavailable)
	// ErrClientCertificateInvalid means Vault answered with a value the
	// broker will not present: not a PEM certificate and matching key, too
	// large, or a CA certificate rather than an end-entity one. It is cached
	// and refused like ErrClientCertificateDeleted, but tells the operator
	// the value needs fixing, not restoring.
	ErrClientCertificateInvalid = fmt.Errorf("%w: not an end-entity certificate with its key", ErrClientCertificateDeleted)
	// ErrClientCertificateExpired means the certificate is outside its
	// validity window (see Usable).
	ErrClientCertificateExpired = errors.New("client certificate outside its validity window")
)

// Bounds on a stored certificate chain and key, far above any real one.
const (
	maxClientCertificateBytes = 64 << 10
	maxClientKeyBytes         = 16 << 10
)

// ClientCertificates caches each client certificate as Keys caches a key: for
// TTL (default and maximum 1 minute), so a new KV version is presented within
// TTL, or sooner after Invalidate; a deleted or invalid one is refused from
// the first read that sees it; and only an unreachable or failing Vault keeps
// a cached certificate in use, for up to MaxStale (default 5 minutes) past its
// TTL.
type ClientCertificates struct {
	Vault    Logical
	TTL      time.Duration
	MaxStale time.Duration
	Now      func() time.Time

	mu          sync.Mutex
	cache       map[ClientCertificateRef]cachedCertificate
	flight      map[ClientCertificateRef]*sync.Mutex
	invalidated map[ClientCertificateRef]time.Time
}

type cachedCertificate struct {
	cert    *ClientCertificate
	fetched time.Time
	gone    error // ErrClientCertificateDeleted or ErrClientCertificateInvalid
}

func (c *ClientCertificates) settings() (time.Duration, time.Duration, time.Time) {
	k := Keys{TTL: c.TTL, MaxStale: c.MaxStale, Now: c.Now}
	return k.settings()
}

// Get returns the current certificate for ref. Concurrent misses for one
// certificate share a single Vault read.
func (c *ClientCertificates) Get(ctx context.Context, ref ClientCertificateRef) (*ClientCertificate, error) {
	ttl, stale, now := c.settings()
	c.mu.Lock()
	if c.cache == nil {
		c.cache, c.flight = map[ClientCertificateRef]cachedCertificate{}, map[ClientCertificateRef]*sync.Mutex{}
	}
	if cached, ok := c.cache[ref]; ok && now.Sub(cached.fetched) < ttl {
		c.mu.Unlock()
		return cached.result()
	}
	lock, ok := c.flight[ref]
	if !ok {
		lock = &sync.Mutex{}
		c.flight[ref] = lock
	}
	c.mu.Unlock()

	lock.Lock()
	defer lock.Unlock()
	c.mu.Lock()
	cached, have := c.cache[ref]
	c.mu.Unlock()
	if have && now.Sub(cached.fetched) < ttl {
		return cached.result() // another request refreshed it while we waited
	}
	cert, err := c.read(ctx, ref)
	switch {
	case errors.Is(err, ErrClientCertificateDeleted):
		c.mu.Lock()
		c.cache[ref] = cachedCertificate{fetched: now, gone: err}
		c.mu.Unlock()
		return nil, err
	case err != nil:
		if have && cached.gone == nil && now.Sub(cached.fetched) < ttl+stale {
			return cached.cert, nil
		}
		return nil, ErrClientCertificateUnavailable
	}
	c.mu.Lock()
	c.cache[ref] = cachedCertificate{cert: cert, fetched: now}
	c.mu.Unlock()
	return cert, nil
}

func (c cachedCertificate) result() (*ClientCertificate, error) {
	if c.gone != nil {
		return nil, c.gone
	}
	return c.cert, nil
}

// Invalidate drops a cached certificate after the upstream refuses it, so the
// next request reads the newest version. Like Keys.Invalidate, it acts at
// most once per certificate every 30 seconds.
func (c *ClientCertificates) Invalidate(ref ClientCertificateRef) {
	_, _, now := c.settings()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.invalidated == nil {
		c.invalidated = map[ClientCertificateRef]time.Time{}
	}
	if last, ok := c.invalidated[ref]; ok && now.Sub(last) < invalidateInterval {
		return
	}
	c.invalidated[ref] = now
	delete(c.cache, ref)
}

// read never puts Vault's response, the certificate or the key into an error.
func (c *ClientCertificates) read(ctx context.Context, ref ClientCertificateRef) (*ClientCertificate, error) {
	if c.Vault == nil {
		return nil, ErrClientCertificateUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	resp, err := c.Vault.ReadWithDataWithContext(ctx, ref.Mount+"/data/"+ref.Path, nil)
	if err != nil {
		return nil, ErrClientCertificateUnavailable
	}
	if resp == nil || resp.Data == nil {
		return nil, ErrClientCertificateDeleted
	}
	data, _ := resp.Data["data"].(map[string]interface{})
	metadata, _ := resp.Data["metadata"].(map[string]interface{})
	certPEM, _ := data[ClientCertificateField].(string)
	keyPEM, _ := data[ClientCertificateKeyField].(string)
	if certPEM == "" || keyPEM == "" {
		return nil, ErrClientCertificateDeleted
	}
	cert, err := ParseClientCertificate(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	switch n := metadata["version"].(type) {
	case json.Number:
		cert.Version, _ = strconv.Atoi(n.String())
	case float64:
		cert.Version = int(n)
	}
	return cert, nil
}

// ParseClientCertificate checks a PEM certificate chain and key the way the
// broker does before presenting them: the key matches the first certificate,
// which is an end-entity certificate, not a CA. A CA's key can sign new
// certificates, which a broker presenting one identity never needs. Errors
// are ErrClientCertificateInvalid and never quote either value.
func ParseClientCertificate(certPEM, keyPEM string) (*ClientCertificate, error) {
	if len(certPEM) > maxClientCertificateBytes || len(keyPEM) > maxClientKeyBytes {
		return nil, ErrClientCertificateInvalid
	}
	pair, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil || len(pair.Certificate) == 0 {
		return nil, ErrClientCertificateInvalid
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || leaf.IsCA {
		return nil, ErrClientCertificateInvalid
	}
	pair.Leaf = leaf
	return &ClientCertificate{certificate: pair, NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter, Fingerprint: sha256.Sum256(leaf.Raw)}, nil
}
