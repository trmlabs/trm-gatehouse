package workloadidentity

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// TrustDomain is another cluster whose service-account tokens the broker
// accepts, verified locally against the signing keys the cluster publishes.
// The broker's own cluster is the Config's top-level issuer and audience; a
// listed domain is always remote, because the broker cannot read its Pods.
// Only a proxy binding may name a remote domain: a proxy in that cluster
// runs the Pod check there and presents its own token.
type TrustDomain struct {
	Name     string `json:"name"`
	Issuer   string `json:"issuer"`
	Audience string `json:"audience"`
	// Keys is "remote" or "pinned". Remote: JWKSURL is the HTTPS address of
	// the issuer's published keys (for GKE, the issuer URL followed by
	// /jwks), and CAFile, when set, replaces the system roots for it. The
	// live set is cached and refetched, so a rotation on the cluster needs no
	// configuration change. JWKSDialAddress, when set, is the IP and port
	// the fetch connects to instead of resolving the URL's host (a private
	// Google APIs address, so egress policy can name a fixed address); TLS
	// still verifies the URL's host. JWKS beside remote keys is an optional
	// fallback, used only while no live set is usable: never fetched, or
	// every refetch failing for longer than jwksMaxStale. A usable live set
	// always wins, so a key the cluster removed stops verifying even if the
	// fallback still holds it.
	// Pinned: JWKS holds the issuer's public key set itself, and the broker
	// never fetches; a key the set lacks refuses until the set is updated.
	Keys            string          `json:"keys"`
	JWKSURL         string          `json:"jwksURL,omitempty"`
	JWKSDialAddress string          `json:"jwksDialAddress,omitempty"`
	CAFile          string          `json:"caFile,omitempty"`
	JWKS            json.RawMessage `json:"jwks,omitempty"`
	// MaxTokenLifetimeSeconds bounds accepted tokens (default 3600). A remote
	// token is never checked against a live Pod in the broker's cluster, so
	// its lifetime is the revocation window.
	MaxTokenLifetimeSeconds int64 `json:"maxTokenLifetimeSeconds,omitempty"`
	// Pods, when set, lets the broker read Pods in this cluster, so its pool
	// bindings may admit sidecars there directly; see RemotePods. Without
	// it the domain admits only proxy bindings.
	Pods *RemotePods `json:"pods,omitempty"`
}

// RemotePods is how the broker reads a remote cluster's Pods, so a sidecar
// in that cluster is admitted as a pool worker in the broker's own is: its
// token verified by the domain's keys, then its live Pod (UID, controller,
// images, container, deadline and claimed run) read on every admission and
// recheck. One check is not made: the connection's source address, which
// across clusters is a load balancer's, not the Pod's. The Pod must still be
// running for its token to admit, and the token's lifetime bounds a replay
// from anywhere else.
type RemotePods struct {
	// APIServer is the cluster's HTTPS control-plane origin, named by host
	// (for GKE, the cluster's DNS-based endpoint), never by address, so the
	// address is looked up when the broker connects.
	APIServer string `json:"apiServer"`
	// CAFile, when set, replaces the system roots for the API server.
	CAFile string `json:"caFile,omitempty"`
	// Credential is "google": the broker's own Google identity (Workload
	// Identity), whose access token the cluster accepts through IAM; it needs
	// only container.pods.get on that cluster. Or "token-file": TokenFile
	// holds a bearer token, re-read on every call so its writer can rotate
	// it.
	Credential string `json:"credential"`
	TokenFile  string `json:"tokenFile,omitempty"`
}

// googleTokenSource is the broker's own Google identity; tests replace it.
var googleTokenSource = func(ctx context.Context) (oauth2.TokenSource, error) {
	return google.DefaultTokenSource(ctx, "https://www.googleapis.com/auth/cloud-platform")
}

// remotePodsDial, when set, replaces the dialer for remote API servers, so a
// test can serve a named host locally. Nil dials as net.Dialer does.
var remotePodsDial func(ctx context.Context, network, address string) (net.Conn, error)

// remotePodReader returns a call to the remote cluster's API server: HTTPS
// to a named host only, no redirects, no proxy from the environment, a
// bounded response.
func remotePodReader(p RemotePods, timeout time.Duration) (func(context.Context, string, string, []byte, any) error, error) {
	u, err := url.Parse(p.APIServer)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("trust domain pods apiServer must be an HTTPS origin")
	}
	if _, err := netip.ParseAddr(strings.Trim(u.Hostname(), "[]")); err == nil {
		return nil, errors.New("trust domain pods apiServer must name its host, not an address")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if p.CAFile != "" {
		pem, err := os.ReadFile(p.CAFile)
		if err != nil {
			return nil, errors.New("cannot read trust domain pods CA")
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("invalid trust domain pods CA")
		}
		tlsConfig.RootCAs = pool
	}
	var bearer func() (string, error)
	switch p.Credential {
	case "google":
		if p.TokenFile != "" {
			return nil, errors.New("trust domain pods credential google takes no tokenFile")
		}
		source, err := googleTokenSource(context.Background())
		if err != nil {
			return nil, errors.New("trust domain pods credential google: the broker has no Google identity")
		}
		bearer = func() (string, error) {
			token, err := source.Token()
			if err != nil || token.AccessToken == "" {
				return "", errors.New("google identity unavailable")
			}
			return token.AccessToken, nil
		}
	case "token-file":
		if !strings.HasPrefix(p.TokenFile, "/") {
			return nil, errors.New("trust domain pods credential token-file needs an absolute tokenFile")
		}
		bearer = func() (string, error) { return readBearer(p.TokenFile) }
	default:
		return nil, errors.New("trust domain pods credential must be google or token-file")
	}
	client := &http.Client{
		Timeout:       timeout,
		Transport:     &http.Transport{TLSClientConfig: tlsConfig, Proxy: nil, MaxResponseHeaderBytes: 16 << 10, DialContext: remotePodsDial},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	server := strings.TrimSuffix(p.APIServer, "/")
	return func(ctx context.Context, method, path string, body []byte, out any) error {
		token, err := bearer()
		if err != nil {
			return errors.New("workload verifier unavailable")
		}
		return kubeCall(ctx, client, server, token, method, path, body, out)
	}, nil
}

// domain is one trust domain at run time: its issuer and audience, its key
// cache and how keys are fetched.
type domain struct {
	name        string // "" for the broker's own cluster
	issuer      string
	audience    string
	maxLifetime int64
	remote      bool
	keys        *signingKeys
	fetch       func(context.Context, any) error
	pinned      map[string]crypto.PublicKey // set for keys "pinned"; nil otherwise
	// fallback, for remote keys, verifies only while no live set is usable.
	fallback map[string]crypto.PublicKey
	// pods, for a remote domain with RemotePods, calls its API server; nil
	// where the broker cannot read the domain's Pods.
	pods func(ctx context.Context, method, path string, body []byte, out any) error
}

// remoteKeys returns a fetch for a published key set: HTTPS only, no
// redirects, no proxy from the environment, a bounded response.
func remoteKeys(td TrustDomain, timeout time.Duration) (func(context.Context, any) error, error) {
	u, err := url.Parse(td.JWKSURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
		return nil, errors.New("trust domain jwksURL must be an HTTPS URL")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if td.CAFile != "" {
		pem, err := os.ReadFile(td.CAFile)
		if err != nil {
			return nil, errors.New("cannot read trust domain CA")
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("invalid trust domain CA")
		}
		tlsConfig.RootCAs = pool
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig, Proxy: nil, MaxResponseHeaderBytes: 16 << 10}
	if td.JWKSDialAddress != "" {
		dial, err := netip.ParseAddrPort(td.JWKSDialAddress)
		if err != nil || !dial.IsValid() || dial.Port() == 0 || dial.Addr().IsUnspecified() {
			return nil, errors.New("trust domain jwksDialAddress must be an IP address and port")
		}
		// Only the connection's address changes: the request, its Host and
		// the certificate check stay on the URL's host.
		dialer := &net.Dialer{Timeout: timeout}
		transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, dial.String())
		}
	}
	client := &http.Client{
		Timeout:       timeout,
		Transport:     transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	address := u.String()
	return func(ctx context.Context, out any) error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
		if err != nil {
			return errors.New("trust domain keys unavailable")
		}
		req.Header.Set("Accept", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return errors.New("trust domain keys unavailable")
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("trust domain keys refused (status %d)", resp.StatusCode)
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
		if err != nil || len(b) > 1<<20 || json.Unmarshal(b, out) != nil {
			return errors.New("invalid trust domain keys")
		}
		return nil
	}, nil
}

// buildDomains validates the listed trust domains and returns them after the
// broker's own cluster, which is always first.
func (r *Resolver) buildDomains(c Config) error {
	own := &domain{issuer: c.Issuer, audience: c.Audience, maxLifetime: c.MaxTokenLifetimeSeconds, keys: &signingKeys{}}
	own.fetch = func(ctx context.Context, out any) error {
		return r.api(ctx, http.MethodGet, "/openid/v1/jwks", nil, out)
	}
	r.domains = []*domain{own}
	names := map[string]bool{"": true}
	issuers := map[string]bool{c.Issuer: true}
	for _, td := range c.TrustDomains {
		if !pathSegment(td.Name) || names[td.Name] {
			return errors.New("trust domain names must be unique lowercase DNS-style names")
		}
		u, err := url.Parse(td.Issuer)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || issuers[td.Issuer] {
			return errors.New("trust domain issuer must be a distinct HTTPS URL")
		}
		if td.Audience == "" || (td.Keys != "remote" && td.Keys != "pinned") {
			return errors.New("trust domain needs an audience and remote or pinned keys")
		}
		if td.MaxTokenLifetimeSeconds == 0 {
			td.MaxTokenLifetimeSeconds = 3600
		}
		if td.MaxTokenLifetimeSeconds < 600 || td.MaxTokenLifetimeSeconds > 3600 {
			return errors.New("trust domain maxTokenLifetimeSeconds must be between 600 and 3600")
		}
		dom := &domain{name: td.Name, issuer: td.Issuer, audience: td.Audience, maxLifetime: td.MaxTokenLifetimeSeconds, remote: true, keys: &signingKeys{}}
		if td.Keys == "pinned" {
			if td.JWKSURL != "" || td.CAFile != "" || td.JWKSDialAddress != "" {
				return errors.New("a pinned trust domain takes no jwksURL, jwksDialAddress or caFile")
			}
			pinned, err := parsePinnedJWKS(td.JWKS)
			if err != nil {
				return err
			}
			dom.pinned = pinned
		} else {
			// A fallback set is held to the same rules as a pinned one.
			if len(td.JWKS) != 0 {
				if dom.fallback, err = parsePinnedJWKS(td.JWKS); err != nil {
					return err
				}
			}
			if dom.fetch, err = remoteKeys(td, jwksFetchTimeout); err != nil {
				return err
			}
		}
		if td.Pods != nil {
			if dom.pods, err = remotePodReader(*td.Pods, time.Duration(c.TimeoutSeconds)*time.Second); err != nil {
				return err
			}
		}
		names[td.Name], issuers[td.Issuer] = true, true
		r.domains = append(r.domains, dom)
	}
	return nil
}

// domainFor returns the trust domain that issued a token, by its exact issuer.
func (r *Resolver) domainFor(issuer string) *domain {
	for _, d := range r.domains {
		if d.issuer == issuer {
			return d
		}
	}
	return nil
}
