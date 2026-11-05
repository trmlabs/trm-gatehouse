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

// TrustDomain is another cluster whose service-account tokens the broker verifies locally against its published signing keys.
// A listed domain is always remote (the broker cannot read its Pods) and only a proxy binding may name it: the proxy in that cluster runs the Pod check and presents its own token.
type TrustDomain struct {
	Name     string `json:"name"`
	Issuer   string `json:"issuer"`
	Audience string `json:"audience"`
	// Keys is "remote" or "pinned". Remote: JWKSURL is the issuer's HTTPS key address (GKE: issuer URL plus /jwks), cached and refetched so rotations need no configuration change; CAFile replaces the system roots.
	// JWKSDialAddress (IP:port) replaces resolving the URL host, with TLS still verifying it; JWKS beside remote is a fallback used only while no live set is usable. Pinned: JWKS is the whole key set and nothing is fetched.
	Keys            string          `json:"keys"`
	JWKSURL         string          `json:"jwksURL,omitempty"`
	JWKSDialAddress string          `json:"jwksDialAddress,omitempty"`
	CAFile          string          `json:"caFile,omitempty"`
	JWKS            json.RawMessage `json:"jwks,omitempty"`
	// MaxTokenLifetimeSeconds bounds accepted tokens (default 3600); a remote token is never checked against a live Pod in the broker's cluster, so its lifetime is the revocation window.
	MaxTokenLifetimeSeconds int64 `json:"maxTokenLifetimeSeconds,omitempty"`
	// Pods, when set, lets pool bindings admit sidecars in this cluster directly (see RemotePods); without it only proxy bindings are admitted.
	Pods *RemotePods `json:"pods,omitempty"`
}

// RemotePods is how the broker reads a remote cluster's Pods so a sidecar there is admitted as a pool worker: token verified by the domain's keys, then its live Pod read on every admission and recheck.
// The source address is not checked (across clusters it is a load balancer's); the Pod must still be running, and the token's lifetime bounds replay from elsewhere.
type RemotePods struct {
	// APIServer is the cluster's HTTPS control-plane origin, named by host (GKE: its DNS-based endpoint), never by address.
	APIServer string `json:"apiServer"`
	// CAFile, when set, replaces the system roots for the API server.
	CAFile string `json:"caFile,omitempty"`
	// Credential is "google" (the broker's Workload Identity access token, needing only container.pods.get) or "token-file" (TokenFile holds a bearer token re-read on every call so it can rotate).
	Credential string `json:"credential"`
	TokenFile  string `json:"tokenFile,omitempty"`
}

// googleTokenSource is the broker's own Google identity; tests replace it.
var googleTokenSource = func(ctx context.Context) (oauth2.TokenSource, error) {
	return google.DefaultTokenSource(ctx, "https://www.googleapis.com/auth/cloud-platform")
}

// remotePodsDial, when set, replaces the dialer for remote API servers so tests can serve a named host locally.
var remotePodsDial func(ctx context.Context, network, address string) (net.Conn, error)

// remotePodReader returns a call to the remote API server: HTTPS to a named host only, no redirects, no environment proxy, bounded response.
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
			if err != nil {
				return "", errVerifierUnreachable
			}
			if token.AccessToken == "" {
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
			return err
		}
		return kubeCall(ctx, client, server, token, method, path, body, out)
	}, nil
}

// domain is one trust domain at run time: issuer, audience, key cache and key fetching.
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

// remoteKeys returns a fetch for a published key set: HTTPS only, no redirects, no environment proxy, bounded response.
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
		// Only the connection's address changes; the request, Host and certificate check stay on the URL's host.
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
