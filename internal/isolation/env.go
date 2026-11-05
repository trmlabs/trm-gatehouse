// Package isolation builds the non-cooperative container that
// `vault run --isolation=container` launches the child agent inside.
package isolation

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
)

const (
	ContainerCAPath       = "/etc/agent-vault/ca.pem"
	ContainerProxyHost    = "host.docker.internal"
	ContainerClaudeHome   = "/home/claude/.claude"
	ContainerClaudeConfig = "/home/claude/.claude.json"
)

// ProxyEnvParams feeds BuildProxyEnv; process and container mode differ only in Host and CAPath.
type ProxyEnvParams struct {
	Host   string // MITM listener host from the child's point of view
	Port   int
	Token  string
	Vault  string
	CAPath string // path the child reads the CA PEM from
}

// BuildProxyEnv returns the env vars pointing a client at the MITM proxy; keep in sync with buildProxyEnv() in the TypeScript SDK sessions.ts.
func BuildProxyEnv(p ProxyEnvParams) []string {
	scheme := "http"
	proxyURL := (&url.URL{
		Scheme: scheme,
		User:   url.UserPassword(p.Token, p.Vault),
		Host:   net.JoinHostPort(p.Host, strconv.Itoa(p.Port)),
	}).String()
	return []string{
		"HTTPS_PROXY=" + proxyURL,
		"HTTP_PROXY=" + proxyURL,
		"NO_PROXY=localhost,127.0.0.1," + p.Host,
		"NODE_USE_ENV_PROXY=1",
		"OPENCLAW_PROXY_URL=" + proxyURL,
		"SSL_CERT_FILE=" + p.CAPath,
		"NODE_EXTRA_CA_CERTS=" + p.CAPath,
		"REQUESTS_CA_BUNDLE=" + p.CAPath,
		"CURL_CA_BUNDLE=" + p.CAPath,
		"GIT_SSL_CAINFO=" + p.CAPath,
		"DENO_CERT=" + p.CAPath,
	}
}

// ProxyEnvKeys are the keys BuildProxyEnv emits; strip them from the parent env first since getenv returns the first match.
var ProxyEnvKeys = []string{
	"HTTPS_PROXY",
	"HTTP_PROXY",
	"NO_PROXY",
	"NODE_USE_ENV_PROXY",
	"OPENCLAW_PROXY_URL",
	"SSL_CERT_FILE",
	"NODE_EXTRA_CA_CERTS",
	"REQUESTS_CA_BUNDLE",
	"CURL_CA_BUNDLE",
	"GIT_SSL_CAINFO",
	"DENO_CERT",
}

// BuildContainerEnv returns KEY=VALUE entries for `docker run -e`, built fresh so the host env is not inherited.
func BuildContainerEnv(token, vault string, httpPort, mitmPort int) []string {
	env := BuildProxyEnv(ProxyEnvParams{
		Host:   ContainerProxyHost,
		Port:   mitmPort,
		Token:  token,
		Vault:  vault,
		CAPath: ContainerCAPath,
	})
	return append(env,
		"AGENT_VAULT_TOKEN="+token,
		"AGENT_VAULT_ADDR="+fmt.Sprintf("http://%s:%d", ContainerProxyHost, httpPort),
		"AGENT_VAULT_VAULT="+vault,
		fmt.Sprintf("VAULT_HTTP_PORT=%d", httpPort),
		fmt.Sprintf("VAULT_MITM_PORT=%d", mitmPort),
	)
}
