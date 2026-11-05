package cmd

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Infisical/agent-vault/internal/isolation"
	"github.com/Infisical/agent-vault/internal/session"
	"github.com/Infisical/agent-vault/internal/store"
	"github.com/Infisical/agent-vault/internal/telemetry"
	"github.com/charmbracelet/huh"
	"github.com/spf13/cobra"
)

//go:embed skill_cli.md
var skillCLI string

// newRunCmd is called twice (`vault run` and top-level `run`) so each gets its own pflag state.
func newRunCmd(examplePrefix string) *cobra.Command {
	c := &cobra.Command{
		Use:   "run [flags] -- <command> [args...]",
		Short: "Wrap an agent process with Agent Vault access",
		Long: `Start an agent process (e.g. claude, agent, codex, hermes, opencode, openclaw) with an Agent Vault session.
Everything after -- is treated as the command to execute.

Two modes:
  Admin mode (default): use the on-disk session from 'agent-vault auth login'.
    Mints a fresh vault-scoped session token for the child.
  Agent mode: pre-supply a token via env. Used for unattended / containerized
    deployments where there's no human to interactively log in.
      AGENT_VAULT_TOKEN  — vault-scoped session token or long-lived agent token
      AGENT_VAULT_ADDR   — broker base URL
      AGENT_VAULT_VAULT  — vault to scope the run to (required in agent mode for both token types)
    The token is validated against the broker once before the child is exec'd.
    --ttl has no effect in agent mode and is rejected (the token's lifetime
    is fixed at mint time).

Environment variables set on the child:
  AGENT_VAULT_TOKEN  — bearer token for the Agent Vault server
  AGENT_VAULT_ADDR   — base URL of the Agent Vault HTTP control server
  AGENT_VAULT_VAULT  — vault the session is scoped to

The child also inherits HTTPS_PROXY / HTTP_PROXY / NO_PROXY /
NODE_USE_ENV_PROXY / OPENCLAW_PROXY_URL plus the root CA trust variables
(SSL_CERT_FILE, NODE_EXTRA_CA_CERTS, REQUESTS_CA_BUNDLE, CURL_CA_BUNDLE,
GIT_SSL_CAINFO, DENO_CERT) so both HTTPS and plain-HTTP clients
transparently route through the broker. NODE_USE_ENV_PROXY=1 enables
Node.js built-in proxy support (v22.21.0+) so fetch() and
http.get()/https.get() honor the proxy env natively. OPENCLAW_PROXY_URL
feeds OpenClaw's Proxyline managed proxy (OpenClaw requires this in
addition to proxy.enabled in its config). HTTPS_PROXY and HTTP_PROXY
both point at the same proxy URL — the listener accepts
CONNECT for https:// upstreams and absolute-form forward-proxy requests
for http:// on the same port. The root CA PEM is written to
~/.agent-vault/mitm-ca.pem.

Example:
  ` + examplePrefix + ` -- claude
  ` + examplePrefix + ` --vault myproject -- claude`,
		Args:                  cobra.MinimumNArgs(1),
		DisableFlagsInUseLine: true,
		RunE:                  runCmdRunE,
	}

	var iso IsolationMode
	c.Flags().Var(&iso, "isolation", "Isolation mode: host (default) or container")

	c.Flags().String("address", "", "Agent Vault server address (defaults to session address)")
	c.Flags().Int("ttl", 0, "Session TTL in seconds (300–604800; default: server default 24h)")

	c.Flags().String("image", "", "Container image override (requires --isolation=container)")
	c.Flags().StringArray("mount", nil, "Extra bind mount src:dst[:ro] (repeatable; requires --isolation=container)")
	c.Flags().Bool("keep", false, "Don't pass --rm to docker (requires --isolation=container)")
	c.Flags().Bool("no-firewall", false, "Skip iptables egress rules inside the container (requires --isolation=container; debug only)")
	c.Flags().Bool("home-volume-shared", false, "Share /home/claude/.claude across invocations (requires --isolation=container); default is a per-invocation volume, losing auth state but avoiding concurrency corruption")
	c.Flags().Bool("share-agent-dir", false, "Bind-mount the host's agent state dir (~/.claude) into the container so it reuses your host login (requires --isolation=container; mutually exclusive with --home-volume-shared)")

	return c
}

var runCmd = newRunCmd("agent-vault vault run")
var topRunCmd = newRunCmd("agent-vault run")

func runCmdRunE(cmd *cobra.Command, args []string) error {
	// Validate isolation flags before any network I/O so conflicts surface immediately.
	mode := *cmd.Flags().Lookup("isolation").Value.(*IsolationMode)
	if mode == "" {
		if v := os.Getenv("AGENT_VAULT_ISOLATION"); v != "" {
			if err := mode.Set(v); err != nil {
				return fmt.Errorf("AGENT_VAULT_ISOLATION: %w", err)
			}
		}
	}
	if mode == "" {
		mode = IsolationHost
	}
	if err := validateIsolationFlagConflicts(cmd, mode); err != nil {
		return err
	}

	// Agent mode uses an env-supplied token; human mode uses the on-disk admin session.
	sess, tokenSource, err := resolveSession()
	if err != nil {
		return err
	}
	fromEnv := tokenSource != ""

	addr, _ := cmd.Flags().GetString("address")
	if addr == "" {
		addr = sess.Address
	}

	// Agent mode validates the env token once at startup so a bad token fails fast.
	var (
		vault, token string
	)
	if fromEnv {
		// Error on --ttl: the env token's lifetime is fixed at mint time.
		if cmd.Flags().Changed("ttl") {
			return fmt.Errorf("--ttl has no effect when %s is supplied; the token's lifetime is fixed at mint time", tokenSource)
		}
		v, err := resolveVaultForAgentMode(cmd)
		if err != nil {
			return err
		}
		vault = v
		token = sess.Token
		if err := validateEnvToken(addr, token, vault, tokenSource); err != nil {
			return err
		}
	} else {
		ttl, _ := cmd.Flags().GetInt("ttl")
		v, scopedToken, err := mintScopedSession(cmd, sess, addr, ttl)
		if err != nil {
			return err
		}
		vault = v
		token = scopedToken
	}

	// Record telemetry before the container/host split; syscall.Exec replaces the process, so flush synchronously.
	captureRunEvent(args[0], mode, vault)
	tel.Close()

	if mode == IsolationContainer {
		return runContainer(cmd, args, token, addr, vault)
	}

	// 4. Resolve the target binary.
	binary, err := exec.LookPath(args[0])
	if err != nil {
		return fmt.Errorf("command not found: %s", args[0])
	}

	// Strip pre-existing AGENT_VAULT_* keys: POSIX getenv returns the first match, so a stale parent value would shadow ours.
	env := os.Environ()
	env = stripEnvKeys(env, agentVaultInjectedKeys)
	env = append(env,
		"AGENT_VAULT_TOKEN="+token,
		"AGENT_VAULT_ADDR="+addr,
		"AGENT_VAULT_VAULT="+vault,
	)

	// The MITM ingress is the only credential-injection path, so failure here is fatal.
	newEnv, mitmPort, err := requireMITMEnv(env, addr, token, vault, "")
	if err != nil {
		return err
	}
	env = newEnv
	fmt.Fprintf(os.Stderr, "%s routing HTTP/HTTPS through MITM proxy (%s)\n", successText("agent-vault:"), net.JoinHostPort(resolveMITMHost(addr), strconv.Itoa(mitmPort)))

	// 7. If the target command is a supported agent, offer to install the
	//    Agent Vault skill (only when not already present).
	if name, dir, ok := agentSkillDir(args[0]); ok {
		maybeInstallSkills(name, dir)
		if name == "OpenClaw" {
			maybeConfigureOpenClaw()
		}
	}

	// 8. Confirm, then exec — replaces this process entirely so the child
	//    (e.g. Claude Code) gets direct terminal control.
	fmt.Fprintf(os.Stderr, "%s agent-vault connected. Starting %s...\n\n", successText("agent-vault:"), boldText(args[0]))
	// gosec G702: exec wrapper by design, same rationale as the G204 exclusion in .golangci.yml.
	return syscall.Exec(binary, args, env) //nolint:gosec
}

// knownAgents maps CLI binary base-names to (agentName, skillsDir); several names can share an entry.
var knownAgents = []struct {
	bases     []string
	agentName string
	baseDir   string
}{
	{[]string{"claude"}, "Claude Code", ".claude"},
	{[]string{"cursor", "agent"}, "Cursor", ".cursor"},
	{[]string{"codex"}, "Codex", ".agents"},
	{[]string{"hermes"}, "Hermes", ".hermes"},
	{[]string{"opencode"}, "OpenCode", ".opencode"},
	{[]string{"openclaw"}, "OpenClaw", ".openclaw"},
	{[]string{"pi"}, "Pi", filepath.Join(".pi", "agent")},
	{[]string{"devin"}, "Devin", filepath.Join(".config", "devin")},
	{[]string{"windsurf", "devin-desktop"}, "Windsurf / Devin Desktop", filepath.Join(".codeium", "windsurf")},
	{[]string{"cline"}, "Cline", ".cline"},
	{[]string{"roo"}, "Roo Code", ".roo"},
}

// agentSkillDir returns the display name and skills base directory for a
// known agent command, or ok=false if the command is not recognized.
func agentSkillDir(cmd string) (agentName, baseDir string, ok bool) {
	base := filepath.Base(cmd)
	for _, a := range knownAgents {
		for _, b := range a.bases {
			if base == b {
				return a.agentName, a.baseDir, true
			}
		}
	}
	return "", "", false
}

// maybeInstallSkills installs both Agent Vault skills under ~/{baseDir}/skills/ if missing, after one prompt.
func maybeInstallSkills(agentName, baseDir string) {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}

	type skillEntry struct {
		relPath string
		content string
	}
	skills := []skillEntry{
		{filepath.Join(baseDir, "skills", "agent-vault-cli", "SKILL.md"), skillCLI},
	}

	// Refresh skills whose on-disk content differs from the embedded version.
	var stale []skillEntry
	for _, s := range skills {
		fullPath := filepath.Join(home, s.relPath)
		existing, err := os.ReadFile(fullPath)
		if err != nil || !bytes.Equal(existing, []byte(s.content)) {
			stale = append(stale, s)
		}
	}
	if len(stale) == 0 {
		return
	}

	for _, s := range stale {
		fullPath := filepath.Join(home, s.relPath)
		dir := filepath.Dir(fullPath)
		if err := os.MkdirAll(dir, 0o750); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not create skill directory: %v\n", err)
			continue
		}
		if err := os.WriteFile(fullPath, []byte(s.content), 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not write skill file: %v\n", err)
			continue
		}
	}
	fmt.Fprintf(os.Stderr, "%s Installed Agent Vault skills for %s.\n", successText("agent-vault:"), agentName)
}

// maybeConfigureOpenClaw enables OpenClaw's proxy settings, which it otherwise ignores; errors are non-fatal.
func maybeConfigureOpenClaw() {
	openclawBin, err := exec.LookPath("openclaw")
	if err != nil {
		return
	}
	settings := []struct{ key, value string }{
		{"proxy.enabled", "true"},
		{"tools.web.fetch.useTrustedEnvProxy", "true"},
	}
	var ok int
	for _, s := range settings {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		out, err := exec.CommandContext(ctx, openclawBin, "config", "set", s.key, s.value).CombinedOutput()
		cancel()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not set OpenClaw config %s: %s\n", s.key, strings.TrimSpace(string(out)))
		} else {
			ok++
		}
	}
	if ok > 0 {
		fmt.Fprintf(os.Stderr, "%s Configured OpenClaw proxy settings (revert with: openclaw config set proxy.enabled false && openclaw config set tools.web.fetch.useTrustedEnvProxy false).\n", successText("agent-vault:"))
	}
}

// resolveVaultForAgentMode picks the vault in env mode: --vault, then AGENT_VAULT_VAULT, else error (no silent default).
func resolveVaultForAgentMode(cmd *cobra.Command) (string, error) {
	if name, _ := cmd.Flags().GetString("vault"); name != "" {
		return name, nil
	}
	if v := os.Getenv("AGENT_VAULT_VAULT"); v != "" {
		return v, nil
	}
	return "", fmt.Errorf("vault is required in agent mode: set AGENT_VAULT_VAULT or pass --vault")
}

// resolveVaultForCommand requires an explicit vault in env mode so misconfig fails fast; human mode uses resolveVault.
func resolveVaultForCommand(cmd *cobra.Command, tokenSource string) (string, error) {
	if tokenSource != "" {
		return resolveVaultForAgentMode(cmd)
	}
	return resolveVault(cmd), nil
}

// resolveVaultForRun picks the vault for a run session. Priority:
// --vault flag > project file > vault context > interactive select (if multiple) > "default".
func resolveVaultForRun(cmd *cobra.Command, addr, token string) (string, error) {
	// Explicit --vault flag takes priority.
	if name, _ := cmd.Flags().GetString("vault"); name != "" {
		return name, nil
	}
	// Project-level agent-vault.json is next.
	if pv := loadProjectVault(); pv != "" {
		return pv, nil
	}
	// Vault context (set by a previous command) is next.
	if ctx := session.LoadVaultContext(); ctx != "" {
		return ctx, nil
	}

	// Fetch vaults from the server to decide.
	vaults, err := fetchUserVaults(addr, token)
	if err != nil {
		// Bubble session expiry so the outer retry can re-auth and resolve the real vault.
		if errors.Is(err, errSessionExpired) {
			return "", err
		}
		// On other failures keep the silent fallback to "default" for single-vault users.
		return store.DefaultVault, nil
	}

	switch len(vaults) {
	case 0:
		return store.DefaultVault, nil
	case 1:
		return vaults[0], nil
	default:
		var choice string
		opts := make([]huh.Option[string], len(vaults))
		for i, v := range vaults {
			opts[i] = huh.NewOption(v, v)
		}
		err := huh.NewSelect[string]().
			Title("Which vault?").
			Options(opts...).
			Value(&choice).
			Run()
		if err != nil {
			return "", fmt.Errorf("vault selection: %w", err)
		}
		return choice, nil
	}
}

// fetchUserVaults returns the names of vaults the current user has access to.
func fetchUserVaults(addr, token string) ([]string, error) {
	req, err := http.NewRequest(http.MethodGet, addr+"/v1/vaults", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		var errResp struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&errResp)
		msg := errResp.Error
		if msg == "" {
			msg = fmt.Sprintf("status %d", resp.StatusCode)
		}
		if resp.StatusCode == http.StatusUnauthorized {
			return nil, &sessionExpiredError{msg: "listing vaults: " + msg}
		}
		return nil, fmt.Errorf("listing vaults: %s", msg)
	}

	var result struct {
		Vaults []struct {
			Name string `json:"name"`
		} `json:"vaults"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	names := make([]string, len(result.Vaults))
	for i, v := range result.Vaults {
		names[i] = v.Name
	}
	return names, nil
}

// mitmInjectedKeys must be stripped from the inherited env first: POSIX getenv returns the first match.
var mitmInjectedKeys = func() map[string]struct{} {
	m := make(map[string]struct{}, len(isolation.ProxyEnvKeys))
	for _, k := range isolation.ProxyEnvKeys {
		m[k] = struct{}{}
	}
	return m
}()

// agentVaultInjectedKeys are stripped for the same first-match getenv reason as mitmInjectedKeys.
var agentVaultInjectedKeys = map[string]struct{}{
	"AGENT_VAULT_TOKEN": {},
	"AGENT_VAULT_ADDR":  {},
	"AGENT_VAULT_VAULT": {},
}

// stripEnvKeys removes env entries whose key is in keys (case-sensitive).
func stripEnvKeys(env []string, keys map[string]struct{}) []string {
	out := env[:0:len(env)]
	for _, kv := range env {
		i := strings.IndexByte(kv, '=')
		if i < 0 {
			out = append(out, kv)
			continue
		}
		if _, drop := keys[kv[:i]]; drop {
			continue
		}
		out = append(out, kv)
	}
	return out
}

// resolveMITMHost returns the host to dial for the MITM proxy, falling back to loopback.
func resolveMITMHost(addr string) string {
	if u, err := url.Parse(addr); err == nil {
		if h := u.Hostname(); h != "" {
			return h
		}
	}
	return "127.0.0.1"
}

// requireMITMEnv turns MITM transport failures and --mitm-port 0 into errors, since MITM is the only ingress.
func requireMITMEnv(env []string, addr, token, vault, caPath string) ([]string, int, error) {
	newEnv, port, ok, err := augmentEnvWithMITM(env, addr, token, vault, caPath)
	if err != nil {
		return env, 0, fmt.Errorf("MITM setup failed: %w", err)
	}
	if !ok {
		return env, 0, errors.New("MITM proxy is disabled on the Agent Vault server; restart the server without --mitm-port 0 to enable it")
	}
	return newEnv, port, nil
}

// augmentEnvWithMITM routes child HTTP and HTTPS through the broker; caPath is a test seam ("" for default).
func augmentEnvWithMITM(env []string, addr, token, vault, caPath string) ([]string, int, bool, error) {
	pem, port, enabled, err := fetchMITMCA(addr)
	if err != nil {
		return env, 0, false, err
	}
	if !enabled {
		return env, 0, false, nil
	}
	if port == 0 {
		// Older server that didn't advertise X-MITM-Port. Fall back to
		// the compile-time default so upgrade paths don't hard-break.
		port = DefaultMITMPort
	}

	if caPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return env, 0, false, fmt.Errorf("resolve home dir: %w", err)
		}
		caPath = filepath.Join(home, ".agent-vault", "mitm-ca.pem")
	}
	if err := os.MkdirAll(filepath.Dir(caPath), 0o700); err != nil {
		return env, 0, false, fmt.Errorf("create CA dir: %w", err)
	}
	// gosec G306 and G703: 0o600 is for the linter, and caPath is user-controlled by design.
	if err := os.WriteFile(caPath, pem, 0o600); err != nil { //nolint:gosec
		return env, 0, false, fmt.Errorf("write CA: %w", err)
	}

	env = stripEnvKeys(env, mitmInjectedKeys)
	env = append(env, isolation.BuildProxyEnv(isolation.ProxyEnvParams{
		Host:   resolveMITMHost(addr),
		Port:   port,
		Token:  token,
		Vault:  vault,
		CAPath: caPath,
	})...)
	return env, port, true, nil
}

// mintScopedSession mints a vault-scoped token with inline re-auth; the vault picker runs at most once across retries.
func mintScopedSession(cmd *cobra.Command, sess *session.ClientSession, addr string, ttl int) (vault, scopedToken string, err error) {
	err = withReauthRetry(sess, addr, func(s *session.ClientSession) error {
		if vault == "" {
			v, verr := resolveVaultForRun(cmd, addr, s.Token)
			if verr != nil {
				return verr
			}
			vault = v
		}
		token, terr := requestScopedSession(addr, s.Token, vault, ttl)
		if terr != nil {
			return terr
		}
		scopedToken = token
		return nil
	})
	return
}

// requestScopedSession creates a vault-scoped session; the role is always `proxy`.
func requestScopedSession(addr, adminToken, vault string, ttlSeconds int) (string, error) {
	body := map[string]any{"vault": vault}
	if ttlSeconds > 0 {
		body["ttl_seconds"] = ttlSeconds
	}
	reqBody, err := json.Marshal(body)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest(http.MethodPost, addr+"/v1/sessions", bytes.NewReader(reqBody))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+adminToken)

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("could not reach server at %s: %w", addr, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		var errResp struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&errResp)
		msg := errResp.Error
		if msg == "" {
			msg = fmt.Sprintf("status %d", resp.StatusCode)
		}
		if resp.StatusCode == http.StatusUnauthorized {
			return "", &sessionExpiredError{msg: "failed to create scoped session: " + msg}
		}
		return "", fmt.Errorf("failed to create scoped session: %s", msg)
	}

	var result struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("parsing scoped session response: %w", err)
	}
	return result.Token, nil
}

func captureRunEvent(command string, mode IsolationMode, vault string) {
	distinctID := telemetry.MachineID()
	if sess, _ := session.Load(); sess != nil && sess.Email != "" {
		distinctID = sess.Email
	}
	if distinctID == "" {
		distinctID = "anonymous_cli"
	}
	agentName := filepath.Base(command)
	if name, _, ok := agentSkillDir(command); ok {
		agentName = name
	}
	tel.CaptureEvent(distinctID, "av.run", map[string]string{
		"agent_name": agentName,
		"isolation":  string(mode),
		"vault":      vault,
	})
}

func init() {
	// Register --vault locally: the top-level shorthand has no parent flag, and doing it in newRunCmd would collide.
	topRunCmd.Flags().String("vault", "", "target vault (overrides active context)")

	vaultCmd.AddCommand(runCmd)
	rootCmd.AddCommand(topRunCmd)
}
