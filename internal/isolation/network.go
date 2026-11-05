package isolation

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"
)

// NetworkLabelKey/Value mark networks agent-vault owns so PruneStaleNetworks leaves other tools' networks alone.
const (
	NetworkLabelKey    = "agent-vault-isolation"
	NetworkLabelValue  = "1"
	NetworkNamePrefix  = "agent-vault-"
	VolumeNamePrefix   = "agent-vault-claude-home-"
	DefaultPruneGrace  = 60 * time.Second
	sessionIDBytes     = 8 // 16 hex chars
	sessionLabelPrefix = "agent-vault-session="
)

// Network describes a created per-invocation docker bridge network.
type Network struct {
	Name      string
	GatewayIP net.IP
}

// NewSessionID returns 16 lowercase hex chars, separate from the auth-session token so rotating one keeps names stable.
func NewSessionID() (string, error) {
	var b [sessionIDBytes]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("session id: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

func networkName(sessionID string) string { return NetworkNamePrefix + sessionID }

// CreatePerInvocationNetwork creates agent-vault-<sessionID> as a labeled bridge; the gateway IP is where the forwarder binds.
func CreatePerInvocationNetwork(ctx context.Context, sessionID string) (*Network, error) {
	name := networkName(sessionID)
	create := exec.CommandContext(ctx, "docker", "network", "create",
		"--driver", "bridge",
		"--label", NetworkLabelKey+"="+NetworkLabelValue,
		"--label", sessionLabelPrefix+sessionID,
		name,
	)
	if out, err := create.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("docker network create %s: %w: %s", name, err, strings.TrimSpace(string(out)))
	}
	gw, err := inspectNetworkGateway(ctx, name)
	if err != nil {
		// Use a detached context for cleanup so a ctx cancellation
		// (SIGINT during startup) doesn't leak a half-created network.
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = exec.CommandContext(cleanup, "docker", "network", "rm", name).Run()
		cancel()
		return nil, err
	}
	return &Network{Name: name, GatewayIP: gw}, nil
}

func inspectNetworkGateway(ctx context.Context, name string) (net.IP, error) {
	cmd := exec.CommandContext(ctx, "docker", "network", "inspect", name,
		"--format", "{{range .IPAM.Config}}{{.Gateway}}{{end}}")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("docker network inspect %s: %w", name, err)
	}
	gw := net.ParseIP(strings.TrimSpace(string(out)))
	if gw == nil {
		return nil, fmt.Errorf("docker network inspect %s: empty gateway", name)
	}
	return gw, nil
}

// RemoveNetwork is a best-effort teardown.
func RemoveNetwork(ctx context.Context, name string) error {
	return exec.CommandContext(ctx, "docker", "network", "rm", name).Run()
}

// ClaudeHomeVolumeName keeps the volume naming in one place to match PruneStaleVolumes's prefix filter.
func ClaudeHomeVolumeName(sessionID string) string {
	return VolumeNamePrefix + sessionID
}

// RemoveVolume is a best-effort `docker volume rm` that ignores volume-in-use errors.
func RemoveVolume(ctx context.Context, name string) error {
	return exec.CommandContext(ctx, "docker", "volume", "rm", name).Run()
}

// PruneStaleVolumes removes unmounted per-invocation claude-home volumes; no grace period since docker rejects rm on attached ones.
func PruneStaleVolumes(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "docker", "volume", "ls",
		"--filter", "name="+VolumeNamePrefix,
		"--format", "{{.Name}}",
	)
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("docker volume ls: %w", err)
	}
	for _, name := range strings.Fields(string(out)) {
		// The trailing dash in VolumeNamePrefix excludes the shared claude-home volume.
		if !strings.HasPrefix(name, VolumeNamePrefix) {
			continue
		}
		_ = exec.CommandContext(ctx, "docker", "volume", "rm", name).Run()
	}
	return nil
}

// PruneStaleNetworks removes empty agent-vault-* networks older than grace; grace stops one run pruning another's new network.
func PruneStaleNetworks(ctx context.Context, grace time.Duration) error {
	if grace <= 0 {
		grace = DefaultPruneGrace
	}
	names, err := listLabeledNetworks(ctx)
	if err != nil {
		return err
	}
	cutoff := time.Now().Add(-grace)
	for _, n := range names {
		info, err := inspectNetworkInfo(ctx, n)
		if err != nil {
			continue // best-effort
		}
		if !shouldPrune(info, cutoff) {
			continue
		}
		// Ignore errors: another run may be removing it too, or it may
		// have just attached a container between ls and rm.
		_ = exec.CommandContext(ctx, "docker", "network", "rm", n).Run()
	}
	return nil
}

func listLabeledNetworks(ctx context.Context) ([]string, error) {
	cmd := exec.CommandContext(ctx, "docker", "network", "ls",
		"--filter", "label="+NetworkLabelKey+"="+NetworkLabelValue,
		"--filter", "name="+NetworkNamePrefix,
		"--format", "{{.Name}}",
	)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("docker network ls: %w", err)
	}
	raw := strings.Fields(string(out))
	// docker's name= filter is a substring match, so enforce a strict prefix here.
	filtered := raw[:0]
	for _, n := range raw {
		if strings.HasPrefix(n, NetworkNamePrefix) {
			filtered = append(filtered, n)
		}
	}
	return filtered, nil
}

// networkInfo is the slice of `docker network inspect` output we care
// about for prune decisions.
type networkInfo struct {
	Created    time.Time
	Containers map[string]any
}

func inspectNetworkInfo(ctx context.Context, name string) (networkInfo, error) {
	cmd := exec.CommandContext(ctx, "docker", "network", "inspect", name, "--format", "{{json .}}")
	out, err := cmd.Output()
	if err != nil {
		return networkInfo{}, err
	}
	return parseNetworkInspect(out)
}

func parseNetworkInspect(data []byte) (networkInfo, error) {
	var raw struct {
		Created    time.Time      `json:"Created"`
		Containers map[string]any `json:"Containers"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return networkInfo{}, fmt.Errorf("parse network inspect: %w", err)
	}
	return networkInfo{Created: raw.Created, Containers: raw.Containers}, nil
}

func shouldPrune(info networkInfo, cutoff time.Time) bool {
	if len(info.Containers) > 0 {
		return false
	}
	if info.Created.After(cutoff) {
		return false
	}
	return true
}
