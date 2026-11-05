package isolation

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
)

//go:embed assets/Dockerfile assets/init-firewall.sh assets/entrypoint.sh
var isolationAssets embed.FS

const (
	isolationImageRepo = "agent-vault/isolation"
	// assetsHashLen is 12 hex chars — plenty of collision resistance
	// for this purpose and short enough to read in docker image ls.
	assetsHashLen = 12
)

// assetFiles lists embedded assets in hashing order; changing it invalidates every cached image.
var assetFiles = []string{
	"assets/Dockerfile",
	"assets/entrypoint.sh",
	"assets/init-firewall.sh",
}

// TODO: concurrent runs that miss the image cache each build the same bytes; acceptable for v1.

// EnsureImage returns the local isolation image tag, building it if needed; a non-empty override is used as-is.
func EnsureImage(ctx context.Context, override string, stderr io.Writer) (string, error) {
	if override != "" {
		return override, nil
	}
	hash, err := assetsHash()
	if err != nil {
		return "", err
	}
	tag := isolationImageRepo + ":" + hash
	if imageExists(ctx, tag) {
		return tag, nil
	}

	dir, err := unpackAssets(hash)
	if err != nil {
		return "", err
	}
	fmt.Fprintln(stderr, "agent-vault: building isolation image (one-time setup)...")
	build := exec.CommandContext(ctx, "docker", "build",
		"-t", tag,
		"-t", isolationImageRepo+":latest",
		dir,
	)
	build.Stdout = stderr
	build.Stderr = stderr
	if err := build.Run(); err != nil {
		return "", fmt.Errorf("docker build: %w", err)
	}
	return tag, nil
}

func imageExists(ctx context.Context, tag string) bool {
	return exec.CommandContext(ctx, "docker", "image", "inspect", tag).Run() == nil
}

func assetsHash() (string, error) {
	h := sha256.New()
	for _, name := range assetFiles {
		data, err := isolationAssets.ReadFile(name)
		if err != nil {
			return "", fmt.Errorf("read embedded asset %s: %w", name, err)
		}
		_, _ = h.Write([]byte(name))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write(data)
	}
	return hex.EncodeToString(h.Sum(nil))[:assetsHashLen], nil
}

// unpackAssets writes the embedded files to ~/.agent-vault/isolation/<hash>/ (idempotent) with scripts 0o755.
func unpackAssets(hash string) (string, error) {
	dir, err := hostIsolationDir()
	if err != nil {
		return "", err
	}
	outDir := filepath.Join(dir, hash)
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return "", fmt.Errorf("mkdir %s: %w", outDir, err)
	}
	for _, name := range assetFiles {
		data, err := isolationAssets.ReadFile(name)
		if err != nil {
			return "", err
		}
		base := filepath.Base(name)
		mode := os.FileMode(0o644)
		if filepath.Ext(base) == ".sh" {
			mode = 0o755
		}
		if err := os.WriteFile(filepath.Join(outDir, base), data, mode); err != nil {
			return "", fmt.Errorf("write %s: %w", base, err)
		}
	}
	return outDir, nil
}
