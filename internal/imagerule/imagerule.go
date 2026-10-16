// Package imagerule decides which pulled images an agent Pod may run: an exact
// digest, or a repository prefix under the operator's agent image registry. It
// matches what the node pulled (a container status's imageID), never what the
// Pod spec asked for.
package imagerule

import (
	"fmt"
	"regexp"
	"strings"
	"sync/atomic"
)

var (
	digest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	// The registry: a host with at least one dot, then one or more path
	// segments, ending in "/", such as an Artifact Registry project.
	registryShape = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+(/[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+/$`)
	// Below the registry: a whole repository, or a repository and one tenant
	// segment.
	prefix = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?/([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?/)?$`)
	// An image reference by the OCI distribution grammar: an optional
	// registry host (and port), then path components of lowercase letters
	// and digits joined by single separators, so ".", ".." and empty
	// components never parse.
	domainPart = `[a-z0-9]([a-z0-9-]*[a-z0-9])?`
	pathPart   = `[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*`
	ref        = regexp.MustCompile(`^(` + domainPart + `(\.` + domainPart + `)*(:[0-9]{1,5})?/)?` + pathPart + `(/` + pathPart + `)*@sha256:[0-9a-f]{64}$`)
)

// RegistryEnv names the setting that holds the agent image registry.
const RegistryEnv = "AGENT_VAULT_IMAGE_REGISTRY"

var registry atomic.Value // string

// SetRegistry sets the registry every image prefix must lie under, such as
// "us-docker.pkg.dev/example-project/". Empty clears it: no prefix is then
// valid, and agent images are admitted by exact digest only.
func SetRegistry(r string) error {
	if r != "" && !registryShape.MatchString(r) {
		return fmt.Errorf("image registry (--image-registry or %s) must be a registry host with no port and a path ending in /, such as us-docker.pkg.dev/example-project/", RegistryEnv)
	}
	registry.Store(r)
	return nil
}

// Registry returns the registry SetRegistry set, or "".
func Registry() string {
	r, _ := registry.Load().(string)
	return r
}

// ValidDigest reports whether d is sha256: and 64 lowercase hex characters.
func ValidDigest(d string) bool { return digest.MatchString(d) }

// ValidPrefix reports whether p is a whole repository in the agent image
// registry, or one tenant path in such a repository, ending in "/". With no
// registry set, no prefix is valid.
func ValidPrefix(p string) bool {
	r := Registry()
	return r != "" && strings.HasPrefix(p, r) && prefix.MatchString(p[len(r):])
}

// Overlap reports whether one prefix contains the other (or they are equal):
// two profiles may never claim the same images.
func Overlap(a, b string) bool { return strings.HasPrefix(a, b) || strings.HasPrefix(b, a) }

// Split returns a pulled image reference's repository and digest. A bare
// digest (a locally loaded image) has no repository.
func Split(imageID string) (repository, d string, ok bool) {
	imageID = strings.TrimPrefix(imageID, "docker-pullable://")
	if digest.MatchString(imageID) {
		return "", imageID, true
	}
	if len(imageID) > 600 || !ref.MatchString(imageID) {
		return "", "", false
	}
	i := strings.LastIndexByte(imageID, '@')
	return imageID[:i], imageID[i+1:], true
}

// Allowed reports whether a pulled image may run: its digest is listed, or
// its repository lies under prefix (when prefix is set).
func Allowed(imageID, prefix string, digests []string) bool {
	repository, d, ok := Split(imageID)
	if !ok {
		return false
	}
	for _, allowed := range digests {
		if d == allowed {
			return true
		}
	}
	return prefix != "" && repository != "" && strings.HasPrefix(repository+"/", prefix) && len(repository)+1 > len(prefix)
}
