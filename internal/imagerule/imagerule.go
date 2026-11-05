// Package imagerule decides which pulled images an agent Pod may run: an exact digest, or a repository prefix under the agent image registry.
// It matches what the node pulled (a container status's imageID), never the Pod spec.
package imagerule

import (
	"fmt"
	"regexp"
	"strings"
	"sync/atomic"
)

var (
	digest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	// The registry: a host with at least one dot, then path segments, ending in "/".
	registryShape = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+(/[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+/$`)
	// Below the registry: a whole repository, or a repository and one tenant segment.
	prefix = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?/([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?/)?$`)
	// An OCI distribution reference: optional registry host (and port), then lowercase components joined by single separators, so ".", ".." and empty never parse.
	domainPart = `[a-z0-9]([a-z0-9-]*[a-z0-9])?`
	pathPart   = `[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*`
	ref        = regexp.MustCompile(`^(` + domainPart + `(\.` + domainPart + `)*(:[0-9]{1,5})?/)?` + pathPart + `(/` + pathPart + `)*@sha256:[0-9a-f]{64}$`)
)

// RegistryEnv names the setting that holds the agent image registry.
const RegistryEnv = "AGENT_VAULT_IMAGE_REGISTRY"

var registry atomic.Value // string

// SetRegistry sets the registry every image prefix must lie under, such as "us-docker.pkg.dev/example-project/". Empty clears it: only exact digests are then admitted.
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

// ValidPrefix reports whether p is a whole repository in the registry, or one tenant path in one, ending in "/". With no registry set, none is valid.
func ValidPrefix(p string) bool {
	r := Registry()
	return r != "" && strings.HasPrefix(p, r) && prefix.MatchString(p[len(r):])
}

// Overlap reports whether one prefix contains the other (or they are equal): two profiles may never claim the same images.
func Overlap(a, b string) bool { return strings.HasPrefix(a, b) || strings.HasPrefix(b, a) }

// Split returns a pulled image reference's repository and digest; a bare digest (a locally loaded image) has no repository.
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

// Allowed reports whether a pulled image may run: its digest is listed, or its repository lies under prefix (when set).
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
