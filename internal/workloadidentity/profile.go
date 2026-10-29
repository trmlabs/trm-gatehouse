package workloadidentity

import (
	"slices"

	"github.com/Infisical/agent-vault/internal/imagerule"
)

// Identity kinds a harness profile names.
const (
	IdentityPodToken      = "pod-token"
	IdentitySessionJWT    = "session-jwt"
	IdentityProxyAttested = "proxy-attested"
)

// Profile is the identity half of a pool's declared harness profile: the
// trust domain, identity kind, namespaces, controller kind and images its
// agents must match. The broker catalog holds it, so it can change at a
// catalog reload without a restart.
type Profile struct {
	Name         string
	Issuer       string
	Audience     string
	Remote       bool
	Kind         string
	OwnerKind    string
	Namespaces   []string
	ImageDigests []string
	ImagePrefix  string // proxy-attested only: images pulled from under this path
}

// ProfileSource returns the declared profile for a pool, or false when the
// catalog declares none (its profile is then derived, and checks nothing
// beyond the binding).
type ProfileSource func(pool string) (Profile, bool)

type profileSource struct{ fn ProfileSource }

// SetProfiles makes every admission also match the pool's declared profile.
func (r *Resolver) SetProfiles(fn ProfileSource) {
	r.profiles.Store(&profileSource{fn: fn})
}

// profileAdmits reports whether an admission matches the pool's declared
// profile. A pool Pod (kind pod-token) may serve a pod-token or session-jwt
// profile: both are the Pod's own token, and the session is checked later.
func (r *Resolver) profileAdmits(pool string, d *domain, kind, namespace, ownerKind string, images []string) bool {
	src := r.profiles.Load()
	if src == nil || src.fn == nil {
		return true
	}
	p, ok := src.fn(pool)
	if !ok {
		return true
	}
	if p.Issuer != d.issuer || p.Audience != d.audience || p.Remote != d.remote {
		return false
	}
	switch kind {
	case IdentityProxyAttested:
		if p.Kind != IdentityProxyAttested {
			return false
		}
	default:
		if p.Kind != IdentityPodToken && p.Kind != IdentitySessionJWT {
			return false
		}
	}
	if !slices.Contains(p.Namespaces, namespace) || ownerKind != p.OwnerKind || len(images) == 0 {
		return false
	}
	for _, image := range images {
		if !imagerule.Allowed(image, p.ImagePrefix, p.ImageDigests) {
			return false
		}
	}
	return true
}

// proxyProfileAdmits requires a declared catalog profile for a proxy
// admission: the one the binding maps the namespace to, from the trust
// domain that verified the proxy's token. With no catalog profile, the proxy
// admits nothing.
func (r *Resolver) proxyProfileAdmits(pp ProxyProfile, d *domain, a Attestation) bool {
	src := r.profiles.Load()
	if src == nil || src.fn == nil {
		return false
	}
	p, ok := src.fn(pp.Pool)
	if !ok || p.Name != pp.Profile || len(p.Namespaces) != 1 {
		return false
	}
	return p.ImagePrefix == pp.ImagePrefix && r.profileAdmits(pp.Pool, d, IdentityProxyAttested, a.Namespace, a.OwnerKind, a.Images)
}

// NamespaceSource finds the catalog pool claiming a namespace of the issuer's domain, and lists them.
type NamespaceSource interface {
	PoolFor(namespace, issuer string) (string, bool)
	Namespaces(issuer string) []string
}

type namespaceSource struct{ src NamespaceSource }

// SetNamespaces lets a proxy binding with catalogPools serve the namespaces the catalog's proxy-attested profiles claim.
func (r *Resolver) SetNamespaces(src NamespaceSource) {
	r.namespaces.Store(&namespaceSource{src: src})
}

// catalogProfile is the profile the catalog gives an attested namespace; one another binding lists by hand is not its.
func (r *Resolver) catalogProfile(binding *Binding, d *domain, namespace string) (ProxyProfile, bool) {
	ns, profiles := r.namespaces.Load(), r.profiles.Load()
	if ns == nil || ns.src == nil || profiles == nil || profiles.fn == nil {
		return ProxyProfile{}, false
	}
	if r.listedElsewhere(binding, namespace) {
		return ProxyProfile{}, false
	}
	pool, ok := ns.src.PoolFor(namespace, d.issuer)
	if !ok {
		return ProxyProfile{}, false
	}
	p, ok := profiles.fn(pool)
	if !ok {
		return ProxyProfile{}, false
	}
	return ProxyProfile{Namespace: namespace, Profile: p.Name, Pool: pool, ImagePrefix: p.ImagePrefix}, true
}

func (r *Resolver) listedElsewhere(binding *Binding, namespace string) bool {
	for i := range r.config.Bindings {
		if b := &r.config.Bindings[i]; b != binding && b.TrustDomain == binding.TrustDomain && b.Proxy != nil {
			if _, listed := b.Proxy.profileFor(namespace); listed {
				return true
			}
		}
	}
	return false
}
