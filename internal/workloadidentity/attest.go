package workloadidentity

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
)

var _ brokercore.Attestor = (*Resolver)(nil)

const (
	jwksMaxAge = time.Hour
	// jwksMaxStale bounds how long the last good keys stand while refetches
	// fail: a key the cluster rotated out stops verifying within a day.
	jwksMaxStale       = 24 * time.Hour
	jwksRefetchBackoff = 30 * time.Second
	jwksFetchTimeout   = 10 * time.Second
)

// signingKeys caches the cluster's service-account signing keys, so a pool
// worker's token is verified locally instead of by an API call per connection.
// A failed fetch keeps the last good set, and one fetch runs at a time
// outside the lock, so neither an unknown kid nor an API outage stalls or
// fails the admissions the cached keys can still verify.
type signingKeys struct {
	mu        sync.Mutex
	keys      map[string]crypto.PublicKey
	fetched   time.Time     // last successful fetch
	attempted time.Time     // last fetch started
	flight    chan struct{} // closed when the running fetch ends
}

// signingKey returns the key for kid, or nil. The live set decides while it
// is usable (fetched within jwksMaxStale); while none is, a remote domain's
// fallback set stands in. A key either holds serves at once, and an old or
// missing live set is refreshed behind it, so neither an outage nor an
// unreachable issuer stalls a known key. An unknown kid waits for the running
// fetch, or starts one (at most one per 30 s), so a rotation is picked up with
// no configuration change.
func (r *Resolver) signingKey(ctx context.Context, d *domain, kid string) crypto.PublicKey {
	j := d.keys
	for waited := false; ; waited = true {
		j.mu.Lock()
		now := r.now()
		live := j.keys
		if j.fetched.IsZero() || now.Sub(j.fetched) > jwksMaxStale {
			live = nil
		}
		key := live[kid]
		if live == nil {
			key = d.fallback[kid]
		}
		fresh := live != nil && now.Sub(j.fetched) < jwksMaxAge
		if (key != nil && fresh) || waited {
			j.mu.Unlock()
			return key
		}
		// An unknown kid joins a running fetch even inside the backoff, so a
		// burst of tokens signed with a just-rotated key all wait for it.
		flight := j.flight
		if flight == nil {
			if !j.attempted.IsZero() && now.Sub(j.attempted) < jwksRefetchBackoff {
				j.mu.Unlock()
				return key
			}
			flight = make(chan struct{})
			j.flight, j.attempted = flight, now
			// The fetch serves every waiter, so the caller's cancellation
			// does not end it.
			go r.fetchSigningKeys(context.WithoutCancel(ctx), d, flight)
		}
		j.mu.Unlock()
		if key != nil {
			// A known key serves now; the refresh runs behind it.
			return key
		}
		select {
		case <-flight:
		case <-ctx.Done():
			return nil
		}
	}
}

// fetchSigningKeys replaces the key set on success and leaves it alone on
// failure, then releases the waiters. A failure and a changed set are each
// logged by kid, so an operator sees an outage, and every rotation, without
// any part of a key.
func (r *Resolver) fetchSigningKeys(ctx context.Context, d *domain, flight chan struct{}) {
	ctx, cancel := context.WithTimeout(ctx, jwksFetchTimeout)
	defer cancel()
	var set struct {
		Keys []map[string]any `json:"keys"`
	}
	err := d.fetch(ctx, &set)
	keys := map[string]crypto.PublicKey{}
	for _, m := range set.Keys {
		// A published set may hold keys this broker cannot use; skip them.
		if kid, key, ok := parseJWK(m); ok {
			keys[kid] = key
		}
	}
	if err == nil && len(keys) == 0 {
		// A set with no usable key is an outage, not a revocation of every
		// key: keep the last good set.
		err = errors.New("trust domain published no usable key")
	}
	j := d.keys
	j.mu.Lock()
	var added, removed []string
	lastGood := j.fetched
	if err == nil {
		for kid := range keys {
			if j.keys[kid] == nil {
				added = append(added, kid)
			}
		}
		for kid := range j.keys {
			if keys[kid] == nil {
				removed = append(removed, kid)
			}
		}
		j.keys, j.fetched = keys, r.now()
	}
	j.flight = nil
	j.mu.Unlock()
	// Log before releasing the waiters, so a waiter that returns has seen
	// the line.
	defer close(flight)
	name := d.name
	if name == "" {
		name = "in-cluster"
	}
	switch {
	case err != nil:
		using := "last good keys"
		if lastGood.IsZero() || r.now().Sub(lastGood) > jwksMaxStale {
			using = "no live keys"
			if d.fallback != nil {
				using = "fallback keys"
			}
		}
		var since any = "never"
		if !lastGood.IsZero() {
			since = lastGood.UTC().Format(time.RFC3339)
		}
		r.logger.Warn("workloadidentity: trust domain keys refresh failed", "domain", name, "error", err.Error(),
			"verifying_with", using, "last_good", since)
	case len(added) != 0 || len(removed) != 0:
		slices.Sort(added)
		slices.Sort(removed)
		r.logger.Info("workloadidentity: trust domain keys changed", "domain", name, "added", added, "removed", removed)
	}
}

// verifyLocally checks the token's signature against the keys of the trust
// domain that issued it, and its claims against that domain's policy. It is
// authentication, not a pre-filter.
func (r *Resolver) verifyLocally(ctx context.Context, token string, renewal bool) (claims, *domain, error) {
	if len(token) == 0 || len(token) > 32768 {
		return claims{}, nil, brokercore.Denied("token_format")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return claims{}, nil, brokercore.Denied("token_format")
	}
	headerBytes, err1 := base64.RawURLEncoding.DecodeString(parts[0])
	payload, err2 := base64.RawURLEncoding.DecodeString(parts[1])
	signature, err3 := base64.RawURLEncoding.DecodeString(parts[2])
	if err1 != nil || err2 != nil || err3 != nil {
		return claims{}, nil, brokercore.Denied("token_format")
	}
	var header struct {
		Alg, Kid, Typ string
		Crit          []string
	}
	var c claims
	if json.Unmarshal(headerBytes, &header) != nil || (header.Alg != "RS256" && header.Alg != "ES256") || header.Kid == "" || len(header.Crit) != 0 || json.Unmarshal(payload, &c) != nil {
		return claims{}, nil, brokercore.Denied("token_format")
	}
	// The issuer picks the domain; its keys alone can then verify the token.
	d := r.domainFor(c.Issuer)
	if d == nil {
		return claims{}, nil, brokercore.Denied("token_issuer")
	}
	now := r.now().Unix()
	// A renewal recheck of an open session accepts an expired token; its Pod
	// must still qualify below. A new connection needs an unexpired token.
	if !exactly(c.Audience, d.audience) || (c.Expires <= now && !renewal) || c.Issued <= 0 || c.Issued > now+60 || c.NotBefore > now+60 || c.Expires <= c.Issued || c.Expires-c.Issued > d.maxLifetime {
		return claims{}, nil, brokercore.Denied("token_claims")
	}
	k := c.Kubernetes
	if k.Pod.UID == "" || !pathSegment(k.Pod.Name) || !pathSegment(k.Namespace) || k.ServiceAccount.UID == "" || c.Subject != "system:serviceaccount:"+k.Namespace+":"+k.ServiceAccount.Name {
		return claims{}, nil, brokercore.Denied("token_pod_claims")
	}
	// Each key refusal names the token's kid, so an operator can tell a
	// rotation from a forgery; each trust-domain mode has its own code.
	var key crypto.PublicKey
	switch {
	case d.pinned != nil:
		// Pinned keys: no fetch. A kid outside the set is a rotation the
		// configuration has not taken yet, and refuses until it does.
		if key = d.pinned[header.Kid]; key == nil {
			return claims{}, nil, brokercore.DeniedKey("token_keys_pinned_mismatch", header.Kid)
		}
	case d.name == "":
		// The broker's own cluster: the kid is not in its current key set,
		// or the set could not be read.
		if key = r.signingKey(ctx, d, header.Kid); key == nil {
			return claims{}, nil, brokercore.DeniedKey("token_keys_in_cluster_unknown", header.Kid)
		}
	default:
		if key = r.signingKey(ctx, d, header.Kid); key == nil {
			return claims{}, nil, brokercore.DeniedKey("token_keys_unavailable", header.Kid)
		}
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !verifySignature(header.Alg, key, digest[:], signature) {
		return claims{}, nil, brokercore.DeniedKey("token_signature", header.Kid)
	}
	return c, d, nil
}

type livePod struct {
	Metadata struct {
		UID               string            `json:"uid"`
		Name              string            `json:"name"`
		Namespace         string            `json:"namespace"`
		DeletionTimestamp *string           `json:"deletionTimestamp"`
		Annotations       map[string]string `json:"annotations"`
		OwnerReferences   []struct {
			Kind               string `json:"kind"`
			UID                string `json:"uid"`
			Controller         *bool  `json:"controller"`
			BlockOwnerDeletion *bool  `json:"blockOwnerDeletion"`
		} `json:"ownerReferences"`
	} `json:"metadata"`
	Spec struct {
		ServiceAccountName    string `json:"serviceAccountName"`
		ActiveDeadlineSeconds *int64 `json:"activeDeadlineSeconds"`
		EphemeralContainers   []struct {
			Name string `json:"name"`
		} `json:"ephemeralContainers"`
	} `json:"spec"`
	Status struct {
		Phase                 string                `json:"phase"`
		PodIP                 string                `json:"podIP"`
		PodIPs                []struct{ IP string } `json:"podIPs"`
		StartTime             *time.Time            `json:"startTime"`
		ContainerStatuses     []containerStatus     `json:"containerStatuses"`
		InitContainerStatuses []containerStatus     `json:"initContainerStatuses"`
	} `json:"status"`
}

type containerStatus struct {
	Name         string `json:"name"`
	ImageID      string `json:"imageID"`
	RestartCount int    `json:"restartCount"`
	State        struct {
		Running *struct{} `json:"running"`
	} `json:"state"`
}

// refusedImage names the container that keeps the Pod out, or "" when every
// container and init container (a native sidecar is one) runs an image whose
// digest the binding lists and no ephemeral container was added. A container
// not yet started has no imageID and is refused.
func (p *livePod) refusedImage(digests []string) string {
	if len(p.Spec.EphemeralContainers) != 0 {
		return "ephemeral:" + p.Spec.EphemeralContainers[0].Name
	}
	if len(p.Status.ContainerStatuses) == 0 {
		return "(no container status)"
	}
	for _, s := range append(append([]containerStatus(nil), p.Status.ContainerStatuses...), p.Status.InitContainerStatuses...) {
		// repo@sha256:..., or a bare sha256:... for a locally loaded image.
		digest := s.ImageID[strings.LastIndexByte(s.ImageID, '@')+1:]
		if digest == "" || !slices.Contains(digests, digest) {
			return s.Name
		}
	}
	return ""
}

// controllerKind is the kind of the Pod's controller owner, or "".
func (p *livePod) controllerKind() string {
	for _, owner := range p.Metadata.OwnerReferences {
		if owner.Controller != nil && *owner.Controller {
			return owner.Kind
		}
	}
	return ""
}

// images lists the digest of every container and init container.
func (p *livePod) images() []string {
	var digests []string
	for _, s := range append(append([]containerStatus(nil), p.Status.ContainerStatuses...), p.Status.InitContainerStatuses...) {
		digests = append(digests, s.ImageID[strings.LastIndexByte(s.ImageID, '@')+1:])
	}
	return digests
}

// deadline returns when the Pod's admission ends, or the zero time if it is
// not an admissible pool Pod right now. refusedContainer names the container
// when an unlisted image is the reason, for the operational log. A remote
// Pod's address is not compared with the peer: across clusters the peer is a
// load balancer (see RemotePods).
func (p *livePod) deadline(b *Binding, c claims, peer netip.Addr, remote bool, now time.Time) (end time.Time, refusedContainer string) {
	k := c.Kubernetes
	m := p.Metadata
	if m.UID != k.Pod.UID || m.Name != k.Pod.Name || m.Namespace != k.Namespace || m.DeletionTimestamp != nil ||
		p.Spec.ServiceAccountName != k.ServiceAccount.Name || p.Status.Phase != "Running" || p.Status.StartTime == nil {
		return time.Time{}, ""
	}
	// Second check: the connection came from this Pod's own address.
	addresses := []string{p.Status.PodIP}
	for _, ip := range p.Status.PodIPs {
		addresses = append(addresses, ip.IP)
	}
	matched := remote
	for _, a := range addresses {
		if parsed, err := netip.ParseAddr(a); err == nil && parsed == peer {
			matched = true
		}
	}
	if !matched {
		return time.Time{}, ""
	}
	// ownerReferences are written by whoever creates or updates the Pod, and the
	// owner is never looked up, so this is not proof the controller made it:
	// anyone who may create Pods under this service account in this namespace
	// can name an approved controller. That right is the boundary, and RBAC
	// alone does not hold it, since a cluster-wide grant includes it. A
	// deployment must hold it with admission policy: only the pool controller
	// creates Pods in the worker namespace, and only it changes their owner
	// references. Gatehouse does not ship that policy. Controllers always set
	// blockOwnerDeletion, so it is required; it adds a check only where the
	// OwnerReferencesPermissionEnforcement admission plugin is enabled, and the
	// boundary does not depend on that.
	owned := false
	for _, owner := range m.OwnerReferences {
		if owner.Controller != nil && *owner.Controller && owner.BlockOwnerDeletion != nil && *owner.BlockOwnerDeletion {
			for _, approved := range b.OwnerUIDs {
				owned = owned || owner.UID == approved
			}
		}
	}
	if !owned {
		return time.Time{}, ""
	}
	if container := p.refusedImage(b.ImageDigests); container != "" {
		return time.Time{}, container
	}
	if b.ContainerName != "" {
		running := 0
		for _, s := range p.Status.ContainerStatuses {
			if s.Name == b.ContainerName {
				if s.State.Running == nil || s.RestartCount != 0 {
					return time.Time{}, ""
				}
				running++
			}
		}
		if running != 1 {
			return time.Time{}, ""
		}
	}
	end = p.Status.StartTime.Add(time.Duration(b.MaxPodSeconds) * time.Second)
	if d := p.Spec.ActiveDeadlineSeconds; d != nil {
		if active := p.Status.StartTime.Add(time.Duration(*d) * time.Second); active.Before(end) {
			end = active
		}
	}
	if !now.Before(end) {
		return time.Time{}, ""
	}
	return end, ""
}

// Attest admits a pool worker: local token verification first, then the live
// Pod must be the connection's peer, Running, owned by an approved controller
// and inside its deadline. Bindings without approved owners keep the online
// TokenReview path of ResolveForProxy.
func (r *Resolver) Attest(ctx context.Context, token string, peer netip.Addr) (*brokercore.ProxyScope, error) {
	return r.attest(ctx, token, peer, false)
}

// Reattest is the periodic recheck of an open session: the same checks, except
// that the connection's original token may have expired since admission.
func (r *Resolver) Reattest(ctx context.Context, token string, peer netip.Addr) (*brokercore.ProxyScope, error) {
	return r.attest(ctx, token, peer, true)
}

func (r *Resolver) attest(ctx context.Context, token string, peer netip.Addr, renewal bool) (*brokercore.ProxyScope, error) {
	if !peer.IsValid() || peer.IsLoopback() || peer.IsUnspecified() {
		return nil, brokercore.Denied("peer")
	}
	peer = peer.Unmap()
	ctx, cancel := context.WithTimeout(ctx, time.Duration(r.config.TimeoutSeconds)*time.Second)
	defer cancel()
	c, d, err := r.verifyLocally(ctx, token, renewal)
	if err != nil {
		return nil, brokercore.WithPeer(err, peer)
	}
	k := c.Kubernetes
	var binding *Binding
	for i := range r.config.Bindings {
		b := &r.config.Bindings[i]
		if b.TrustDomain == d.name && b.Namespace == k.Namespace && b.ServiceAccount == k.ServiceAccount.Name && b.ServiceAccountUID == k.ServiceAccount.UID {
			binding = b
			break
		}
	}
	if binding == nil {
		return nil, brokercore.Denied("no_binding")
	}
	attestation := brokercore.AttestationFrom(ctx)
	if binding.Proxy != nil {
		return r.attestProxied(ctx, binding, c, d, peer, attestation, renewal)
	}
	// Only a proxy binding may vouch for another Pod, and a remote cluster's
	// sidecar is admitted only where the broker reads that cluster's Pods.
	if attestation != "" || (d.remote && d.pods == nil) {
		return nil, brokercore.Denied("attestation_not_proxy")
	}
	if len(binding.OwnerUIDs) == 0 {
		return r.ResolveForProxy(ctx, token, "")
	}
	read := r.api
	if d.remote {
		read = d.pods
	}
	var pod livePod
	if read(ctx, http.MethodGet, "/api/v1/namespaces/"+url.PathEscape(k.Namespace)+"/pods/"+url.PathEscape(k.Pod.Name), nil, &pod) != nil {
		return nil, brokercore.Denied("pod_unreadable")
	}
	notAfter, refusedContainer := pod.deadline(binding, c, peer, d.remote, r.now())
	if refusedContainer != "" {
		r.logger.Warn("workloadidentity: pool Pod refused", "reason", "image_not_allowed", "container", refusedContainer,
			"namespace", k.Namespace, "pod", k.Pod.Name)
		return nil, brokercore.Denied("image_not_allowed")
	}
	if notAfter.IsZero() {
		return nil, brokercore.Denied("pod_not_admissible")
	}
	if !r.profileAdmits(binding.Pool, d, IdentityPodToken, k.Namespace, pod.controllerKind(), pod.images()) {
		return nil, brokercore.Denied("catalog_profile")
	}
	scope, err := r.grant(ctx, binding, "")
	if err != nil {
		return nil, err
	}
	if ctx.Err() != nil || (c.Expires <= r.now().Unix() && !renewal) || !r.now().Before(notAfter) {
		return nil, brokercore.Denied("deadline")
	}
	scope.WorkloadID, scope.NotAfter, scope.Pool, scope.IdentityKind = k.Pod.UID, notAfter, binding.Pool, brokercore.KindPodToken
	scope.ClaimedRun = pod.Metadata.Annotations[brokercore.CursorRunAnnotation]
	scope.Pod = brokercore.PodRef{Domain: d.name, Namespace: k.Namespace, Name: k.Pod.Name, UID: k.Pod.UID, Container: binding.ContainerName}
	return scope, nil
}

var _ brokercore.LivePods = (*Resolver)(nil)

// PodRunning rereads the Pod from its cluster; a missing Pod is false, any other failed read is an error.
func (r *Resolver) PodRunning(ctx context.Context, ref brokercore.PodRef, run string) (bool, error) {
	if ref.IsZero() || run == "" {
		return false, nil
	}
	read := r.api
	found := false
	for _, d := range r.domains {
		if d.name != ref.Domain {
			continue
		}
		found = true
		if d.remote {
			read = d.pods
		}
	}
	if !found || read == nil {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(r.config.TimeoutSeconds)*time.Second)
	defer cancel()
	var pod livePod
	if err := read(ctx, http.MethodGet, "/api/v1/namespaces/"+url.PathEscape(ref.Namespace)+"/pods/"+url.PathEscape(ref.Name), nil, &pod); err != nil {
		var refused *kubeStatusError
		if errors.As(err, &refused) && refused.code == http.StatusNotFound {
			return false, nil
		}
		return false, err
	}
	m := pod.Metadata
	if m.UID != ref.UID || m.Name != ref.Name || m.Namespace != ref.Namespace || m.DeletionTimestamp != nil ||
		pod.Status.Phase != "Running" || m.Annotations[brokercore.CursorRunAnnotation] != run {
		return false, nil
	}
	if ref.Container == "" {
		return true, nil
	}
	for _, c := range pod.Status.ContainerStatuses {
		if c.Name == ref.Container {
			return c.State.Running != nil && c.RestartCount == 0, nil
		}
	}
	return false, nil
}

// verifySignature checks a JWS signature with the algorithm the key's type
// requires: RS256 for RSA, ES256 (r||s, 64 bytes) for EC P-256. A token whose
// header names the other algorithm fails.
func verifySignature(alg string, key crypto.PublicKey, digest, signature []byte) bool {
	switch k := key.(type) {
	case *rsa.PublicKey:
		return alg == "RS256" && rsa.VerifyPKCS1v15(k, crypto.SHA256, digest, signature) == nil
	case *ecdsa.PublicKey:
		if alg != "ES256" || len(signature) != 64 {
			return false
		}
		return ecdsa.Verify(k, digest, new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:]))
	}
	return false
}
