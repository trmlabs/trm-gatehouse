package agenttoken

import (
	"context"
	"errors"
	"log/slog"
	"maps"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Infisical/agent-vault/internal/authorize"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/httpcatalog"
	"github.com/Infisical/agent-vault/internal/runnerid"
)

// Refusal reasons of the config-driven verifier, beside the oidc_* codes the runnerid verifier gives.
const (
	ReasonSubjectUnlisted = "oidc_subject_unlisted"
	ReasonGroupMissing    = "oidc_group_missing"
)

const defaultClockSkew = 60 * time.Second

// Signed admits any platform's signed ID token from its harness profile: the issuer picks the harness (the token is still checked in full against that harness's own keys, audiences and algorithms), the configured subject claim picks the Automation, and its configured groups claim gates it. A platform is added by a catalog entry; the catalog is read per call, so a removed or changed entry applies at the next reload.
type Signed struct {
	Catalog interface{ Current() httpcatalog.Catalog }
	// Client fetches signing keys; nil gets a plain client that follows no redirect.
	Client *http.Client
	Now    func() time.Time

	mu        sync.Mutex
	verifiers map[string]cachedVerifier
}

type cachedVerifier struct {
	config httpcatalog.HarnessSignedToken
	v      *runnerid.SignedVerifier
}

var _ Verifier = (*Signed)(nil)

// Handles reports whether the token names an issuer some signed-token harness is declared for; it reads the unverified issuer only to route.
func (s *Signed) Handles(token string) bool {
	iss, ok := runnerid.PeekIssuer(token)
	return ok && s.handlesIssuer(iss)
}

func (s *Signed) handlesIssuer(iss string) bool {
	_, found := s.Catalog.Current().SignedTokenHarness(iss)
	return found
}

// verifier returns the harness's verifier, rebuilt when its config changed, and forgets verifiers of harnesses no longer declared so the set follows the catalog.
func (s *Signed) verifier(cat httpcatalog.Catalog, h httpcatalog.Harness) *runnerid.SignedVerifier {
	cfg := *h.Identity.Token
	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.verifiers[h.Name]; ok && reflect.DeepEqual(c.config, cfg) {
		return c.v
	}
	if s.verifiers == nil {
		s.verifiers = map[string]cachedVerifier{}
	}
	live := map[string]bool{}
	for _, d := range cat.Harnesses() {
		live[d.Name] = true
	}
	for name := range s.verifiers {
		if !live[name] {
			delete(s.verifiers, name)
		}
	}
	skew := defaultClockSkew
	if cfg.ClockSkewSeconds != nil {
		skew = time.Duration(*cfg.ClockSkewSeconds) * time.Second
	}
	v := runnerid.NewSignedVerifier(runnerid.SignedConfig{
		Issuer: cfg.Issuer, JWKSURL: cfg.JWKSURL, Discovery: cfg.Discovery,
		Audiences: slices.Clone(cfg.Audiences), Algorithms: slices.Clone(cfg.Algorithms),
		MaxLifetime: time.Duration(cfg.MaxLifetimeSeconds) * time.Second, ClockSkew: skew,
		SubjectClaim: cfg.SubjectClaim, GroupsClaim: cfg.GroupsClaim, RequiredClaims: maps.Clone(cfg.RequiredClaims),
		KeyMaxAge: time.Duration(cfg.KeyMaxAgeSeconds) * time.Second, RefreshBackoff: time.Duration(cfg.RefreshBackoffSeconds) * time.Second,
	}, s.Client, s.Now)
	s.verifiers[h.Name] = cachedVerifier{cfg, v}
	return v
}

func (s *Signed) Verify(ctx context.Context, token string) (Session, error) {
	iss, ok := runnerid.PeekIssuer(token)
	if !ok {
		return Session{}, brokercore.Denied("oidc_malformed")
	}
	return s.verifyIssuer(ctx, token, iss)
}

// verifyIssuer is Verify for a token whose unverified issuer the caller already read.
func (s *Signed) verifyIssuer(ctx context.Context, token, iss string) (Session, error) {
	cat := s.Catalog.Current()
	h, ok := cat.SignedTokenHarness(iss)
	if !ok {
		return Session{}, brokercore.Denied("oidc_issuer")
	}
	id, err := s.verifier(cat, h).Verify(ctx, token)
	if err != nil {
		var r *runnerid.Refusal
		if errors.As(err, &r) {
			return Session{}, brokercore.DeniedKey(r.Reason, r.Kid)
		}
		return Session{}, brokercore.Denied("oidc_malformed")
	}
	a, pool, ok := cat.SignedTokenAgent(h.Name, id.Subject)
	if !ok {
		return Session{}, brokercore.Denied(ReasonSubjectUnlisted)
	}
	if want := a.SignedToken.Groups; len(want) > 0 && !slices.ContainsFunc(want, func(g string) bool { return slices.Contains(id.Groups, g) }) {
		return Session{}, brokercore.DeniedKey(ReasonGroupMissing, a.ID)
	}
	return Session{Automation: a.ID, Pool: pool, Expires: id.Expires, Source: authorize.SourceSignedToken}, nil
}

// SignedByIssuer sends a token to Signed when a signed-token harness is declared for its issuer and to Fallback otherwise; a nil Fallback refuses the rest as malformed, as a token no verifier reads always was. It leaves every other verifier's behavior as it was.
type SignedByIssuer struct {
	Signed   *Signed
	Fallback Verifier
	// Reserved are issuers another verifier owns (such as a configured Gumloop issuer); a harness naming one is ignored and logged.
	Reserved []string
}

var _ Verifier = SignedByIssuer{}

func (b SignedByIssuer) Verify(ctx context.Context, token string) (Session, error) {
	// The issuer is read once here and handed on, so a token is never parsed twice for routing.
	if iss, ok := runnerid.PeekIssuer(token); ok && b.Signed != nil && b.Signed.handlesIssuer(iss) {
		if !slices.Contains(b.Reserved, strings.TrimSuffix(iss, "/")) {
			return b.Signed.verifyIssuer(ctx, token, iss)
		}
		slog.Error("signed-token harness names an issuer another verifier owns; the token goes to that verifier", "issuer", iss)
	}
	if b.Fallback == nil {
		return Session{}, brokercore.Denied(ReasonMalformed)
	}
	return b.Fallback.Verify(ctx, token)
}
