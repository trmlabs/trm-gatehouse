package agenttoken

import (
	"context"
	"errors"

	"github.com/Infisical/agent-vault/internal/authorize"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/httpcatalog"
	"github.com/Infisical/agent-vault/internal/runnerid"
)

// ReasonOrgUnlisted is a verified Gumloop token whose org and owner no Automation block names.
const ReasonOrgUnlisted = "oidc_org_unlisted"

// GumloopOIDC admits a Gumloop-signed ID token as the Automation whose block names the token's org and owner.
type GumloopOIDC struct {
	Catalog  interface{ Current() httpcatalog.Catalog }
	Verifier *runnerid.GumloopVerifier
}

var _ Verifier = GumloopOIDC{}

func (g GumloopOIDC) Verify(ctx context.Context, token string) (Session, error) {
	id, err := g.Verifier.Verify(ctx, token)
	if err != nil {
		var r *runnerid.Refusal
		if errors.As(err, &r) {
			return Session{}, brokercore.DeniedKey(r.Reason, r.Kid)
		}
		return Session{}, brokercore.Denied("oidc_malformed")
	}
	a, pool, ok := g.Catalog.Current().GumloopAgent(id.OrgID, id.OwnerID)
	if !ok {
		return Session{}, brokercore.Denied(ReasonOrgUnlisted)
	}
	return Session{Automation: a.ID, Pool: pool, Expires: id.Expires, Source: authorize.SourceGumloopOIDC, Owner: id.OwnerID}, nil
}

// Either sends a token with a static token's shape to Static and any other to OIDC, whose signatures are never 43 characters; a nil OIDC leaves every token to Static.
type Either struct {
	Static, OIDC Verifier
}

var _ Verifier = Either{}

func (e Either) Verify(ctx context.Context, token string) (Session, error) {
	if _, static := Split(token); !static && e.OIDC != nil {
		return e.OIDC.Verify(ctx, token)
	}
	return e.Static.Verify(ctx, token)
}
