package agenttoken

import (
	"context"
	"errors"

	"github.com/Infisical/agent-vault/internal/authorize"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/httpcatalog"
	"github.com/Infisical/agent-vault/internal/runnerid"
)

// ReasonServiceAccountUnlisted is a verified Google token whose service account no Automation block names.
const ReasonServiceAccountUnlisted = "oidc_service_account_unlisted"

// ReasonEmailMismatch is a verified Google token whose email claim is not the email its block lists for that unique ID.
const ReasonEmailMismatch = "oidc_email_mismatch"

// GoogleOIDC admits a Google-signed ID token as the Automation whose block names the token's service account unique ID.
type GoogleOIDC struct {
	Catalog  interface{ Current() httpcatalog.Catalog }
	Verifier *runnerid.GoogleVerifier
}

var _ Verifier = GoogleOIDC{}

func (g GoogleOIDC) Verify(ctx context.Context, token string) (Session, error) {
	id, err := g.Verifier.Verify(ctx, token)
	if err != nil {
		var r *runnerid.Refusal
		if errors.As(err, &r) {
			return Session{}, brokercore.DeniedKey(r.Reason, r.Kid)
		}
		return Session{}, brokercore.Denied("oidc_malformed")
	}
	a, pool, ok := g.Catalog.Current().GoogleAgent(id.UniqueID)
	if !ok {
		return Session{}, brokercore.Denied(ReasonServiceAccountUnlisted)
	}
	if id.Email != "" && id.Email != a.GoogleServiceAccount.Email {
		return Session{}, brokercore.Denied(ReasonEmailMismatch)
	}
	return Session{Automation: a.ID, Pool: pool, Expires: id.Expires, Source: authorize.SourceGoogleOIDC}, nil
}

// ByIssuer sends a Google-issued token to Google and any other to Gumloop; both are required.
type ByIssuer struct {
	Google, Gumloop Verifier
}

var _ Verifier = ByIssuer{}

func (b ByIssuer) Verify(ctx context.Context, token string) (Session, error) {
	if iss, _ := runnerid.PeekIssuer(token); iss == runnerid.GoogleIssuer {
		return b.Google.Verify(ctx, token)
	}
	return b.Gumloop.Verify(ctx, token)
}
