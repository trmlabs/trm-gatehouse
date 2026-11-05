package workloadidentity

import (
	"context"
	"fmt"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/runtimestatus"
)

// Observer verifies live Kubernetes identity for a read-only status surface; it has no SessionResolver methods or store and destination grants.
// Use a separate audience and service account.
type Observer struct{ resolver *Resolver }

// NewObserver accepts operator-owned bindings; AgentID and VaultID must be empty so observer access never authorizes proxying.
func NewObserver(c Config) (*Observer, error) {
	r, err := newResolver(c, nil, true)
	if err != nil {
		return nil, err
	}
	return &Observer{resolver: r}, nil
}

// Authorize repeats TokenReview and the live Pod check for every observation and returns the binding's access.
func (o *Observer) Authorize(ctx context.Context, proof string) (runtimestatus.Access, error) {
	if o == nil || o.resolver == nil {
		return runtimestatus.Access{}, brokercore.ErrInvalidSession
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(o.resolver.config.TimeoutSeconds)*time.Second)
	defer cancel()
	binding, c, err := o.resolver.verifyProof(ctx, proof)
	if err != nil {
		return runtimestatus.Access{}, err
	}
	if binding == nil || ctx.Err() != nil || c.Expires <= o.resolver.now().Unix() {
		return runtimestatus.Access{}, brokercore.ErrInvalidSession
	}
	return runtimestatus.Access{ListAgents: binding.ListAgents}, nil
}

// ValidateObserverSeparation must run before mounting the observer route beside a proxy: separate audiences are not enough when one service account can request both proofs, so the account policies must differ.
func ValidateObserverSeparation(observer, proxy Config) error {
	if observer.Audience == "" || observer.Audience == proxy.Audience {
		return fmt.Errorf("cleanup observer requires a separate audience")
	}
	for _, d := range proxy.TrustDomains {
		if observer.Audience == d.Audience {
			return fmt.Errorf("cleanup observer requires a separate audience")
		}
	}
	for _, observed := range observer.Bindings {
		for _, admitted := range proxy.Bindings {
			if observed.Namespace == admitted.Namespace && observed.ServiceAccount == admitted.ServiceAccount {
				return fmt.Errorf("cleanup observer must not share a proxy service account")
			}
		}
	}
	return nil
}
