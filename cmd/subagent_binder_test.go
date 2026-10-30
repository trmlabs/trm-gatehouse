package cmd

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/authorize"
	"github.com/Infisical/agent-vault/internal/authorize/authorizetest"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/httpcatalog"
	"github.com/Infisical/agent-vault/internal/mitm"
	"github.com/Infisical/agent-vault/internal/store"
)

type noPods struct{}

func (noPods) PodRunning(context.Context, brokercore.PodRef, string) (bool, error) { return false, nil }

// Subagents are served only with both a store registry and a Pod-reading resolver; either missing leaves plain session pins.
func TestSessionBinderServesSubagentsWithARegistryAndPods(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "binder.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	t.Setenv("AGENT_VAULT_SUBAGENT_WAIT_SECONDS", "45")
	sub, ok := sessionBinder(st, noPods{}).(*authorize.Subagents)
	if !ok || sub.Registry == nil || sub.Pods == nil || sub.Binder == nil || sub.Wait != 45*time.Second {
		t.Fatalf("binder %+v", sub)
	}
	if _, ok := sessionBinder(st, nil).(*authorize.Subagents); ok {
		t.Fatal("served subagents without a Pod reader")
	}
	if sessionBinder(st, nil) == nil {
		t.Fatal("the store's session pins are gone")
	}
	if sessionBinder(struct{}{}, noPods{}) != nil {
		t.Fatal("a store without pins became a binder")
	}
	t.Setenv("AGENT_VAULT_SUBAGENT_WAIT_SECONDS", "")
	if sub := sessionBinder(st, noPods{}).(*authorize.Subagents); sub.Wait != 0 {
		t.Fatalf("unset wait %v, want the default (0)", sub.Wait)
	}
}

// A catalog that grants subagents refuses to start on a binder that cannot serve them, rather than refusing every subagent silently.
func TestSubagentsServableRefusesAHalfConfiguredBroker(t *testing.T) {
	cat, err := httpcatalog.Parse([]byte(`{"pools":[{"name":"p","namespace":"cursor","serviceAccount":"w","identity":"cursor-automation","ceiling":"T2"}],
		"entries":[{"name":"e","host":"api.e.example","pathPrefixes":["/v1/"],"methods":["GET"],"header":"Authorization","scheme":"Bearer",
		"placeholder":"__vault_KEY__","key":{"mount":"gatehouse","path":"vendors/x","field":"key"},"pools":["p"]}],
		"automations":[{"id":"a","name":"a","owner":"team","entries":["e"],"subagents":2}]}`))
	if err != nil {
		t.Fatal(err)
	}
	plain := &mitm.HeaderAdapter{Catalog: cat, Sessions: &authorizetest.MemBinder{}}
	if subagentsServable(plain) == nil {
		t.Fatal("a catalog granting subagents started on a binder that serves none")
	}
	served := &mitm.HeaderAdapter{Catalog: cat, Sessions: &authorize.Subagents{Binder: &authorizetest.MemBinder{}}}
	if err := subagentsServable(served); err != nil {
		t.Fatal(err)
	}
}
