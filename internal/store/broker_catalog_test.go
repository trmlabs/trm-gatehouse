package store

import (
	"context"
	"errors"
	"testing"
)

func TestBrokerCatalogKeepsTheNewestVersionPerLocation(t *testing.T) {
	checkBrokerCatalog(t, openTestDB(t))
}

func checkBrokerCatalog(t *testing.T, s *SQLStore) {
	t.Helper()
	ctx := context.Background()
	if _, err := s.db.Exec("DELETE FROM broker_catalog"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.LoadBrokerCatalog(ctx, "kv/catalog"); !errors.Is(err, ErrNoBrokerCatalog) {
		t.Fatalf("empty store: %v", err)
	}
	for _, step := range []struct {
		version int
		doc     string
	}{{3, "v3"}, {5, "v5"}, {4, "v4"}} {
		if err := s.SaveBrokerCatalog(ctx, "kv/catalog", step.version, []byte(step.doc)); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.SaveBrokerCatalog(ctx, "kv/other", 1, []byte("other")); err != nil {
		t.Fatal(err)
	}
	doc, version, err := s.LoadBrokerCatalog(ctx, "kv/catalog")
	if err != nil || version != 5 || string(doc) != "v5" {
		t.Fatalf("stored %q v%d %v, want v5", doc, version, err)
	}
	if err := s.SaveBrokerCatalog(ctx, "kv/catalog", 0, []byte("x")); err == nil {
		t.Fatal("version 0 stored")
	}
}
