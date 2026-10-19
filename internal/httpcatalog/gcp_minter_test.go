package httpcatalog

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

// gcpMinterFixture is a broker that started with no gcp entry: a live Source
// watching loader, a minter following it, and a fake IAM Credentials that
// counts the tokens it mints.
type gcpMinterFixture struct {
	loader *scriptedLoader
	source *Source
	minter *GCPMinter
	entry  Entry
	builds atomic.Int32
	mints  atomic.Int32
	// applied counts the catalog versions every hook has seen; published, those
	// sent to the loader.
	applied   atomic.Int32
	published int32
}

func newGCPMinterFixture(t *testing.T) *gcpMinterFixture {
	t.Helper()
	f := &gcpMinterFixture{entry: gcpCatalog(t, bqEntry).Entries()[0]}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mints.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{"accessToken": "impersonated", "expireTime": time.Now().Add(15 * time.Minute).UTC().Format(time.RFC3339)})
	}))
	t.Cleanup(srv.Close)
	f.minter = &GCPMinter{Build: func() (*GCPTokens, error) {
		f.builds.Add(1)
		return &GCPTokens{Root: staticRoot{&oauth2.Token{AccessToken: "root-token", Expiry: time.Now().Add(time.Hour)}}, Client: srv.Client(),
			STSURL: srv.URL + "/v1/token", IAMCredentialsURL: srv.URL}, nil
	}}
	f.loader = &scriptedLoader{doc: `{"entries":[` + validEntry + `]}`, version: 1}
	source, err := Open(context.Background(), f.loader.load)
	if err != nil {
		t.Fatal(err)
	}
	f.source = source
	f.minter.Follow(source.Current())
	source.OnChange(f.minter.Follow)
	source.OnChange(func(Catalog) { f.applied.Add(1) }) // runs after the minter's hook
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go source.Watch(ctx, 5*time.Millisecond, f.loader.load, func(int, error) {})
	return f
}

func (f *gcpMinterFixture) mint() error {
	_, err := f.minter.Token(context.Background(), &f.entry)
	return err
}

// publish makes doc the catalog version and waits until the minter has seen it.
func (f *gcpMinterFixture) publish(t *testing.T, doc string, version int) {
	t.Helper()
	f.published++
	f.loader.set(doc, version, nil)
	waitFor(t, "the catalog version", func() bool { return f.applied.Load() == f.published })
}

// A broker started with no gcp entry mints once a catalog version adds one,
// without a restart, and lets the minter go when the last one is removed.
func TestGCPMinterFollowsTheCatalog(t *testing.T) {
	f := newGCPMinterFixture(t)
	if err := f.mint(); !errors.Is(err, ErrGCPToken) || f.builds.Load() != 0 {
		t.Fatalf("no gcp entry: %v, %d builds", err, f.builds.Load())
	}
	gcpDoc := `{` + gcpPools + `,"entries":[` + bqEntry + `]}`
	f.publish(t, gcpDoc, 2)
	if err := f.mint(); err != nil || f.builds.Load() != 1 || f.mints.Load() != 1 {
		t.Fatalf("first gcp entry: %v, %d builds, %d mints", err, f.builds.Load(), f.mints.Load())
	}
	// More versions with gcp entries keep the minter, and its cached token.
	f.publish(t, `{`+gcpPools+`,"entries":[`+bqEntry+`,`+gcsEntry+`]}`, 3)
	if err := f.mint(); err != nil || f.builds.Load() != 1 || f.mints.Load() != 1 {
		t.Fatalf("another gcp version: %v, %d builds, %d mints", err, f.builds.Load(), f.mints.Load())
	}
	// The last gcp entry goes: the minter goes with it.
	f.publish(t, `{"entries":[`+validEntry+`]}`, 4)
	if err := f.mint(); !errors.Is(err, ErrGCPToken) {
		t.Fatalf("last gcp entry removed: %v", err)
	}
	// And a later gcp entry builds a new one.
	f.publish(t, gcpDoc, 5)
	if err := f.mint(); err != nil || f.builds.Load() != 2 {
		t.Fatalf("gcp entry again: %v, %d builds, want 2", err, f.builds.Load())
	}
}

// An invalid gcp entry is left out of its catalog version, so it never builds
// a minter and its requests are refused; the next valid version mints.
func TestGCPMinterRefusesAnInvalidEntry(t *testing.T) {
	f := newGCPMinterFixture(t)
	invalid := strings.Replace(bqEntry, "bigquery.googleapis.com", "iamcredentials.googleapis.com", 1)
	f.publish(t, `{`+gcpPools+`,"entries":[`+invalid+`]}`, 2)
	if dropped := f.source.Dropped(); len(dropped) != 1 || dropped[0].Name != "bq-cases" {
		t.Fatalf("dropped %v, want the invalid entry", dropped)
	}
	if err := f.mint(); !errors.Is(err, ErrGCPToken) || f.builds.Load() != 0 {
		t.Fatalf("invalid entry: %v, %d builds", err, f.builds.Load())
	}
	f.publish(t, `{`+gcpPools+`,"entries":[`+bqEntry+`]}`, 3)
	if err := f.mint(); err != nil {
		t.Fatalf("corrected entry: %v", err)
	}
}

// A broker with no Google identity still serves; each catalog change tries
// again, and the first change that finds an identity gives it a minter.
func TestGCPMinterRefusesUntilItCanBuild(t *testing.T) {
	var failed []error
	identity := errors.New("no identity")
	minter := &GCPMinter{Failed: func(err error) { failed = append(failed, err) }}
	minter.Build = func() (*GCPTokens, error) {
		if identity != nil {
			return nil, identity
		}
		return &GCPTokens{}, nil
	}
	c := gcpCatalog(t, bqEntry)
	entry := c.Entries()[0]
	minter.Follow(c)
	if _, err := minter.Token(context.Background(), &entry); !errors.Is(err, ErrGCPToken) || len(failed) != 1 {
		t.Fatalf("no identity: %v, %d failures", err, len(failed))
	}
	minter.Invalidate(&entry) // nothing to invalidate yet
	identity = nil
	minter.Follow(c)
	if minter.cur.Load() == nil || len(failed) != 1 {
		t.Fatalf("identity found: %d failures", len(failed))
	}
}
