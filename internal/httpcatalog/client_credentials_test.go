package httpcatalog

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const clientPath = "gatehouse/data/vendors/internal-api"

func clientEntry(fields string) string {
	return `{"entries":[{"name":"internal-api","host":"api.example.com","pathPrefixes":["/v1/internal/"],"methods":["GET","POST"],` +
		fields + `,"pools":["pool-agent"]}]}`
}

const clientHeader = `"header":"Authorization","scheme":"Bearer","placeholder":"__vault_INTERNAL_API__"`
const clientBinding = `"clientCredentials":{"tokenHost":"example.com","audience":"https://api.example.com","client":{"mount":"gatehouse","path":"vendors/internal-api"}}`

func TestClientCredentialsEntries(t *testing.T) {
	c, err := Parse([]byte(clientEntry(clientHeader + "," + clientBinding)))
	if err != nil {
		t.Fatal(err)
	}
	e := c.Entries()[0]
	if e.ClientCredentials.TokenPath != "/oauth/token" || e.Scheme != "Bearer" || e.Key != (KeyRef{}) || !c.HasTokenHost("EXAMPLE.com") || c.HasTokenHost("api.example.com") {
		t.Fatalf("parsed %+v", e.ClientCredentials)
	}
	key := `"key":{"mount":"gatehouse","path":"vendors/rpc","field":"key"}`
	for name, fields := range map[string]string{
		"a stored key too":        clientHeader + "," + key + "," + clientBinding,
		"no header":               `"placeholder":"__vault_INTERNAL_API__",` + clientBinding,
		"another header":          `"header":"X-Api-Key","scheme":"Bearer","placeholder":"__vault_INTERNAL_API__",` + clientBinding,
		"basic":                   `"header":"Authorization","basicUser":true,"placeholder":"__vault_INTERNAL_API__",` + clientBinding,
		"no scheme":               `"header":"Authorization","placeholder":"__vault_INTERNAL_API__",` + clientBinding,
		"client certificate":      clientHeader + `,"clientCertificate":{"mount":"gatehouse","path":"vendors/cert"},` + clientBinding,
		"IP token host":           clientHeader + `,"clientCredentials":{"tokenHost":"192.0.2.1","client":{"mount":"gatehouse","path":"vendors/internal-api"}}`,
		"wildcard token host":     clientHeader + `,"clientCredentials":{"tokenHost":"*.example.com","client":{"mount":"gatehouse","path":"vendors/internal-api"}}`,
		"token path query":        clientHeader + `,"clientCredentials":{"tokenHost":"example.com","tokenPath":"/oauth/token?x=1","client":{"mount":"gatehouse","path":"vendors/internal-api"}}`,
		"token path traversal":    clientHeader + `,"clientCredentials":{"tokenHost":"example.com","tokenPath":"/a/../token","client":{"mount":"gatehouse","path":"vendors/internal-api"}}`,
		"audience with space":     clientHeader + `,"clientCredentials":{"tokenHost":"example.com","audience":"a b","client":{"mount":"gatehouse","path":"vendors/internal-api"}}`,
		"scope control byte":      clientHeader + `,"clientCredentials":{"tokenHost":"example.com","scope":"read\n","client":{"mount":"gatehouse","path":"vendors/internal-api"}}`,
		"client outside vendors/": clientHeader + `,"clientCredentials":{"tokenHost":"example.com","client":{"mount":"gatehouse","path":"secrets/internal-api"}}`,
		"no client":               clientHeader + `,"clientCredentials":{"tokenHost":"example.com"}`,
		"unknown field":           clientHeader + `,"clientCredentials":{"tokenHost":"example.com","grant":"password","client":{"mount":"gatehouse","path":"vendors/internal-api"}}`,
	} {
		if _, err := Parse([]byte(clientEntry(fields))); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	git := `{"entries":[{"name":"g","kind":"git","host":"github.com","placeholder":"__vault_GIT__",` + clientBinding +
		`,"git":{"appID":1,"installationID":2,"repos":[{"repo":"example/repo","access":"read"}]},"pools":["pool-agent"]}]}`
	if _, err := Parse([]byte(git)); err == nil || !strings.Contains(err.Error(), "clientCredentials") {
		t.Errorf("a git entry with clientCredentials: %v", err)
	}
}

// tokenIssuer is an authorization server for the client-credentials grant.
type tokenIssuer struct {
	server  *httptest.Server
	mints   atomic.Int32
	mu      sync.Mutex
	forms   []map[string]string
	answer  func(w http.ResponseWriter, n int32) // nil: a good token
	release chan struct{}                        // when set, each mint waits for it
}

func newTokenIssuer(t *testing.T) *tokenIssuer {
	t.Helper()
	i := &tokenIssuer{}
	i.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := i.mints.Add(1)
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		if r.Method != http.MethodPost || r.URL.Path != "/oauth/token" || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" || r.ParseForm() != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		form := map[string]string{}
		for k := range r.PostForm {
			form[k] = r.PostForm.Get(k)
		}
		i.mu.Lock()
		i.forms = append(i.forms, form)
		release := i.release
		i.mu.Unlock()
		if release != nil {
			<-release
		}
		if i.answer != nil {
			i.answer(w, n)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":"minted-%d-for-%s","expires_in":3600,"token_type":"Bearer"}`, n, form["client_secret"])
	}))
	t.Cleanup(i.server.Close)
	return i
}

func (i *tokenIssuer) lastForm() map[string]string {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.forms[len(i.forms)-1]
}

// client reaches the issuer for any address, trusting its certificate, which
// names example.com.
func (i *tokenIssuer) client() *http.Client {
	tr := i.server.Client().Transport.(*http.Transport).Clone()
	addr := i.server.Listener.Addr().String()
	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	return &http.Client{Transport: tr}
}

type clientFixture struct {
	issuer *tokenIssuer
	vault  *certVault
	tokens *ClientTokens
	entry  *Entry
	now    time.Time
	mu     sync.Mutex
}

func newClientFixture(t *testing.T) *clientFixture {
	t.Helper()
	c, err := Parse([]byte(clientEntry(clientHeader + "," + clientBinding)))
	if err != nil {
		t.Fatal(err)
	}
	f := &clientFixture{issuer: newTokenIssuer(t), vault: newCertVault(), now: time.Now()}
	f.vault.setFields(clientPath, map[string]interface{}{"client_id": "client-one", "client_secret": "secret-one"})
	clock := func() time.Time { f.mu.Lock(); defer f.mu.Unlock(); return f.now }
	f.tokens = &ClientTokens{Keys: &Keys{Vault: f.vault, Now: clock}, Client: f.issuer.client(), Now: clock}
	f.entry = &c.Entries()[0]
	return f
}

func (f *clientFixture) advance(d time.Duration) { f.mu.Lock(); f.now = f.now.Add(d); f.mu.Unlock() }

func TestClientTokensMintCacheAndRenew(t *testing.T) {
	f := newClientFixture(t)
	ctx := context.Background()
	first, err := f.tokens.Token(ctx, f.entry)
	if err != nil || first.Value() != "minted-1-for-secret-one" || first.Version != 1 {
		t.Fatalf("first token: %v %v", first, err)
	}
	form := f.issuer.lastForm()
	if form["grant_type"] != "client_credentials" || form["client_id"] != "client-one" || form["client_secret"] != "secret-one" ||
		form["audience"] != "https://api.example.com" || len(form) != 4 {
		t.Fatalf("token request %v", form)
	}
	// Printing never shows the token.
	if printed := fmt.Sprint(first) + fmt.Sprintf("%#v", first); strings.Contains(printed, "minted") {
		t.Fatalf("printed as %q", printed)
	}
	// Served from memory until a quarter of its hour remains.
	f.advance(44 * time.Minute)
	if again, err := f.tokens.Token(ctx, f.entry); err != nil || again.Value() != first.Value() || f.issuer.mints.Load() != 1 {
		t.Fatalf("cached token: %v %v mints=%d", again, err, f.issuer.mints.Load())
	}
	f.advance(2 * time.Minute)
	if renewed, err := f.tokens.Token(ctx, f.entry); err != nil || renewed.Value() != "minted-2-for-secret-one" {
		t.Fatalf("renewed token: %v %v", renewed, err)
	}
}

func TestClientTokensShareOneMint(t *testing.T) {
	f := newClientFixture(t)
	f.issuer.release = make(chan struct{})
	var wg sync.WaitGroup
	got := make([]string, 20)
	for n := range got {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if s, err := f.tokens.Token(context.Background(), f.entry); err == nil {
				got[n] = s.Value()
			}
		}()
	}
	time.Sleep(50 * time.Millisecond)
	close(f.issuer.release)
	wg.Wait()
	for _, v := range got {
		if v != "minted-1-for-secret-one" {
			t.Fatalf("tokens %v", got)
		}
	}
	if f.issuer.mints.Load() != 1 {
		t.Fatalf("mints %d", f.issuer.mints.Load())
	}
}

// A new client version mints a new token once Keys reads it; a client deleted
// in Vault is refused even while a token is held.
func TestClientTokensFollowVault(t *testing.T) {
	f := newClientFixture(t)
	ctx := context.Background()
	if _, err := f.tokens.Token(ctx, f.entry); err != nil {
		t.Fatal(err)
	}
	f.vault.setFields(clientPath, map[string]interface{}{"client_id": "client-one", "client_secret": "secret-two"})
	f.advance(61 * time.Second)
	if rotated, err := f.tokens.Token(ctx, f.entry); err != nil || rotated.Value() != "minted-2-for-secret-two" || rotated.Version != 2 {
		t.Fatalf("rotated client: %v %v", rotated, err)
	}
	f.vault.setFields(clientPath, map[string]interface{}{"client_id": "client-one"})
	f.advance(61 * time.Second)
	if _, err := f.tokens.Token(ctx, f.entry); !errors.Is(err, ErrKeyDeleted) {
		t.Fatalf("deleted client: %v", err)
	}
	if f.issuer.mints.Load() != 2 {
		t.Fatalf("mints %d", f.issuer.mints.Load())
	}
}

func TestClientTokensRefuseBadAnswers(t *testing.T) {
	for name, answer := range map[string]func(http.ResponseWriter, int32){
		"refused": func(w http.ResponseWriter, _ int32) { w.WriteHeader(http.StatusUnauthorized) },
		"redirect": func(w http.ResponseWriter, _ int32) {
			http.Redirect(w, &http.Request{}, "https://example.net/oauth/token", http.StatusTemporaryRedirect)
		},
		"not a bearer": func(w http.ResponseWriter, _ int32) {
			fmt.Fprint(w, `{"access_token":"t","expires_in":3600,"token_type":"mac"}`)
		},
		"short-lived": func(w http.ResponseWriter, _ int32) {
			fmt.Fprint(w, `{"access_token":"t","expires_in":30,"token_type":"Bearer"}`)
		},
		"not for header": func(w http.ResponseWriter, _ int32) {
			fmt.Fprint(w, `{"access_token":"t t","expires_in":3600,"token_type":"Bearer"}`)
		},
		"no token": func(w http.ResponseWriter, _ int32) { fmt.Fprint(w, `{"expires_in":3600,"token_type":"Bearer"}`) },
		"not JSON": func(w http.ResponseWriter, _ int32) { fmt.Fprint(w, `access_token=t`) },
	} {
		t.Run(name, func(t *testing.T) {
			f := newClientFixture(t)
			f.issuer.answer = answer
			if _, err := f.tokens.Token(context.Background(), f.entry); !errors.Is(err, ErrClientToken) {
				t.Fatalf("accepted: %v", err)
			}
			if f.issuer.mints.Load() != 1 {
				t.Fatalf("mints %d", f.issuer.mints.Load())
			}
		})
	}
}

// A failed mint refuses without asking again for ten seconds; then it asks.
func TestClientTokensWaitAfterAFailedMint(t *testing.T) {
	f := newClientFixture(t)
	f.issuer.answer = func(w http.ResponseWriter, n int32) {
		if n == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		fmt.Fprint(w, `{"access_token":"second","expires_in":3600,"token_type":"Bearer"}`)
	}
	ctx := context.Background()
	for range 3 {
		if _, err := f.tokens.Token(ctx, f.entry); !errors.Is(err, ErrClientToken) {
			t.Fatalf("after a failed mint: %v", err)
		}
	}
	if f.issuer.mints.Load() != 1 {
		t.Fatalf("mints %d", f.issuer.mints.Load())
	}
	f.advance(11 * time.Second)
	if s, err := f.tokens.Token(ctx, f.entry); err != nil || s.Value() != "second" {
		t.Fatalf("retry: %v %v", s, err)
	}
}

// A refused token is minted again only once it is a minute old.
func TestClientTokensInvalidateKeepsAYoungToken(t *testing.T) {
	f := newClientFixture(t)
	ctx := context.Background()
	first, _ := f.tokens.Token(ctx, f.entry)
	f.tokens.Invalidate(f.entry)
	if again, _ := f.tokens.Token(ctx, f.entry); again.Value() != first.Value() {
		t.Fatalf("a young token was dropped: %v", again)
	}
	f.advance(61 * time.Second)
	f.tokens.Invalidate(f.entry)
	if again, _ := f.tokens.Token(ctx, f.entry); again.Value() != "minted-2-for-secret-one" {
		t.Fatalf("an old refused token was kept: %v", again)
	}
}

func TestClientTokensPruneRemovedEntries(t *testing.T) {
	f := newClientFixture(t)
	if _, err := f.tokens.Token(context.Background(), f.entry); err != nil {
		t.Fatal(err)
	}
	f.tokens.Prune(Catalog{entries: []Entry{*f.entry}})
	if len(f.tokens.states) != 1 {
		t.Fatal("a listed entry's token was dropped")
	}
	f.tokens.Prune(Catalog{})
	if len(f.tokens.states) != 0 {
		t.Fatal("a removed entry's token was kept")
	}
}
