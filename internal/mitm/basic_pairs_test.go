package mitm

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/Infisical/agent-vault/internal/auditchain"
	"github.com/Infisical/agent-vault/internal/authorize/authorizetest"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/entitlement"
	"github.com/Infisical/agent-vault/internal/httpcatalog"
	"github.com/Infisical/agent-vault/internal/store"
	vaultapi "github.com/hashicorp/vault/api"
)

const (
	basicPairsAlphaUser   = "pk-selector-alpha"
	basicPairsBetaUser    = "pk-selector-beta"
	basicPairsAlphaPath   = "gatehouse/data/vendors/langfuse-alpha"
	basicPairsBetaPath    = "gatehouse-secondary/data/vendors/langfuse-beta"
	basicPairsPlaceholder = "__vault_LLM_KEY__"
)

type basicPairsVault struct {
	mu     sync.Mutex
	values map[string]map[string]interface{}
	reads  map[string]int
}

func (v *basicPairsVault) ReadWithDataWithContext(_ context.Context, path string, _ map[string][]string) (*vaultapi.Secret, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.reads[path]++
	fields, ok := v.values[path]
	if !ok {
		return nil, nil
	}
	data := map[string]interface{}{}
	for name, value := range fields {
		data[name] = value
	}
	return &vaultapi.Secret{Data: map[string]interface{}{"data": data, "metadata": map[string]interface{}{"version": float64(1)}}}, nil
}

func (v *basicPairsVault) readCount(path string) int {
	v.mu.Lock()
	defer v.mu.Unlock()
	if path != "" {
		return v.reads[path]
	}
	var total int
	for _, n := range v.reads {
		total += n
	}
	return total
}

type basicPairsFixture struct {
	*adapterFixture
	vault           *basicPairsVault
	mu              sync.Mutex
	passwords       map[string]string
	rejectionStatus int
}

func newBasicPairsFixture(t *testing.T, edits ...func(string) string) *basicPairsFixture {
	t.Helper()
	v := &basicPairsVault{values: map[string]map[string]interface{}{
		basicPairsAlphaPath: {"pair": basicPairsAlphaUser + ":" + adapterKeyV1},
		basicPairsBetaPath:  {"credentials": basicPairsBetaUser + ":" + adapterKeyV2},
	}, reads: map[string]int{}}
	f := &basicPairsFixture{vault: v, passwords: map[string]string{basicPairsAlphaUser: adapterKeyV1, basicPairsBetaUser: adapterKeyV2}, rejectionStatus: http.StatusUnauthorized}
	f.adapterFixture = newAdapterFixtureWith(t, "basicPair", func(o *Options) {
		port := o.HeaderAdapter.Catalog.Current().Entries()[0].Port
		doc := fmt.Sprintf(`{"entries":[{"name":"llm","host":"example.com","port":%d,"pathPrefixes":["/v1"],"methods":["GET","POST"],
		 "header":"Authorization","basicPair":true,"pairUserHeader":"X-Langfuse-Public-Key","placeholder":"__vault_LLM_KEY__","pools":["pool-agent"],
		 "basicPairs":[
		 {"name":"project-alpha","user":"pk-selector-alpha","key":{"mount":"gatehouse","path":"vendors/langfuse-alpha","field":"pair"}},
		 {"name":"project-beta","user":"pk-selector-beta","key":{"mount":"gatehouse-secondary","path":"vendors/langfuse-beta","field":"credentials"}}]}]}`, port)
		for _, edit := range edits {
			doc = edit(doc)
		}
		catalog, err := httpcatalog.Parse([]byte(doc))
		if err != nil {
			t.Fatalf("valid fixed Basic-pair bindings refused: %v", err)
		}
		o.HeaderAdapter.Catalog, o.HeaderAdapter.Keys = catalog, &httpcatalog.Keys{Vault: v}
	})
	f.vendor.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.calls.Add(1)
		f.seen.Store(r.Header.Clone())
		user, password, ok := r.BasicAuth()
		f.mu.Lock()
		want, present := f.passwords[user]
		status := f.rejectionStatus
		f.mu.Unlock()
		if !ok || !present || password != want {
			w.WriteHeader(status)
			return
		}
		switch r.URL.Path {
		case "/v1/echo-password":
			io.WriteString(w, password) // #nosec G705 -- test upstream echoing a synthetic credential
		case "/v1/echo-pair":
			io.WriteString(w, user+":"+password) // #nosec G705 -- test upstream echoing a synthetic credential
		case "/v1/echo-encoded":
			io.WriteString(w, strings.TrimPrefix(r.Header.Get("Authorization"), "Basic ")) // #nosec G705 -- test upstream echoing a synthetic credential
		case "/v1/echo-header":
			w.Header().Set("X-Echo", password)
			io.WriteString(w, "ok")
		case "/v1/public-user":
			io.WriteString(w, user) // #nosec G705 -- test upstream echoing a synthetic public user
		default:
			io.WriteString(w, "ok")
		}
	})
	return f
}

func basicPairsAuth(user, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+password))
}

func (f *basicPairsFixture) request(t *testing.T, user, method, path string, mutate func(*http.Request)) (int, string, error) {
	t.Helper()
	f.mu.Lock()
	f.acceptsV = user + ":" + f.passwords[user]
	f.mu.Unlock()
	return f.do(t, method, path, "", func(r *http.Request) {
		r.SetBasicAuth(user, basicPairsPlaceholder)
		if mutate != nil {
			mutate(r)
		}
	})
}

func assertBasicPairsBinding(t *testing.T, binding, selected, other string) {
	t.Helper()
	if !strings.Contains(binding, selected) || strings.Contains(binding, other) {
		t.Fatalf("audit binding %q does not identify selected %q exclusively", binding, selected)
	}
}

func TestBasicPairsSelectExactlyTheDeclaredVaultReference(t *testing.T) {
	f := newBasicPairsFixture(t)
	for _, tc := range []struct{ user, path, binding, other string }{
		{basicPairsAlphaUser, basicPairsAlphaPath, "project-alpha", "project-beta"},
		{basicPairsBetaUser, basicPairsBetaPath, "project-beta", "project-alpha"},
	} {
		t.Run(tc.binding, func(t *testing.T) {
			before := f.vault.readCount("")
			code, body, err := f.request(t, tc.user, "POST", "/v1/traces", func(r *http.Request) { r.Header.Set("X-Langfuse-Public-Key", tc.user) })
			if err != nil || code != 200 || body != "ok" || f.vault.readCount("") != before+1 || f.vault.readCount(tc.path) != 1 {
				t.Fatalf("selected request status=%d err=%v Vault reads=%d", code, err, f.vault.readCount(""))
			}
			seen := f.seen.Load().(http.Header)
			if seen.Get("X-Langfuse-Public-Key") != tc.user || seen.Get("Authorization") == basicPairsAuth(tc.user, basicPairsPlaceholder) {
				t.Fatal("vendor did not receive the selected pair and public user")
			}
			rows := f.audit.all()
			for i, kind := range []string{auditchain.EventHTTPRequest, auditchain.EventHTTPResponse} {
				row := rows[len(rows)-2+i]
				if row.Event != kind || row.Pool != "pool-agent" || row.Agent != "agent-uuid-1" || row.PodUID != "pod-uid-1" {
					t.Fatalf("missing request attribution: %+v", row)
				}
				assertBasicPairsBinding(t, row.Binding, tc.binding, tc.other)
			}
		})
	}
	if code, _, err := f.request(t, basicPairsAlphaUser, "GET", "/v1/traces", nil); err != nil || code != 200 || f.vault.readCount(basicPairsAlphaPath) != 1 {
		t.Fatalf("binding cache not reused: status=%d err=%v", code, err)
	}
}

func TestBasicPairsSelectWithAuthorizationOnly(t *testing.T) {
	f := newBasicPairsFixture(t, func(doc string) string {
		return strings.Replace(doc, `"pairUserHeader":"X-Langfuse-Public-Key",`, ``, 1)
	})
	for _, user := range []string{basicPairsAlphaUser, basicPairsBetaUser} {
		if code, body, err := f.request(t, user, "GET", "/v1/traces", nil); err != nil || code != 200 || body != "ok" {
			t.Fatalf("Authorization-only selection status=%d err=%v", code, err)
		}
		if f.seen.Load().(http.Header).Get("X-Langfuse-Public-Key") != "" {
			t.Fatal("Authorization-only selection synthesized an optional public-user header")
		}
	}
	if f.vault.readCount(basicPairsAlphaPath) != 1 || f.vault.readCount(basicPairsBetaPath) != 1 || f.vault.readCount("") != 2 {
		t.Fatal("Authorization-only selection did not read exactly the declared references")
	}
}

func TestBasicPairsRejectSelectorsBeforeAnyCredentialRead(t *testing.T) {
	f := newBasicPairsFixture(t)
	valid := basicPairsAuth(basicPairsAlphaUser, basicPairsPlaceholder)
	for name, values := range map[string]http.Header{
		"missing":                            {},
		"bare placeholder":                   {"Authorization": {basicPairsPlaceholder}},
		"both placeholders":                  {"Authorization": {basicPairsAuth(basicPairsPlaceholder, basicPairsPlaceholder)}},
		"placeholders with public user":      {"Authorization": {basicPairsAuth(basicPairsPlaceholder, basicPairsPlaceholder)}, "X-Langfuse-Public-Key": {basicPairsAlphaUser}},
		"username placeholder":               {"Authorization": {basicPairsAuth(basicPairsPlaceholder, "")}},
		"user header only":                   {"X-Langfuse-Public-Key": {basicPairsAlphaUser}},
		"unknown user":                       {"Authorization": {basicPairsAuth("pk-selector-unknown", basicPairsPlaceholder)}},
		"user case change":                   {"Authorization": {basicPairsAuth(strings.ToUpper(basicPairsAlphaUser), basicPairsPlaceholder)}},
		"literal password":                   {"Authorization": {basicPairsAuth(basicPairsAlphaUser, "synthetic-unapproved")}},
		"another placeholder":                {"Authorization": {basicPairsAuth(basicPairsAlphaUser, "__vault_OTHER__")}},
		"placeholder suffix":                 {"Authorization": {basicPairsAuth(basicPairsAlphaUser, "x"+basicPairsPlaceholder)}},
		"empty user":                         {"Authorization": {basicPairsAuth("", basicPairsPlaceholder)}},
		"colon in user":                      {"Authorization": {basicPairsAuth(basicPairsAlphaUser+":extra", basicPairsPlaceholder)}},
		"malformed encoding":                 {"Authorization": {"Basic !!!"}},
		"missing padding":                    {"Authorization": {strings.TrimRight(valid, "=")}},
		"Bearer":                             {"Authorization": {"Bearer " + basicPairsPlaceholder}},
		"two Authorization values":           {"Authorization": {valid, valid}},
		"contradictory Authorization values": {"Authorization": {valid, basicPairsAuth(basicPairsBetaUser, basicPairsPlaceholder)}},
		"coalesced Authorization":            {"Authorization": {valid + ", " + valid}},
		"contradictory user header":          {"Authorization": {valid}, "X-Langfuse-Public-Key": {basicPairsBetaUser}},
		"placeholder in user header":         {"Authorization": {valid}, "X-Langfuse-Public-Key": {basicPairsPlaceholder}},
		"empty user header":                  {"Authorization": {valid}, "X-Langfuse-Public-Key": {""}},
		"duplicate user header":              {"Authorization": {valid}, "X-Langfuse-Public-Key": {basicPairsAlphaUser, basicPairsAlphaUser}},
		"contradictory user headers":         {"Authorization": {valid}, "X-Langfuse-Public-Key": {basicPairsAlphaUser, basicPairsBetaUser}},
		"coalesced user header":              {"Authorization": {valid}, "X-Langfuse-Public-Key": {basicPairsAlphaUser + ", " + basicPairsBetaUser}},
	} {
		t.Run(name, func(t *testing.T) {
			code, _, err := f.request(t, basicPairsAlphaUser, "POST", "/v1/traces", func(r *http.Request) {
				r.Header.Del("Authorization")
				for name, v := range values {
					r.Header[name] = v
				}
			})
			if err != nil || code != 400 || f.vault.readCount("") != 0 || f.calls.Load() != 0 {
				t.Fatalf("selector status=%d err=%v Vault reads=%d upstream calls=%d", code, err, f.vault.readCount(""), f.calls.Load())
			}
		})
	}
}

func TestBasicPairsKeepAuthorizationAheadOfCredentialReads(t *testing.T) {
	for _, tc := range []struct {
		name, method, path, outcome string
		status                      int
	}{
		{"method", "DELETE", "/v1/traces", "method", http.StatusMethodNotAllowed},
		{"path", "GET", "/outside", "unlisted", http.StatusForbidden},
		{"pool", "GET", "/v1/traces", "pool", http.StatusForbidden},
		{"initiator", "GET", "/v1/traces", "no_person", http.StatusForbidden},
		{"verified non-member", "GET", "/v1/traces", "not_entitled", http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var edits []func(string) string
			if tc.name == "initiator" || tc.name == "verified non-member" {
				edits = append(edits, func(doc string) string {
					pool := strings.Replace(requesterPool, `"identity":"claude-session"`, `"identity":"claude-session","ceiling":"T1"`, 1)
					doc = strings.Replace(doc, `{"entries":`, `{`+pool+`"entries":`, 1)
					return strings.Replace(doc, `"name":"llm"`, `"name":"llm","tier":"T1","requires":["`+authzGroup+`"]`, 1)
				})
			}
			f := newBasicPairsFixture(t, edits...)
			if tc.name == "verified non-member" {
				f.proxy.adapter.Runner = requesterRunner
				f.proxy.adapter.Sessions = &authorizetest.MemBinder{}
				f.proxy.adapter.Entitlements = &entitlement.Cache{Source: directory{"bob@example.com": {}}}
				f.client.Transport.(*http.Transport).ProxyConnectHeader = http.Header{SessionHeader: {"bob"}}
			}
			if tc.name == "pool" {
				if code, _, err := f.request(t, basicPairsAlphaUser, "GET", "/outside", nil); err != nil || code != 403 {
					t.Fatalf("open tunnel without credential access: status=%d err=%v", code, err)
				}
				f.sessions.set(&brokercore.ProxyScope{VaultID: "vault-1", AgentID: "agent-uuid-1", Pool: "ungranted", WorkloadID: "pod-uid-1", VaultRole: "proxy"})
			}
			for name, header := range map[string]string{
				"valid selector":     basicPairsAuth(basicPairsAlphaUser, basicPairsPlaceholder),
				"unknown selector":   basicPairsAuth("pk-selector-unknown", basicPairsPlaceholder),
				"malformed selector": "Basic !!!",
			} {
				t.Run(name, func(t *testing.T) {
					code, _, err := f.request(t, basicPairsAlphaUser, tc.method, tc.path, func(r *http.Request) { r.Header.Set("Authorization", header) })
					row := f.audit.last()
					if err != nil || code != tc.status || f.vault.readCount("") != 0 || f.calls.Load() != 0 || row.Outcome != tc.outcome {
						t.Fatalf("authorization status=%d err=%v Vault reads=%d upstream calls=%d outcome=%q", code, err, f.vault.readCount(""), f.calls.Load(), row.Outcome)
					}
					if tc.name == "verified non-member" && (row.Requester != "bob@example.com" || row.TokenSHA256 != "bb") {
						t.Fatal("entitlement refusal did not identify the verified requester")
					}
				})
			}
		})
	}
}

func TestBasicPairsVerifyTheSelectedStoredPublicUser(t *testing.T) {
	for name, value := range map[string]string{
		"other declared user": basicPairsBetaUser + ":" + adapterKeyV1,
		"unlisted user":       "pk-selector-unknown:" + adapterKeyV1,
		"no pair":             adapterKeyV1,
		"no password":         basicPairsAlphaUser + ":",
	} {
		t.Run(name, func(t *testing.T) {
			f := newBasicPairsFixture(t)
			f.vault.values[basicPairsAlphaPath]["pair"] = value
			code, _, err := f.request(t, basicPairsAlphaUser, "GET", "/v1/traces", nil)
			if err != nil || code < 400 || f.calls.Load() != 0 || f.vault.readCount(basicPairsAlphaPath) != 1 || f.vault.readCount(basicPairsBetaPath) != 0 {
				t.Fatalf("invalid stored pair status=%d err=%v Vault reads=%d upstream calls=%d", code, err, f.vault.readCount(""), f.calls.Load())
			}
			assertBasicPairsBinding(t, f.audit.last().Binding, "project-alpha", "project-beta")
			if code, _, err := f.request(t, basicPairsBetaUser, "GET", "/v1/traces", nil); err != nil || code != 200 {
				t.Fatalf("unaffected binding status=%d err=%v", code, err)
			}
		})
	}
}

func TestBasicPairsRotationDeletionAndInvalidationStayOnTheSelectedReference(t *testing.T) {
	for _, rejected := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		for _, deleted := range []bool{false, true} {
			t.Run(fmt.Sprintf("rejected-%d/deleted-%t", rejected, deleted), func(t *testing.T) {
				f := newBasicPairsFixture(t)
				for _, user := range []string{basicPairsAlphaUser, basicPairsBetaUser} {
					if code, _, err := f.request(t, user, "GET", "/v1/traces", nil); err != nil || code != 200 {
						t.Fatalf("warm cache status=%d err=%v", code, err)
					}
				}
				f.mu.Lock()
				f.passwords[basicPairsAlphaUser], f.rejectionStatus = "synthetic-rotated-alpha-8ed5c7", rejected
				f.mu.Unlock()
				f.vault.mu.Lock()
				if deleted {
					delete(f.vault.values, basicPairsAlphaPath)
				} else {
					f.vault.values[basicPairsAlphaPath]["pair"] = basicPairsAlphaUser + ":synthetic-rotated-alpha-8ed5c7"
				}
				f.vault.mu.Unlock()
				if code, _, err := f.request(t, basicPairsAlphaUser, "GET", "/v1/traces", nil); err != nil || code != rejected {
					t.Fatalf("vendor rejection status=%d err=%v", code, err)
				}
				if code, _, err := f.request(t, basicPairsBetaUser, "GET", "/v1/traces", nil); err != nil || code != 200 || f.vault.readCount(basicPairsBetaPath) != 1 {
					t.Fatalf("other binding was invalidated: status=%d err=%v reads=%d", code, err, f.vault.readCount(basicPairsBetaPath))
				}
				want := 200
				if deleted {
					want = http.StatusServiceUnavailable
				}
				before := f.calls.Load()
				code, _, err := f.request(t, basicPairsAlphaUser, "GET", "/v1/traces", nil)
				if err != nil || code != want || f.vault.readCount(basicPairsAlphaPath) != 2 || f.vault.readCount(basicPairsBetaPath) != 1 {
					t.Fatalf("selected refresh status=%d err=%v alpha reads=%d beta reads=%d", code, err, f.vault.readCount(basicPairsAlphaPath), f.vault.readCount(basicPairsBetaPath))
				}
				if deleted && (f.calls.Load() != before || f.audit.last().Outcome != "key_deleted") {
					t.Fatal("deleted selected key reached the vendor or retained a stale cached value")
				}
				assertBasicPairsBinding(t, f.audit.last().Binding, "project-alpha", "project-beta")
			})
		}
	}
}

func TestBasicPairsScreenTheSelectedSecretAndAllowItsPublicUser(t *testing.T) {
	f := newBasicPairsFixture(t)
	for _, user := range []string{basicPairsAlphaUser, basicPairsBetaUser} {
		for _, path := range []string{"/v1/echo-password", "/v1/echo-pair", "/v1/echo-encoded", "/v1/echo-header"} {
			t.Run(user+path, func(t *testing.T) {
				f.request(t, user, "GET", path, nil)
				if row := f.audit.last(); row.Event != auditchain.EventHTTPResponse || (row.Outcome != "secret_echo" && row.Outcome != "response_refused") {
					t.Fatalf("selected secret echo was not screened: %+v", row)
				}
			})
		}
		if code, body, err := f.request(t, user, "GET", "/v1/public-user", nil); err != nil || code != 200 || body != user {
			t.Fatalf("non-secret user was screened: status=%d err=%v", code, err)
		}
	}
}

type basicPairsAuditMaterial struct {
	key     auditchain.Key
	private ed25519.PrivateKey
}

func (m basicPairsAuditMaterial) Current(context.Context) (auditchain.Key, error) { return m.key, nil }
func (m basicPairsAuditMaterial) Sign(_ context.Context, input []byte) (string, error) {
	return "vault:v1:" + base64.StdEncoding.EncodeToString(ed25519.Sign(m.private, input)), nil
}
func (basicPairsAuditMaterial) BeginAuditBoot(context.Context, string) (uint64, store.AuditBoot, error) {
	return 1, store.AuditBoot{}, nil
}
func (basicPairsAuditMaterial) RecordAuditCheckpoint(context.Context, string, uint64, uint64, string) error {
	return nil
}

func TestBasicPairsSelectedBindingSurvivesSignedAuditAndHasNoSecret(t *testing.T) {
	f := newBasicPairsFixture(t)
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	keyBytes := bytes.Repeat([]byte{0x57}, 32)
	key, err := auditchain.NewKey(1, keyBytes)
	if err != nil {
		t.Fatal(err)
	}
	material := basicPairsAuditMaterial{key: key, private: private}
	var auditOut, logs bytes.Buffer
	chain, err := auditchain.New(context.Background(), auditchain.Options{Out: &auditOut, Replica: "selector-test", Keys: material, Signer: material, Boots: material})
	if err != nil {
		t.Fatal(err)
	}
	f.proxy.adapter.Audit = chain
	f.proxy.logger = slog.New(slog.NewJSONHandler(&logs, nil))
	for _, request := range []struct{ user, path string }{
		{basicPairsAlphaUser, "/v1/audit-alpha"},
		{basicPairsBetaUser, "/v1/audit-beta"},
	} {
		if code, _, err := f.request(t, request.user, "GET", request.path, nil); err != nil || code != 200 {
			t.Fatalf("signed request status=%d err=%v", code, err)
		}
	}
	f.vault.mu.Lock()
	delete(f.vault.values, basicPairsAlphaPath)
	f.vault.mu.Unlock()
	f.proxy.adapter.Keys.Invalidate(httpcatalog.KeyRef{Mount: "gatehouse", Path: "vendors/langfuse-alpha", Field: "pair"})
	if code, _, err := f.request(t, basicPairsAlphaUser, "GET", "/v1/audit-alpha-refused", nil); err != nil || code != 503 {
		t.Fatalf("signed selected refusal status=%d err=%v", code, err)
	}
	if err := chain.Checkpoint(context.Background()); err != nil {
		t.Fatal(err)
	}
	verifier := auditchain.Verifier{HMACKey: func(int) ([]byte, error) { return keyBytes, nil }, PublicKeys: map[int]ed25519.PublicKey{1: public}}
	if report, err := verifier.Verify(strings.NewReader(auditOut.String())); err != nil || len(report.Findings) != 0 {
		t.Fatalf("selected-binding audit did not verify: findings=%v err=%v", report.Findings, err)
	}
	seen := map[string]bool{}
	expectedBindings := map[string]string{
		"/v1/audit-alpha":         "project-alpha",
		"/v1/audit-beta":          "project-beta",
		"/v1/audit-alpha-refused": "project-alpha",
	}
	decoder := json.NewDecoder(strings.NewReader(auditOut.String()))
	for {
		var row auditchain.Row
		err := decoder.Decode(&row)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if row.Event == auditchain.EventHTTPRequest || row.Event == auditchain.EventHTTPResponse || (row.Event == auditchain.EventDenied && row.Outcome == "key_deleted") {
			binding, ok := expectedBindings[row.Path]
			if !ok {
				t.Fatalf("signed request attribution has unexpected path %q", row.Path)
			}
			other := "project-beta"
			if binding == "project-beta" {
				other = "project-alpha"
			}
			assertBasicPairsBinding(t, row.Binding, binding, other)
			seen[row.Event+row.Path] = true
		}
	}
	for _, event := range []string{
		auditchain.EventHTTPRequest + "/v1/audit-alpha",
		auditchain.EventHTTPResponse + "/v1/audit-alpha",
		auditchain.EventHTTPRequest + "/v1/audit-beta",
		auditchain.EventHTTPResponse + "/v1/audit-beta",
		auditchain.EventDenied + "/v1/audit-alpha-refused",
	} {
		if !seen[event] {
			t.Fatalf("missing signed attribution %s", event)
		}
	}
	for _, secret := range []string{adapterKeyV1, adapterKeyV2, basicPairsAlphaUser + ":" + adapterKeyV1, basicPairsBetaUser + ":" + adapterKeyV2} {
		for _, representation := range []string{secret, base64.StdEncoding.EncodeToString([]byte(secret))} {
			if strings.Contains(auditOut.String(), representation) || strings.Contains(logs.String(), representation) {
				t.Fatal("selected credential reached audit or operational logs")
			}
		}
	}
}
