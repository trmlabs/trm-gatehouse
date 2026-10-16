package hashicorp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// dbStubState records what the stub database-engine Vault was asked to do so
// tests can assert on lease lifecycle calls.
type dbStubState struct {
	mu          sync.Mutex
	mintCount   int
	renewLeases []string
	revoked     []string
}

func (s *dbStubState) snapshot() (mint int, renews, revokes []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mintCount, append([]string(nil), s.renewLeases...), append([]string(nil), s.revoked...)
}

// stubDatabaseVault stands up a minimal Vault HTTP API covering the database
// secrets engine reads and the sys/leases renew+revoke writes the real vault/api
// client issues, so these tests exercise Client.ReadDatabaseCredential /
// RenewLease / RevokeLease end-to-end without a live Vault. validRoles is the
// set of roles that mint a credential; noPasswordRole mints a malformed
// credential (username only) to exercise the validation path.
func stubDatabaseVault(t *testing.T, mount string, validRoles []string, noPasswordRole string) (*httptest.Server, *dbStubState) {
	t.Helper()
	state := &dbStubState{}
	roleOK := map[string]bool{}
	for _, r := range validRoles {
		roleOK[r] = true
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		logical := strings.TrimPrefix(r.URL.Path, "/v1/")
		switch {
		case strings.HasPrefix(logical, mount+"/creds/"):
			role := strings.TrimPrefix(logical, mount+"/creds/")
			if role == noPasswordRole {
				state.mu.Lock()
				state.mintCount++
				n := state.mintCount
				state.mu.Unlock()
				writeJSON(w, map[string]interface{}{
					"lease_id":       fmt.Sprintf("%s/creds/%s/%d", mount, role, n),
					"lease_duration": 3600,
					"renewable":      true,
					"data":           map[string]interface{}{"username": fmt.Sprintf("v-%s-%d", role, n)},
				})
				return
			}
			if !roleOK[role] {
				w.WriteHeader(http.StatusNotFound)
				_, _ = io.WriteString(w, `{"errors":[]}`)
				return
			}
			state.mu.Lock()
			state.mintCount++
			n := state.mintCount
			state.mu.Unlock()
			writeJSON(w, map[string]interface{}{
				"lease_id":       fmt.Sprintf("%s/creds/%s/lease-%d", mount, role, n),
				"lease_duration": 3600,
				"renewable":      true,
				"data": map[string]interface{}{
					"username": fmt.Sprintf("v-%s-%d", role, n),
					"password": fmt.Sprintf("pw-%d", n),
				},
			})
		case logical == "sys/leases/renew":
			body := decodeBody(t, r)
			leaseID, _ := body["lease_id"].(string)
			state.mu.Lock()
			state.renewLeases = append(state.renewLeases, leaseID)
			state.mu.Unlock()
			writeJSON(w, map[string]interface{}{
				"lease_id":       leaseID,
				"lease_duration": 7200,
				"renewable":      true,
			})
		case strings.HasPrefix(logical, "sys/leases/revoke/"):
			leaseID := strings.TrimPrefix(logical, "sys/leases/revoke/")
			state.mu.Lock()
			state.revoked = append(state.revoked, leaseID)
			state.mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"errors":[]}`)
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, state
}

func decodeBody(t *testing.T, r *http.Request) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&m); err != nil && err != io.EOF {
		t.Fatalf("decode request body: %v", err)
	}
	return m
}

func TestReadDatabaseCredential_MintsDistinctPerCall(t *testing.T) {
	srv, state := stubDatabaseVault(t, "database", []string{"readonly"}, "")
	c := newClientForServer(t, srv.URL)

	issuedAt := time.Now()
	first, err := c.ReadDatabaseCredential(context.Background(), "database", "readonly")
	if err != nil {
		t.Fatalf("first read: %v", err)
	}
	second, err := c.ReadDatabaseCredential(context.Background(), "database", "readonly")
	if err != nil {
		t.Fatalf("second read: %v", err)
	}

	if first.Username == second.Username || first.Password == second.Password {
		t.Fatalf("expected distinct credentials per call, got %q/%q twice", first.Username, first.Password)
	}
	if first.LeaseID == "" || first.LeaseID == second.LeaseID {
		t.Fatalf("expected distinct non-empty lease ids, got %q and %q", first.LeaseID, second.LeaseID)
	}
	if first.LeaseDuration != time.Hour {
		t.Errorf("lease duration = %s, want 1h", first.LeaseDuration)
	}
	if !first.Renewable {
		t.Errorf("expected renewable credential")
	}
	if got := first.ExpiresAt(issuedAt); !got.After(issuedAt) {
		t.Errorf("ExpiresAt(%s) = %s, want later", issuedAt, got)
	}
	if mint, _, _ := state.snapshot(); mint != 2 {
		t.Errorf("mint count = %d, want 2", mint)
	}
}

func TestReadDatabaseCredential_UnknownRole(t *testing.T) {
	srv, _ := stubDatabaseVault(t, "database", []string{"readonly"}, "")
	c := newClientForServer(t, srv.URL)
	if _, err := c.ReadDatabaseCredential(context.Background(), "database", "nope"); err == nil {
		t.Fatal("expected an error for an unconfigured role, got nil")
	}
}

func TestReadDatabaseCredential_MissingPassword(t *testing.T) {
	srv, _ := stubDatabaseVault(t, "database", nil, "brokenrole")
	c := newClientForServer(t, srv.URL)
	if _, err := c.ReadDatabaseCredential(context.Background(), "database", "brokenrole"); err == nil {
		t.Fatal("expected an error when the credential is missing a password, got nil")
	}
}

func TestReadDatabaseCredential_Validation(t *testing.T) {
	srv, _ := stubDatabaseVault(t, "database", []string{"readonly"}, "")
	c := newClientForServer(t, srv.URL)
	for _, tc := range []struct{ mount, role string }{{"", "readonly"}, {"database", ""}, {"  ", "  "}} {
		if _, err := c.ReadDatabaseCredential(context.Background(), tc.mount, tc.role); err == nil {
			t.Errorf("ReadDatabaseCredential(%q,%q): expected validation error", tc.mount, tc.role)
		}
	}
}

func TestRenewLease(t *testing.T) {
	srv, state := stubDatabaseVault(t, "database", []string{"readonly"}, "")
	c := newClientForServer(t, srv.URL)

	got, err := c.RenewLease(context.Background(), "database/creds/readonly/lease-1", 30*time.Minute)
	if err != nil {
		t.Fatalf("RenewLease: %v", err)
	}
	if got != 2*time.Hour {
		t.Errorf("renewed duration = %s, want 2h", got)
	}
	if _, renews, _ := state.snapshot(); len(renews) != 1 || renews[0] != "database/creds/readonly/lease-1" {
		t.Errorf("renew calls = %v, want one for lease-1", renews)
	}
	if _, err := c.RenewLease(context.Background(), "", time.Minute); err == nil {
		t.Error("expected error renewing an empty lease id")
	}
}

func TestRevokeLease(t *testing.T) {
	srv, state := stubDatabaseVault(t, "database", []string{"readonly"}, "")
	c := newClientForServer(t, srv.URL)

	if err := c.RevokeLease(context.Background(), "database/creds/readonly/lease-7"); err != nil {
		t.Fatalf("RevokeLease: %v", err)
	}
	// Empty lease id is a no-op and must not hit Vault.
	if err := c.RevokeLease(context.Background(), ""); err != nil {
		t.Fatalf("RevokeLease(empty): %v", err)
	}
	if _, _, revokes := state.snapshot(); len(revokes) != 1 || revokes[0] != "database/creds/readonly/lease-7" {
		t.Errorf("revoke calls = %v, want one for lease-7", revokes)
	}
	// A lease ID that could leave the credential path never reaches Vault.
	for _, bad := range []string{"database/creds/../../sys/x", "database//creds", "database/creds/readonly/lease?x=1"} {
		if err := c.RevokeLease(context.Background(), bad); err == nil {
			t.Errorf("RevokeLease(%q) accepted", bad)
		}
	}
	if _, _, revokes := state.snapshot(); len(revokes) != 1 {
		t.Errorf("an invalid lease ID reached Vault: %v", revokes)
	}
}

func TestDatabaseReferenceRejectsTraversal(t *testing.T) {
	for _, role := range []string{"../config/root", "readonly?x=1", "readonly#x", "%2e%2e", "x/y"} {
		if err := ValidateDatabaseReference("database", role); err == nil {
			t.Fatalf("accepted role %q", role)
		}
	}
	for _, mount := range []string{"database/../sys", "database//nested", "database?x=1"} {
		if err := ValidateDatabaseReference(mount, "readonly"); err == nil {
			t.Fatalf("accepted mount %q", mount)
		}
	}
	if err := ValidateDatabaseReference("team/database", "app-ro"); err != nil {
		t.Fatal(err)
	}
}

func TestMalformedDatabaseCredentialIsRevoked(t *testing.T) {
	srv, state := stubDatabaseVault(t, "database", nil, "broken")
	c := newClientForServer(t, srv.URL)
	if _, err := c.ReadDatabaseCredential(context.Background(), "database", "broken"); err == nil {
		t.Fatal("accepted malformed credential")
	}
	_, _, revokes := state.snapshot()
	if len(revokes) != 1 {
		t.Fatalf("malformed lease was not revoked: %d", len(revokes))
	}
}

func TestDatabaseMintDoesNotRetryAmbiguousFailure(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("X-Vault-Token") != "test-token" || r.Header.Get("X-Vault-Namespace") != "team" {
			t.Error("mint lost authentication or namespace")
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, `{"errors":["response lost after issuance"]}`)
	}))
	defer srv.Close()
	c := newClientForServer(t, srv.URL)
	c.api.SetToken("test-token")
	c.api.SetNamespace("team")
	c.api.SetMaxRetries(2)
	_, err := c.ReadDatabaseCredential(context.Background(), "database", "readonly")
	if err == nil || calls.Load() != 1 {
		t.Fatalf("mint retried ambiguous issuance: calls=%d error=%v", calls.Load(), err)
	}
	if c.api.MaxRetries() != 2 {
		t.Fatal("mint altered shared retry policy")
	}
}

func TestDatabaseMintNilDataStillRevokesKnownLease(t *testing.T) {
	var revoked atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/sys/leases/revoke/database/creds/readonly/id" {
			revoked.Store(true)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if strings.Contains(r.URL.Path, "creds/") {
			_, _ = io.WriteString(w, `{"lease_id":"database/creds/readonly/id","lease_duration":60}`)
			return
		}
		t.Errorf("unexpected path %s", r.URL.Path)
	}))
	defer srv.Close()
	_, err := newClientForServer(t, srv.URL).ReadDatabaseCredential(context.Background(), "database", "readonly")
	if err == nil || !revoked.Load() {
		t.Fatal("malformed issuance leaked its known lease")
	}
}

// A failed credential read names Vault's status and messages, so the broker's
// log says why, and marks the answers that prove nothing was issued.
func TestDatabaseMintReportsVaultAnswer(t *testing.T) {
	for _, test := range []struct {
		status    int
		errors    []string
		want      string
		notIssued bool
	}{
		{403, []string{"1 error occurred:\n\t* permission denied\n\n"}, "Vault answered 403: 1 error occurred: * permission denied", true},
		{400, []string{"unknown role: reader"}, "Vault answered 400: unknown role: reader", true},
		{500, []string{`failed to execute query: ERROR: role "citus_dynamic_role" does not exist (SQLSTATE 42704)`},
			`Vault answered 500: failed to execute query: ERROR: role "citus_dynamic_role" does not exist (SQLSTATE 42704)`, false},
		{503, nil, "Vault answered 503: no message", false},
		{500, []string{"a", "b", "c", "d", "e", "f"}, "Vault answered 500: a; b; c; d; and 2 more", false},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(test.status)
			writeJSON(w, map[string]any{"errors": test.errors})
		}))
		_, err := newClientForServer(t, srv.URL).ReadDatabaseCredential(context.Background(), "database", "reader")
		srv.Close()
		if err == nil || err.Error() != "database credential read failed: "+test.want {
			t.Errorf("status %d: got %v, want %q", test.status, err, test.want)
		}
		if errors.Is(err, ErrCredentialNotIssued) != test.notIssued {
			t.Errorf("status %d: not-issued %v, want %v", test.status, errors.Is(err, ErrCredentialNotIssued), test.notIssued)
		}
	}
}

func TestDatabaseMintReportsMissingRoleAndNoAnswer(t *testing.T) {
	srv, _ := stubDatabaseVault(t, "database", nil, "")
	_, err := newClientForServer(t, srv.URL).ReadDatabaseCredential(context.Background(), "database", "nope")
	if err == nil || !errors.Is(err, ErrCredentialNotIssued) || !strings.Contains(err.Error(), "Vault answered 404: no credential at database/creds/nope") {
		t.Fatalf("missing role: %v", err)
	}
	gone := httptest.NewServer(http.NotFoundHandler())
	gone.Close()
	_, err = newClientForServer(t, gone.URL).ReadDatabaseCredential(context.Background(), "database", "reader")
	if err == nil || errors.Is(err, ErrCredentialNotIssued) || err.Error() != "database credential read failed: no answer from Vault (network)" {
		t.Fatalf("unreachable Vault: %v", err)
	}
}

func TestDatabaseMintMessageIsBounded(t *testing.T) {
	long := strings.Repeat("x", 1000) + "\n\n\tend"
	got := vaultMessages([]string{long, "  ", "postgres://u:p@h password: hunter2, at or near \"tok\""})
	if !strings.HasPrefix(got, strings.Repeat("x", 300)+"...; ") || strings.Contains(got, "hunter2") || strings.Contains(got, "u:p@") || strings.Contains(got, `"tok"`) {
		t.Fatalf("unbounded or unmasked: %q", got)
	}
}

// Each shape a database or a proxy can echo a password or a token in is
// masked, and the words around it are kept.
func TestDatabaseMintMasksSecretShapes(t *testing.T) {
	// Token-shaped values are built at run time, so no literal here matches a
	// secret scanner's pattern.
	fill := strings.Repeat("x", 18)
	for _, test := range []struct{ name, message, want string }{
		{"JSON password field", `plugin config: {"username":"admin","password":"CANARY"}`, `plugin config: {"username":"admin","password":"***"}`},
		{"JSON password field with an escaped quote", `{"password":"ab\"CANARY"}`, `{"password":"***"}`},
		{"JSON password field escaped inside a string", `{\"password\":\"ab\\\"CANARY\"}`, `{\"password\":\"***\"}`},
		{"JSON password-named field", `{"password_hash": "CANARY"}`, `{"password_hash": "***"}`},
		{"PASSWORD with a double-quoted value", `CREATE ROLE "v-x" WITH LOGIN PASSWORD "CANARY" VALID UNTIL "soon"`, `CREATE ROLE "v-x" WITH LOGIN PASSWORD "***" VALID UNTIL "soon"`},
		{"PASSWORD with a doubled single quote", `ALTER ROLE "v-x" PASSWORD 'ab''CANARY'`, `ALTER ROLE "v-x" PASSWORD '***'`},
		{"PASSWORD with dollar quoting", `ALTER ROLE "v-x" PASSWORD $$CANARY$$;`, `ALTER ROLE "v-x" PASSWORD $$***$$;`},
		{"PASSWORD with tagged dollar quoting", `ALTER ROLE "v-x" PASSWORD $pw$CANARY$pw$;`, `ALTER ROLE "v-x" PASSWORD $pw$***$pw$;`},
		{"PASSWORD with an unterminated dollar quote", `ALTER ROLE "v-x" PASSWORD $$CANARY`, `ALTER ROLE "v-x" PASSWORD $$***`},
		{"IDENTIFIED BY with a double-quoted value", `CREATE USER 'v-x'@'%' IDENTIFIED BY "CANARY"`, `CREATE USER '***'@'***' IDENTIFIED BY "***"`},
		{"PWD in a connection string", `Server=db;Database=app;PWD=CANARY;`, `Server=db;Database=app;PWD=***;`},
		{"Vault service token", "permission denied for token hvs.CANARY_" + fill, `permission denied for token hvs.***`},
		{"Vault batch token", "token hvb.CANARY" + fill + " expired", `token hvb.*** expired`},
		{"legacy Vault token", "invalid token s.CANARY" + fill, `invalid token s.***`},
		{"Bearer token", "upstream echoed Authorization: Bearer CANARY." + fill, `upstream echoed Authorization: Bearer ***`},
		{"password words without a value", `pq: password authentication failed for user "v-root-x"`, `pq: password authentication failed for user "v-root-x"`},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := vaultMessages([]string{test.message}); got != test.want || strings.Contains(got, "CANARY") {
				t.Fatalf("got %q, want %q", got, test.want)
			}
		})
	}
}

// A reply that is not Vault's error JSON, such as a proxy's page that echoes
// the request's headers, is reported by status and size only.
func TestDatabaseMintReportsOnlyTheSizeOfAReplyThatIsNotVaults(t *testing.T) {
	body := "<html>502 Bad Gateway. Request headers: X-Vault-Token: hvs.CANARY" + strings.Repeat("x", 18) + "</html>"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = io.WriteString(w, body)
	}))
	defer srv.Close()
	_, err := newClientForServer(t, srv.URL).ReadDatabaseCredential(context.Background(), "database", "reader")
	want := fmt.Sprintf("database credential read failed: Vault answered 502: a reply that is not Vault's error JSON (%d bytes)", len(body))
	if err == nil || err.Error() != want || errors.Is(err, ErrCredentialNotIssued) {
		t.Fatalf("got %v, want %q", err, want)
	}
}
