package server

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Infisical/agent-vault/internal/auth"
	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/store"
)

// legacyArgon2User swaps a mock user's hash for an Argon2id one, as stored before PBKDF2.
func legacyArgon2User(t *testing.T, ms *mockStore, email, password string) {
	t.Helper()
	p := crypto.KDFParams{Algorithm: crypto.AlgoArgon2id, Time: 1, Memory: 1024, Threads: 1, KeyLen: 32, SaltLen: 16}
	salt, err := crypto.GenerateSalt(16)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := crypto.DeriveKey([]byte(password), salt, p)
	if err != nil {
		t.Fatal(err)
	}
	u := ms.users[email]
	u.PasswordHash, u.PasswordSalt = hash, salt
	u.KDFTime, u.KDFMemory, u.KDFThreads, u.KDFAlgorithm = p.Time, p.Memory, p.Threads, p.Algorithm
}

func login(t *testing.T, srv *Server, email, password string) int {
	t.Helper()
	body := `{"email":"` + email + `","password":"` + password + `"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", strings.NewReader(body))
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)
	return rec.Code
}

func TestLoginUpgradesLegacyArgon2idHashWhenOn(t *testing.T) {
	t.Setenv(crypto.KDFUpgradeEnv, "true")
	const email, pw = "admin@test.com", "test-password-123"
	ms := setupMockStoreWithUser(t, email, pw)
	legacyArgon2User(t, ms, email, pw)
	srv := newTestServer(withStore(ms))

	if code := login(t, srv, email, pw); code != http.StatusOK {
		t.Fatalf("legacy login: expected 200, got %d", code)
	}
	u := ms.users[email]
	if u.KDFAlgorithm != crypto.AlgoPBKDF2SHA256 || u.KDFMemory != 0 || u.KDFThreads != 0 {
		t.Fatalf("hash not upgraded to PBKDF2: algo=%q mem=%d threads=%d", u.KDFAlgorithm, u.KDFMemory, u.KDFThreads)
	}
	if !auth.VerifyUserPassword([]byte(pw), u.PasswordHash, u.PasswordSalt, userKDFParams(u)) {
		t.Fatal("upgraded hash does not verify the original password")
	}
	if code := login(t, srv, email, pw); code != http.StatusOK {
		t.Fatalf("login after upgrade: expected 200, got %d", code)
	}
	if code := login(t, srv, email, "wrong-password-123"); code != http.StatusUnauthorized {
		t.Fatalf("wrong password after upgrade: expected 401, got %d", code)
	}
}

func TestLoginNeverUpgradesWhenOff(t *testing.T) {
	t.Setenv(crypto.KDFUpgradeEnv, "")
	const email, pw = "admin@test.com", "test-password-123"
	ms := setupMockStoreWithUser(t, email, pw)
	legacyArgon2User(t, ms, email, pw)
	before := append([]byte(nil), ms.users[email].PasswordHash...)
	srv := newTestServer(withStore(ms))

	if code := login(t, srv, email, pw); code != http.StatusOK {
		t.Fatalf("expected 200, got %d", code)
	}
	if u := ms.users[email]; u.KDFAlgorithm != crypto.AlgoArgon2id || string(u.PasswordHash) != string(before) {
		t.Fatal("off mode must leave the Argon2id record readable by an older image")
	}
}

func TestOffModeWritesArgon2idForNewHashes(t *testing.T) {
	t.Setenv(crypto.KDFUpgradeEnv, "")
	ms := setupMockStoreWithUser(t, "admin@test.com", "test-password-123")
	if u := ms.users["admin@test.com"]; u.KDFAlgorithm != crypto.AlgoArgon2id || u.KDFMemory != 64*1024 {
		t.Fatalf("a new hash in off mode must be Argon2id with the old params, got %q mem=%d", u.KDFAlgorithm, u.KDFMemory)
	}
}

func TestLoginWrongPasswordDoesNotUpgradeLegacyHash(t *testing.T) {
	t.Setenv(crypto.KDFUpgradeEnv, "true")
	const email, pw = "admin@test.com", "test-password-123"
	ms := setupMockStoreWithUser(t, email, pw)
	legacyArgon2User(t, ms, email, pw)
	before := append([]byte(nil), ms.users[email].PasswordHash...)
	srv := newTestServer(withStore(ms))

	if code := login(t, srv, email, "wrong-password-123"); code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", code)
	}
	if u := ms.users[email]; u.KDFAlgorithm != crypto.AlgoArgon2id || string(u.PasswordHash) != string(before) {
		t.Fatal("a failed login must leave the legacy hash untouched")
	}
}

func TestLoginKeepsPBKDF2HashUnchanged(t *testing.T) {
	t.Setenv(crypto.KDFUpgradeEnv, "true")
	const email, pw = "admin@test.com", "test-password-123"
	ms := setupMockStoreWithUser(t, email, pw)
	before := append([]byte(nil), ms.users[email].PasswordHash...)
	srv := newTestServer(withStore(ms))

	if code := login(t, srv, email, pw); code != http.StatusOK {
		t.Fatalf("expected 200, got %d", code)
	}
	if u := ms.users[email]; u.KDFAlgorithm != crypto.AlgoPBKDF2SHA256 || string(u.PasswordHash) != string(before) {
		t.Fatal("a PBKDF2 hash must not be rewritten on login")
	}
}

func TestLoginLosingTheUpgradeRaceWritesNothing(t *testing.T) {
	t.Setenv(crypto.KDFUpgradeEnv, "true")
	const email, pw = "admin@test.com", "test-password-123"
	ms := setupMockStoreWithUser(t, email, pw)
	legacyArgon2User(t, ms, email, pw)
	// A password reset lands between the login's verify and its upgrade.
	reset := []byte("hash-written-by-the-reset")
	ms.beforeHashUpgrade = func() { ms.users[email].PasswordHash = reset }
	srv := newTestServer(withStore(ms))

	if code := login(t, srv, email, pw); code != http.StatusOK {
		t.Fatalf("losing the race must not fail the login, got %d", code)
	}
	if u := ms.users[email]; string(u.PasswordHash) != string(reset) || u.KDFAlgorithm != crypto.AlgoArgon2id {
		t.Fatal("the stale upgrade overwrote the newer password")
	}
}

func TestLoginSurvivesAFailedUpgrade(t *testing.T) {
	t.Setenv(crypto.KDFUpgradeEnv, "true")
	const email, pw = "admin@test.com", "test-password-123"
	ms := setupMockStoreWithUser(t, email, pw)
	legacyArgon2User(t, ms, email, pw)
	before := append([]byte(nil), ms.users[email].PasswordHash...)
	ms.hashUpgradeErr = errors.New("database unavailable")
	srv := newTestServer(withStore(ms))

	if code := login(t, srv, email, pw); code != http.StatusOK {
		t.Fatalf("a failed upgrade must not fail the login, got %d", code)
	}
	if u := ms.users[email]; u.KDFAlgorithm != crypto.AlgoArgon2id || string(u.PasswordHash) != string(before) {
		t.Fatal("a failed upgrade must leave the record as it was")
	}
}

// loginKDFTrace is what the login KDF ran since the last read.
type loginKDFTrace struct {
	calls      map[string]int
	iterations uint64
	argonPWs   [][]byte
}

// countLoginKDF wraps the login KDF and records which algorithms ran, the PBKDF2 iterations and each Argon2id input.
func countLoginKDF(t *testing.T) func() loginKDFTrace {
	t.Helper()
	var mu sync.Mutex
	tr := loginKDFTrace{calls: map[string]int{}}
	orig := loginDerive
	loginDerive = func(pw, salt []byte, p crypto.KDFParams) ([]byte, error) {
		mu.Lock()
		algo := p.EffectiveAlgorithm()
		tr.calls[algo]++
		if algo == crypto.AlgoPBKDF2SHA256 {
			tr.iterations += uint64(p.Time)
		} else {
			tr.argonPWs = append(tr.argonPWs, append([]byte(nil), pw...))
		}
		mu.Unlock()
		return crypto.DeriveKey(pw, salt, p)
	}
	t.Cleanup(func() { loginDerive = orig })
	return func() loginKDFTrace {
		mu.Lock()
		defer mu.Unlock()
		out := tr
		tr = loginKDFTrace{calls: map[string]int{}}
		return out
	}
}

// pbkdf2User swaps a mock user's hash for a PBKDF2 one at the given iteration count.
func pbkdf2User(t *testing.T, ms *mockStore, email, password string, iterations uint32) {
	t.Helper()
	p := crypto.KDFParams{Algorithm: crypto.AlgoPBKDF2SHA256, Time: iterations, KeyLen: 32, SaltLen: 16}
	salt, err := crypto.GenerateSalt(16)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := crypto.DeriveKey([]byte(password), salt, p)
	if err != nil {
		t.Fatal(err)
	}
	u := ms.users[email]
	u.PasswordHash, u.PasswordSalt = hash, salt
	u.KDFTime, u.KDFMemory, u.KDFThreads, u.KDFAlgorithm = p.Time, 0, 0, p.Algorithm
}

func TestEveryFailedLoginRunsBothKDFs(t *testing.T) {
	const email, pw = "admin@test.com", "test-password-123"
	for _, mode := range []string{"", "true"} {
		t.Run("upgrade="+mode, func(t *testing.T) {
			t.Setenv(crypto.KDFUpgradeEnv, mode)
			for name, setup := range map[string]func(*mockStore){
				"argon2 record": func(ms *mockStore) { legacyArgon2User(t, ms, email, pw) },
				"pbkdf2 record": func(ms *mockStore) {},
				"inactive user": func(ms *mockStore) { ms.users[email].IsActive = false },
				"mislabelled": func(ms *mockStore) {
					legacyArgon2User(t, ms, email, pw)
					ms.users[email].KDFAlgorithm = crypto.AlgoPBKDF2SHA256
				},
			} {
				ms := setupMockStoreWithUser(t, email, pw)
				setup(ms)
				srv := newTestServer(withStore(ms))
				took := countLoginKDF(t)
				for who, tryPW := range map[string]string{"wrong password": "not-the-password", "unknown email": pw} {
					tryEmail := email
					if who == "unknown email" {
						tryEmail = "nobody@test.com"
					}
					if code := login(t, srv, tryEmail, tryPW); code != http.StatusUnauthorized {
						t.Fatalf("%s/%s: got %d", name, who, code)
					}
					if c := took().calls; c[crypto.AlgoArgon2id] != 1 || c[crypto.AlgoPBKDF2SHA256] != 1 {
						t.Fatalf("%s/%s: KDF calls %v, want one of each", name, who, c)
					}
				}
				if name == "inactive user" {
					if code := login(t, srv, email, pw); code != http.StatusUnauthorized {
						t.Fatalf("inactive user got %d", code)
					}
					if c := took().calls; c[crypto.AlgoArgon2id] != 1 || c[crypto.AlgoPBKDF2SHA256] != 1 {
						t.Fatalf("inactive user with the right password: KDF calls %v, want one of each", c)
					}
				}
			}
		})
	}
}

func TestLoginReadsAPBKDF2LabelledArgon2Record(t *testing.T) {
	const email, pw = "admin@test.com", "test-password-123"
	ms := setupMockStoreWithUser(t, email, pw)
	legacyArgon2User(t, ms, email, pw)
	ms.users[email].KDFAlgorithm = crypto.AlgoPBKDF2SHA256
	if code := login(t, newTestServer(withStore(ms)), email, pw); code != http.StatusOK {
		t.Fatalf("an old image's password change must still log in, got %d", code)
	}
}

func TestLoginUpgradesAMislabelledHash(t *testing.T) {
	t.Setenv(crypto.KDFUpgradeEnv, "true")
	const email, pw = "admin@test.com", "test-password-123"
	ms := setupMockStoreWithUser(t, email, pw)
	legacyArgon2User(t, ms, email, pw)
	ms.users[email].KDFAlgorithm = crypto.AlgoPBKDF2SHA256
	srv := newTestServer(withStore(ms))

	if code := login(t, srv, email, pw); code != http.StatusOK {
		t.Fatalf("expected 200, got %d", code)
	}
	u := ms.users[email]
	if u.KDFAlgorithm != crypto.AlgoPBKDF2SHA256 || u.KDFMemory != 0 || u.KDFThreads != 0 || u.KDFTime != crypto.DefaultPBKDF2Iterations {
		t.Fatalf("mislabelled hash not rewritten as PBKDF2: %+v", u)
	}
	if code := login(t, srv, email, pw); code != http.StatusOK {
		t.Fatalf("login after upgrade: %d", code)
	}
}

func TestFailedLoginTopsUpAPBKDF2RecordBelowTheConfiguredCount(t *testing.T) {
	const email, pw, stored, configured = "admin@test.com", "test-password-123", 600_000, 700_000
	t.Setenv(crypto.KDFUpgradeEnv, "true")
	t.Setenv(crypto.IterationsEnv, "700000")
	ms := setupMockStoreWithUser(t, email, pw)
	pbkdf2User(t, ms, email, pw, stored)
	srv := newTestServer(withStore(ms))
	took := countLoginKDF(t)

	if code := login(t, srv, "nobody@test.com", pw); code != http.StatusUnauthorized {
		t.Fatalf("unknown email: %d", code)
	}
	unknown := took()
	if code := login(t, srv, email, "not-the-password"); code != http.StatusUnauthorized {
		t.Fatalf("wrong password: %d", code)
	}
	if real := took(); real.iterations != unknown.iterations || real.iterations != configured {
		t.Fatalf("PBKDF2 iterations: unknown email %d, real user %d, want both %d", unknown.iterations, real.iterations, configured)
	}
}

func TestFailedLoginNeverFeedsTheTypedPasswordToArgon2idUnlessVerifyingAnArgon2idRecord(t *testing.T) {
	const email, pw, typed = "admin@test.com", "test-password-123", "not-the-password"
	t.Setenv(crypto.KDFUpgradeEnv, "true")
	ms := setupMockStoreWithUser(t, email, pw)
	srv := newTestServer(withStore(ms))
	took := countLoginKDF(t)

	for _, tryEmail := range []string{"nobody@test.com", email} {
		if code := login(t, srv, tryEmail, typed); code != http.StatusUnauthorized {
			t.Fatalf("%s: %d", tryEmail, code)
		}
		for _, in := range took().argonPWs {
			if string(in) == typed {
				t.Fatalf("%s: the typed password reached Argon2id", tryEmail)
			}
		}
	}
}

func TestFailedLoginOnACorruptRecordCostsAsMuchAsAnyOther(t *testing.T) {
	const email, pw = "admin@test.com", "test-password-123"
	t.Setenv(crypto.KDFUpgradeEnv, "true")
	for name, corrupt := range map[string]func(*store.User){
		"argon2 with no memory": func(u *store.User) {
			u.KDFAlgorithm, u.KDFTime, u.KDFMemory, u.KDFThreads = crypto.AlgoArgon2id, 1, 0, 1
		},
		"pbkdf2 zero count": func(u *store.User) {
			u.KDFAlgorithm, u.KDFTime, u.KDFMemory, u.KDFThreads = crypto.AlgoPBKDF2SHA256, 0, 0, 0
		},
		"unknown algorithm": func(u *store.User) { u.KDFAlgorithm = "md5" },
	} {
		ms := setupMockStoreWithUser(t, email, pw)
		corrupt(ms.users[email])
		srv := newTestServer(withStore(ms))
		took := countLoginKDF(t)
		if code := login(t, srv, email, pw); code != http.StatusUnauthorized {
			t.Fatalf("%s: %d", name, code)
		}
		if tr := took(); tr.calls[crypto.AlgoArgon2id] < 1 || tr.iterations < crypto.DefaultPBKDF2Iterations {
			t.Fatalf("%s: a corrupt record skipped the dummy work: %v, %d iterations", name, tr.calls, tr.iterations)
		}
	}
}

func TestLoginRehashesPBKDF2AtADifferentCountOnlyWhenOn(t *testing.T) {
	const email, pw = "admin@test.com", "test-password-123"
	for _, tc := range []struct {
		name, upgrade string
		stored        uint32
		wantTime      uint32
	}{
		{"below, on", "true", 600_000, 700_000},
		{"above, on", "true", 800_000, 700_000},
		{"same, on", "true", 700_000, 700_000},
		{"below, off", "", 600_000, 600_000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(crypto.KDFUpgradeEnv, tc.upgrade)
			t.Setenv(crypto.IterationsEnv, "700000")
			ms := setupMockStoreWithUser(t, email, pw)
			pbkdf2User(t, ms, email, pw, tc.stored)
			srv := newTestServer(withStore(ms))
			if code := login(t, srv, email, pw); code != http.StatusOK {
				t.Fatalf("login: %d", code)
			}
			u := ms.users[email]
			if u.KDFTime != tc.wantTime || !auth.VerifyUserPassword([]byte(pw), u.PasswordHash, u.PasswordSalt, userKDFParams(u)) {
				t.Fatalf("stored count %d, want %d, and the hash must still verify", u.KDFTime, tc.wantTime)
			}
		})
	}
}
