package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"time"

	"github.com/Infisical/agent-vault/internal/auth"
	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/keywrap"
	"github.com/Infisical/agent-vault/internal/store"
	"github.com/spf13/cobra"
)

// kmsTimeout bounds each KMS step so an unreachable key service fails startup instead of hanging it.
const kmsTimeout = 30 * time.Second

// envKMSBreakGlass lets a start fall back to the master password when KMS fails; without it every KMS failure refuses to start.
const envKMSBreakGlass = "AGENT_VAULT_KMS_BREAK_GLASS"

// strictBoolEnv parses a true/false setting strictly: unset is false and anything unparseable is an error.
func strictBoolEnv(name string) (bool, error) {
	raw := os.Getenv(name)
	if raw == "" {
		return false, nil
	}
	b, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("%s must be true or false, got %q", name, raw)
	}
	return b, nil
}

// newKMSWrapper builds the wrapper for the configured key; tests replace it with a fake. The client outlives ctx, so callers pass a background one.
var newKMSWrapper = func(ctx context.Context, value string) (keywrap.Wrapper, error) {
	fips, err := strictBoolEnv(keywrap.EnvKMSFIPS)
	if err != nil {
		return nil, err
	}
	return keywrap.New(ctx, value, fips)
}

// kmsWrapperFromEnv returns nil when AGENT_VAULT_MASTER_KEY_KMS is unset.
func kmsWrapperFromEnv(ctx context.Context) (keywrap.Wrapper, error) {
	for _, name := range []string{keywrap.EnvKMSFIPS, envKMSBreakGlass} {
		if _, err := strictBoolEnv(name); err != nil {
			return nil, err
		}
	}
	value := os.Getenv(keywrap.EnvKMS)
	if value == "" {
		return nil, nil
	}
	return newKMSWrapper(ctx, value)
}

// unlockOrSetupKMS reads the optional break-glass password, then unlocks, creates or switches the vault over to KMS.
func unlockOrSetupKMS(cmd *cobra.Command, db store.Store, w keywrap.Wrapper, passwordStdin bool) (*auth.MasterKey, error) {
	var password []byte
	if envPw := os.Getenv("AGENT_VAULT_MASTER_PASSWORD"); envPw != "" {
		_ = os.Unsetenv("AGENT_VAULT_MASTER_PASSWORD")
		password = []byte(envPw)
	} else if passwordStdin {
		var err error
		if password, err = readPasswordFromStdin(); err != nil {
			return nil, err
		}
	}
	prompt := func() ([]byte, error) {
		fmt.Fprintln(cmd.OutOrStderr(), boldText("Switching this vault to KMS. Enter the current master password once."))
		return auth.PromptPassword("Master password: ")
	}
	return unlockWithKMS(context.Background(), db, w, password, prompt)
}

// unlockWithKMS prefers KMS; a password is used to switch a password-only vault over, or as break-glass only when AGENT_VAULT_KMS_BREAK_GLASS is true.
// Each KMS step gets its own timeout, started after any password prompt.
func unlockWithKMS(ctx context.Context, db store.Store, w keywrap.Wrapper, password []byte, prompt func() ([]byte, error)) (*auth.MasterKey, error) {
	defer crypto.WipeBytes(password)
	record, err := db.GetMasterKeyRecord(ctx)
	if err != nil {
		return nil, fmt.Errorf("checking master key: %w", err)
	}
	switch {
	case record == nil:
		kctx, cancel := context.WithTimeout(ctx, kmsTimeout)
		defer cancel()
		return setupKMSMasterKey(kctx, db, w)
	case record.KMSWrappedDEK != nil:
		kctx, cancel := context.WithTimeout(ctx, kmsTimeout)
		defer cancel()
		return unlockKMSRecord(kctx, db, w, record, password)
	case record.DEKPlaintext != nil:
		return nil, errors.New("this vault has no master password; run 'agent-vault master-password set' once, then restart with KMS to switch over")
	}
	return switchToKMS(ctx, db, w, record, password, prompt)
}

// setupKMSMasterKey creates a vault whose DEK is wrapped only by KMS.
func setupKMSMasterKey(ctx context.Context, db store.Store, w keywrap.Wrapper) (*auth.MasterKey, error) {
	mk, rec, wrapped, err := auth.SetupWithKMS(ctx, w)
	if err != nil {
		return nil, fmt.Errorf("setting up master key with KMS: %w", err)
	}
	storeRec := verificationToStoreRecord(rec)
	storeRec.KMSWrappedDEK, storeRec.KMSKeyName, storeRec.WrapKind = wrapped, w.KeyName(), store.WrapKindKMS
	if err := db.SetMasterKeyRecord(ctx, storeRec); err != nil {
		mk.Wipe()
		return nil, fmt.Errorf("persisting master key record: %w", err)
	}
	// Another instance may have won the insert; use whatever is stored.
	existing, err := db.GetMasterKeyRecord(ctx)
	if err != nil {
		mk.Wipe()
		return nil, fmt.Errorf("re-reading master key after setup: %w", err)
	}
	if bytes.Equal(existing.KMSWrappedDEK, wrapped) {
		slog.Info("master key created and wrapped with KMS", "key", w.KeyName())
		return mk, nil
	}
	mk.Wipe()
	if existing.KMSWrappedDEK == nil {
		return nil, errors.New("another instance created the master key without KMS; restart to switch it over")
	}
	return unlockKMSRecord(ctx, db, w, existing, nil)
}

// unlockKMSWrap unwraps the stored KMS wrap, refusing a record wrapped by a different key.
func unlockKMSWrap(ctx context.Context, w keywrap.Wrapper, record *store.MasterKeyRecord) (*auth.MasterKey, error) {
	if record.KMSKeyName != w.KeyName() {
		return nil, fmt.Errorf("the vault master key is wrapped by %s but %s is %s", record.KMSKeyName, keywrap.EnvKMS, w.KeyName())
	}
	return auth.UnlockWithKMS(ctx, w, record.KMSWrappedDEK, buildVerificationRecord(record))
}

// unlockKMSRecord unlocks with KMS and refuses on any KMS failure; only AGENT_VAULT_KMS_BREAK_GLASS=true with a password and a remaining password wrap falls back, loudly.
func unlockKMSRecord(ctx context.Context, db store.Store, w keywrap.Wrapper, record *store.MasterKeyRecord, password []byte) (*auth.MasterKey, error) {
	mk, kmsErr := unlockKMSWrap(ctx, w, record)
	if kmsErr == nil {
		if record.WrapKind != store.WrapKindKMS {
			if err := db.SetMasterKeyWrapKind(ctx, store.WrapKindKMS); err != nil {
				slog.Warn("could not record the KMS unlock", "error", err)
			}
		}
		clearStalePlaintext(ctx, db, mk, record)
		slog.Info("master key unlocked with KMS", "key", w.KeyName())
		return mk, nil
	}
	breakGlass, err := strictBoolEnv(envKMSBreakGlass)
	if err != nil {
		return nil, err
	}
	if !breakGlass {
		return nil, fmt.Errorf("%w; refusing to start, set %s=true with the master password to use the break-glass wrap", kmsErr, envKMSBreakGlass)
	}
	if record.DEKCiphertext == nil {
		return nil, fmt.Errorf("%w; the password wrap was removed, there is no break-glass", kmsErr)
	}
	if len(password) == 0 {
		return nil, fmt.Errorf("%w; %s is true but no master password was provided", kmsErr, envKMSBreakGlass)
	}
	mk, err = auth.Unlock(password, buildVerificationRecord(record))
	if err != nil {
		return nil, fmt.Errorf("%w; the break-glass master password also failed: %w", kmsErr, err)
	}
	slog.Error("KMS unlock failed; unlocked with the break-glass master password", "error", kmsErr, "setting", envKMSBreakGlass)
	if err := db.SetMasterKeyWrapKind(ctx, store.WrapKindKMSFallback); err != nil {
		slog.Error("could not record the break-glass unlock; do not run remove-password-wrap until KMS unlocks again", "error", err)
	}
	return mk, nil
}

// clearStalePlaintext removes a plaintext key an old image's 'master-password remove' left beside the KMS wrap, once KMS has unwrapped the key and it matches; a lost race or failure only logs.
func clearStalePlaintext(ctx context.Context, db store.Store, mk *auth.MasterKey, record *store.MasterKeyRecord) {
	if record.DEKPlaintext == nil {
		return
	}
	if !bytes.Equal(record.DEKPlaintext, mk.Key()) {
		slog.Warn("the master key record holds a plaintext key that differs from the KMS-wrapped one; leaving it, investigate")
		return
	}
	switch cleared, err := db.ClearMasterKeyPlaintext(ctx, record); {
	case err != nil:
		slog.Warn("could not clear the plaintext master key left by an old image's 'master-password remove'", "error", err)
	case cleared:
		slog.Warn("cleared the plaintext master key an old image's 'master-password remove' left beside the KMS wrap")
	}
}

// switchToKMS leaves the password wrap byte for byte as it was, so an older image can still start after a rollback; it wraps the DEK of a password-only vault with KMS, verifies it reads back, and only then saves it beside the password wrap.
func switchToKMS(ctx context.Context, db store.Store, w keywrap.Wrapper, record *store.MasterKeyRecord, password []byte, prompt func() ([]byte, error)) (*auth.MasterKey, error) {
	if len(password) == 0 && prompt != nil {
		var err error
		if password, err = prompt(); err != nil {
			return nil, fmt.Errorf("password input: %w", err)
		}
		defer crypto.WipeBytes(password)
	}
	var cancel context.CancelFunc
	ctx, cancel = context.WithTimeout(ctx, kmsTimeout)
	defer cancel()
	if len(password) == 0 {
		return nil, errors.New("this vault is protected by a master password; provide it once (AGENT_VAULT_MASTER_PASSWORD or --password-stdin) to switch to KMS")
	}
	mk, err := auth.Unlock(password, buildVerificationRecord(record))
	if err != nil {
		return nil, errors.New("wrong password")
	}

	wrapped, err := auth.WrapWithKMS(ctx, w, mk.Key(), record.Sentinel)
	if err != nil {
		mk.Wipe()
		return nil, fmt.Errorf("switching to KMS failed and nothing was changed: %w", err)
	}
	written, err := db.SetMasterKeyKMSWrap(ctx, record, wrapped, w.KeyName())
	if err != nil {
		mk.Wipe()
		return nil, err
	}
	if !written {
		mk.Wipe()
		current, err := db.GetMasterKeyRecord(ctx)
		if err != nil || current == nil || current.KMSWrappedDEK == nil {
			return nil, errors.New("the master key record changed while switching to KMS and nothing was saved; restart to try again")
		}
		return unlockKMSRecord(ctx, db, w, current, password)
	}
	slog.Info("master key switched to KMS; the password wrap is kept as break-glass until 'agent-vault master-key remove-password-wrap'", "key", w.KeyName())
	return mk, nil
}

// kmsGateWithoutKMS refuses to unlock a KMS-wrapped vault when AGENT_VAULT_MASTER_KEY_KMS is unset unless break-glass is on; it reports whether this start is a break-glass one.
func kmsGateWithoutKMS(record *store.MasterKeyRecord) (bool, error) {
	if record.KMSWrappedDEK == nil {
		return false, nil
	}
	breakGlass, err := strictBoolEnv(envKMSBreakGlass)
	if err != nil {
		return false, err
	}
	if !breakGlass {
		return false, fmt.Errorf("the vault has a KMS wrap (%s) but %s is not set; refusing to start, set it, or set %s=true with the master password to use the break-glass wrap", record.KMSKeyName, keywrap.EnvKMS, envKMSBreakGlass)
	}
	return true, nil
}

// recordKMSFallback logs a break-glass password unlock and records it like a KMS failure fallback, so remove-password-wrap refuses until KMS unlocks again.
func recordKMSFallback(db store.Store, record *store.MasterKeyRecord) {
	slog.Error(keywrap.EnvKMS+" is not set; unlocked with the break-glass master password", "key", record.KMSKeyName, "setting", envKMSBreakGlass)
	if err := db.SetMasterKeyWrapKind(context.Background(), store.WrapKindKMSFallback); err != nil {
		slog.Error("could not record the break-glass unlock; do not run remove-password-wrap until KMS unlocks again", "error", err)
	}
}

// errKMSManaged explains why a password command does not apply to a KMS-wrapped vault.
func errKMSManaged(record *store.MasterKeyRecord) error {
	return fmt.Errorf("the master key is wrapped by KMS key %s; see 'agent-vault master-key remove-password-wrap'", record.KMSKeyName)
}

// errKMSOnly is returned when KMS is not configured but the vault has no password wrap to fall back on.
func errKMSOnly(record *store.MasterKeyRecord) error {
	return fmt.Errorf("the master key is wrapped only by KMS key %s; set %s to unlock it", record.KMSKeyName, keywrap.EnvKMS)
}

var masterKeyCmd = &cobra.Command{
	Use:   "master-key",
	Short: "Manage how the master encryption key is wrapped",
}

var masterKeyRemovePasswordWrapCmd = &cobra.Command{
	Use:   "remove-password-wrap",
	Short: "Remove the break-glass master password once KMS unwraps the key",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		force, _ := cmd.Flags().GetBool("force")
		if err := ensureServerStopped(force); err != nil {
			return err
		}
		w, err := kmsWrapperFromEnv(context.Background())
		if err != nil {
			return err
		}
		if w == nil {
			return fmt.Errorf("set %s to the key this vault uses", keywrap.EnvKMS)
		}
		db, cleanup, err := openDB()
		if err != nil {
			return err
		}
		defer cleanup()
		ctx, cancel := context.WithTimeout(context.Background(), kmsTimeout)
		defer cancel()
		if err := removePasswordWrap(ctx, db, w); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "%s Master password removed. The broker now starts with KMS alone.\n", successText("✓"))
		return nil
	},
}

// removePasswordWrap drops the password wrap, but only after KMS has unwrapped the DEK and it matches the vault.
func removePasswordWrap(ctx context.Context, db store.Store, w keywrap.Wrapper) error {
	record, err := db.GetMasterKeyRecord(ctx)
	if err != nil {
		return fmt.Errorf("reading master key record: %w", err)
	}
	if record == nil {
		return errors.New("no master key record found; run 'agent-vault server' first")
	}
	if record.KMSWrappedDEK == nil {
		return fmt.Errorf("this vault is not wrapped by KMS yet; start the server once with %s set to switch it over", keywrap.EnvKMS)
	}
	if record.DEKCiphertext == nil && record.DEKPlaintext == nil {
		return errors.New("the vault has no master password to remove")
	}
	if record.WrapKind == store.WrapKindKMSFallback {
		return errors.New("the broker last unlocked through the break-glass password, so KMS may be broken; start it once with KMS working, then run this again")
	}
	mk, err := unlockKMSWrap(ctx, w, record)
	if err != nil {
		return fmt.Errorf("not removing the master password, KMS cannot unwrap the key: %w", err)
	}
	if record.DEKPlaintext != nil && !bytes.Equal(record.DEKPlaintext, mk.Key()) {
		mk.Wipe()
		return errors.New("not removing the master password, the plaintext key in the record differs from the KMS-wrapped one; investigate")
	}
	mk.Wipe()

	removed, err := db.RemoveMasterKeyPasswordWrap(ctx, record)
	if err != nil {
		return fmt.Errorf("persisting updated record: %w", err)
	}
	if !removed {
		return errors.New("the master key record changed while removing the master password and nothing was changed; run this again")
	}
	return nil
}

func init() {
	masterKeyRemovePasswordWrapCmd.Flags().Bool("force", false, "proceed even when DATABASE_URL is set (requires all instances to be stopped)")
	masterKeyCmd.AddCommand(masterKeyRemovePasswordWrapCmd)
	rootCmd.AddCommand(masterKeyCmd)
}
