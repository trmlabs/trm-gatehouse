package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/Infisical/agent-vault/internal/httpcatalog"
)

// kvMountEnv names the KV version 2 mount for the broker's own documents
// (the audit HMAC key, the GitHub App key fallback) when no more specific
// setting names one.
const (
	kvMountEnv     = "AGENT_VAULT_KV_MOUNT"
	defaultKVMount = "gatehouse"
)

// kvMount returns AGENT_VAULT_KV_MOUNT, or gatehouse when it is unset.
func kvMount(getenv func(string) string) (string, error) {
	mount := getenv(kvMountEnv)
	if mount == "" {
		return defaultKVMount, nil
	}
	if !httpcatalog.ValidMount(mount) {
		return "", fmt.Errorf("%s must be lower-case segments of letters, digits, _ and - joined by /", kvMountEnv)
	}
	return mount, nil
}

// catalogSettings applies every catalog setting: the environment, the
// naming rules for HTTP key paths and database roles, and the size limit for
// an Automation's settings.
func catalogSettings(getenv func(string) string) error {
	if err := catalogEnvironment(getenv); err != nil {
		return err
	}
	if err := httpcatalog.SetKeyPrefix(getenv(httpcatalog.KeyPrefixEnv)); err != nil {
		return err
	}
	if err := httpcatalog.SetSettingsMaxBytes(getenv(httpcatalog.SettingsMaxBytesEnv)); err != nil {
		return err
	}
	return httpcatalog.SetRolePattern(getenv(httpcatalog.RolePatternEnv))
}

// validateSettings reads the catalog's naming settings from validate's
// flags, which default to the broker's own settings, so validate applies the
// rules the broker will.
func validateSettings(cmd *cobra.Command) func(string) string {
	flags := map[string]string{
		"AGENT_VAULT_CATALOG_ENVIRONMENT": "environment",
		httpcatalog.KeyPrefixEnv:          "key-prefix",
		httpcatalog.RolePatternEnv:        "role-pattern",
		httpcatalog.SettingsMaxBytesEnv:   "settings-max-bytes",
	}
	return func(name string) string {
		value, _ := cmd.Flags().GetString(flags[name])
		return value
	}
}

func init() {
	f := brokerCatalogValidateCmd.Flags()
	f.String("key-prefix", os.Getenv(httpcatalog.KeyPrefixEnv), "KV path every HTTP key must lie under; empty means "+httpcatalog.DefaultKeyPrefix)
	f.String("role-pattern", os.Getenv(httpcatalog.RolePatternEnv), "database role naming rule: a regular expression for the role before -readonly or -readwrite, with {environment}; empty means "+httpcatalog.DefaultRolePattern)
	f.String("settings-max-bytes", os.Getenv(httpcatalog.SettingsMaxBytesEnv), fmt.Sprintf("bytes one Automation's settings may hold, names and values together; empty means %d", httpcatalog.DefaultSettingsMaxBytes))
}
