package hashicorp

import (
	"encoding/json"
	"fmt"
	"strings"
)

const DefaultPollIntervalSeconds = 60

// MinPollIntervalSeconds mirrors the DB CHECK constraint.
const MinPollIntervalSeconds = 10

// DefaultKVVersion applies when kv_version is omitted; KV v2 is the modern Vault default.
const DefaultKVVersion = 2

// VaultConfig is the JSON persisted in vault_credential_stores.config_json.
// Mount and SecretPath name a single KV item whose pairs become the vault's credentials.
type VaultConfig struct {
	Mount      string `json:"mount"`
	SecretPath string `json:"secret_path"`
	KVVersion  int    `json:"kv_version"`
}

// Validate returns a flat error message safe to surface to API callers.
func (c VaultConfig) Validate() error {
	if strings.TrimSpace(c.Mount) == "" {
		return fmt.Errorf("mount is required (e.g. \"secret\")")
	}
	if strings.TrimSpace(c.SecretPath) == "" {
		return fmt.Errorf("secret_path is required")
	}
	if c.KVVersion != 1 && c.KVVersion != 2 {
		return fmt.Errorf("kv_version must be 1 or 2")
	}
	return nil
}

// withDefaults fills zero-value fields so a config omitting kv_version resolves to KV v2.
func (c VaultConfig) withDefaults() VaultConfig {
	if c.KVVersion == 0 {
		c.KVVersion = DefaultKVVersion
	}
	return c
}

func MarshalConfigJSON(c VaultConfig) (string, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// ParseConfigJSON inverts MarshalConfigJSON, trimming and applying defaults so older rows still resolve.
func ParseConfigJSON(raw string) (VaultConfig, error) {
	var c VaultConfig
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		return VaultConfig{}, err
	}
	c.Mount = strings.TrimSpace(c.Mount)
	c.SecretPath = strings.TrimPrefix(strings.TrimSpace(c.SecretPath), "/")
	return c.withDefaults(), nil
}

// Secret is the broker-facing key/value pair pulled from HashiCorp Vault.
type Secret struct {
	Key   string
	Value string
}
