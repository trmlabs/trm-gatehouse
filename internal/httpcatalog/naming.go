package httpcatalog

import (
	"fmt"
	"regexp"
	"strings"
	"sync/atomic"
)

// The operator's Vault naming rules, each a setting with a default. The
// broker reads them from its environment and validate from its flags, so
// both apply the same rules. Every name they allow still has the
// policy-safe shape, since it ends up in the broker's Vault policy.
const (
	// KeyPrefixEnv names the setting for the KV path every HTTP key lies
	// under (validate --key-prefix): lower-case segments, such as vendors or
	// agents/keys. Empty means DefaultKeyPrefix.
	KeyPrefixEnv     = "AGENT_VAULT_CATALOG_KEY_PREFIX"
	DefaultKeyPrefix = "vendors"
	// RolePatternEnv names the setting for the database role naming rule
	// (validate --role-pattern): a regular expression for the role name
	// before its -readonly or -readwrite suffix, with {environment} where
	// the catalog's environment goes. Empty means DefaultRolePattern.
	RolePatternEnv = "AGENT_VAULT_CATALOG_ROLE_PATTERN"
	// DefaultRolePattern is <env>.<region>.<cluster>.<name>, or the
	// Gatehouse-only role for the same connection, the same name prefixed
	// with "gatehouse-".
	DefaultRolePattern = `(gatehouse-)?{environment}\.[a-z]+\.[a-z0-9]+\.[a-z0-9-]+`
)

const environmentSlot = "{environment}"

type keyRule struct {
	prefix string
	path   *regexp.Regexp
}

var (
	keyRules    atomic.Pointer[keyRule]
	rolePattern atomic.Value // string; "" is DefaultRolePattern
	roleRules   atomic.Pointer[roleRule]
)

// SetKeyPrefix sets the KV path every HTTP key must lie under. Empty
// restores DefaultKeyPrefix.
func SetKeyPrefix(prefix string) error {
	if prefix == "" {
		keyRules.Store(nil)
		return nil
	}
	if !ValidMount(prefix) {
		return fmt.Errorf("key prefix (--key-prefix or %s) must be lower-case segments of letters, digits, _ and - joined by /, such as vendors", KeyPrefixEnv)
	}
	keyRules.Store(&keyRule{prefix: prefix, path: regexp.MustCompile(`^` + regexp.QuoteMeta(prefix) + `(/[a-z0-9][a-z0-9_-]*)+$`)})
	return nil
}

// keyPath returns the key prefix and the rule a key path must match: one or
// more lower-case segments under the prefix.
func keyPath() (string, *regexp.Regexp) {
	if r := keyRules.Load(); r != nil {
		return r.prefix, r.path
	}
	return DefaultKeyPrefix, vendorKeyPath
}

// SetRolePattern sets the database role naming rule. The pattern must name
// {environment}, so a catalog for one environment never reaches another's
// roles. Empty restores DefaultRolePattern.
func SetRolePattern(pattern string) error {
	if pattern != "" {
		if !strings.Contains(pattern, environmentSlot) {
			return fmt.Errorf("role pattern (--role-pattern or %s) must contain %s, so roles are named for one environment", RolePatternEnv, environmentSlot)
		}
		if _, err := regexp.Compile(roleExpression(pattern, "staging")); err != nil {
			return fmt.Errorf("role pattern (--role-pattern or %s) is not a valid regular expression: %w", RolePatternEnv, err)
		}
	}
	rolePattern.Store(pattern)
	return nil
}

func roleExpression(pattern, env string) string {
	return `^(?:` + strings.ReplaceAll(pattern, environmentSlot, regexp.QuoteMeta(env)) + `)-(readonly|readwrite)$`
}

// roleRule is the compiled rule for one pattern and environment, kept until
// either changes so a large catalog compiles it once.
type roleRule struct {
	pattern, env string
	role         *regexp.Regexp
}

func environmentRole(env string) *regexp.Regexp {
	pattern, _ := rolePattern.Load().(string)
	if pattern == "" {
		pattern = DefaultRolePattern
	}
	if r := roleRules.Load(); r != nil && r.pattern == pattern && r.env == env {
		return r.role
	}
	r := &roleRule{pattern: pattern, env: env, role: regexp.MustCompile(roleExpression(pattern, env))}
	roleRules.Store(r)
	return r.role
}
