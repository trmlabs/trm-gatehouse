package httpcatalog

import (
	"fmt"
	"regexp"
	"strings"
	"sync/atomic"
)

// The operator's Vault naming rules, each a setting with a default; every allowed name still has the policy-safe shape.
const (
	// KeyPrefixEnv names the KV path every HTTP key lies under (validate --key-prefix): lower-case segments. Empty means DefaultKeyPrefix.
	KeyPrefixEnv     = "AGENT_VAULT_CATALOG_KEY_PREFIX"
	DefaultKeyPrefix = "vendors"
	// RolePatternEnv names the database role naming rule (validate --role-pattern): a regular expression for the role name before its suffix, with {environment}. Empty means DefaultRolePattern.
	RolePatternEnv = "AGENT_VAULT_CATALOG_ROLE_PATTERN"
	// DefaultRolePattern is <env>.<region>.<cluster>.<name>, or the same prefixed with "gatehouse-".
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

func keyPath() (string, *regexp.Regexp) {
	if r := keyRules.Load(); r != nil {
		return r.prefix, r.path
	}
	return DefaultKeyPrefix, vendorKeyPath
}

// SetRolePattern sets the database role naming rule; it must name {environment} so a catalog never reaches another environment's roles. Empty restores DefaultRolePattern.
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
