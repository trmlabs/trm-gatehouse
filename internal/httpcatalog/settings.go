package httpcatalog

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"unicode"
	"unicode/utf8"
)

// Settings are an Automation's plain configuration: environment values its
// runs need, such as an API's base URL, that are not credentials. The broker
// serves them to the sidecar of the Automation's own worker (GET
// SettingsPath), which writes them where the agent's shells read them, so a
// team needs neither a vendor's secret sync, which would copy every team
// secret onto the worker, nor defaults in its own code.
//
// They are never secrets, and the catalog refuses what looks like one: a name
// that reads as a credential's, a value holding a Gatehouse placeholder, or a
// value shaped like a known credential. A name the worker's own runtime sets,
// or one that changes how a shell, a loader, git or a proxy behaves, is
// refused too, so a setting can only add configuration.
const (
	// SettingsMaxBytesEnv names the setting for how many bytes one
	// Automation's settings may hold, names and values together (validate
	// --settings-max-bytes). Empty means DefaultSettingsMaxBytes.
	SettingsMaxBytesEnv = "AGENT_VAULT_CATALOG_SETTINGS_MAX_BYTES"
	// DefaultSettingsMaxBytes is far above what configuration needs: a few
	// hundred bytes is typical.
	DefaultSettingsMaxBytes = 64 << 10
	// MaxSettingsMaxBytes is the highest limit the setting takes. The values
	// become environment variables, and Linux caps a process's arguments and
	// environment together at a few MiB, so one Automation's settings stay
	// well under it.
	MaxSettingsMaxBytes = 1 << 20
	minSettingsMaxBytes = 1 << 10
	// SettingsPath is the broker's route for a sidecar to read its run's
	// Automation settings, on the listener it already reaches the broker on.
	SettingsPath = "/v1/automation-settings"
)

var settingsMaxBytes atomic.Int64 // 0 is DefaultSettingsMaxBytes

// SetSettingsMaxBytes sets how many bytes one Automation's settings may hold.
// Empty restores DefaultSettingsMaxBytes.
func SetSettingsMaxBytes(value string) error {
	if value == "" {
		settingsMaxBytes.Store(0)
		return nil
	}
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil || n < minSettingsMaxBytes || n > MaxSettingsMaxBytes {
		return fmt.Errorf("settings size limit (--settings-max-bytes or %s) must be a whole number of bytes from %d to %d", SettingsMaxBytesEnv, minSettingsMaxBytes, MaxSettingsMaxBytes)
	}
	settingsMaxBytes.Store(n)
	return nil
}

// SettingsMaxBytes is the limit in force for one Automation's settings.
func SettingsMaxBytes() int {
	if n := settingsMaxBytes.Load(); n != 0 {
		return int(n)
	}
	return DefaultSettingsMaxBytes
}

// settingName is an environment variable name a shell can export.
var settingName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)

// secretWords mark a name as a credential's, wherever they appear in it and
// in any case.
var secretWords = []string{"TOKEN", "KEY", "SECRET", "PASSWORD", "PASSWD", "CREDENTIAL", "PRIVATE"}

// reservedSettings are names the shell, the worker's runtime or Gatehouse
// itself set, or that change how a program is found, loaded or trusted.
var reservedSettings = map[string]bool{
	"PATH": true, "HOME": true, "USER": true, "LOGNAME": true, "SHELL": true, "PWD": true, "OLDPWD": true,
	"ENV": true, "IFS": true, "CDPATH": true, "GLOBIGNORE": true, "SHELLOPTS": true, "BASHOPTS": true,
	"PROMPT_COMMAND": true, "PS1": true, "PS2": true, "PS3": true, "PS4": true, "HOSTNAME": true, "TMPDIR": true,
	"NODE_OPTIONS": true, "NODE_PATH": true, "NODE_EXTRA_CA_CERTS": true, "NODE_USE_ENV_PROXY": true,
	"REQUESTS_CA_BUNDLE": true, "CURL_CA_BUNDLE": true,
	"PYTHONPATH": true, "PYTHONHOME": true, "PYTHONSTARTUP": true, "PERL5LIB": true, "PERL5OPT": true,
	"RUBYLIB": true, "RUBYOPT": true, "JAVA_TOOL_OPTIONS": true, "_JAVA_OPTIONS": true, "GCONV_PATH": true,
	"PAGER": true, "MANPAGER": true, "LESS": true, "EDITOR": true, "VISUAL": true,
	"GOFLAGS": true, "GOPROXY": true, "GONOPROXY": true, "GOSUMDB": true, "GONOSUMDB": true, "GONOSUMCHECK": true,
	"GOPRIVATE": true, "GOINSECURE": true, "GOENV": true, "GOTOOLCHAIN": true, "GOROOT": true, "GOPATH": true,
	"GOBIN": true, "GOWORK": true, "GOMODCACHE": true, "PERLLIB": true,
}

// reservedPrefixes cover whole families: Gatehouse's, the runtime's, the shell's, the loader's, git's, TLS trust, the cluster's, and package managers' and interpreters'.
var reservedPrefixes = []string{"GATEHOUSE_", "AGENT_VAULT_", "CURSOR_", "BASH_", "LD_", "DYLD_", "GIT_", "SSL_", "KUBERNETES_", "PIP_", "UV_", "NPM_CONFIG_", "NODE_TLS_", "XDG_", "PYTHON"}

// credentialValue matches a value shaped like a known credential: a PEM
// block, a GitHub, Slack, AWS or API key, a JWT, or a URL carrying a
// password.
var credentialValue = regexp.MustCompile(`-----BEGIN|\bgh[pousr]_[A-Za-z0-9]{20,}|\bgithub_pat_[A-Za-z0-9_]{20,}|\bxox[abposre]-[A-Za-z0-9-]{10,}|\bA[KS]IA[0-9A-Z]{16}\b|\bsk-[A-Za-z0-9_-]{20,}|\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.|://[^/\s@:]*:[^/\s@]+@`)

// CheckSetting checks one setting. Its error names the setting when the name
// is a plain one and never quotes the value.
func CheckSetting(name, value string) error {
	if !settingName.MatchString(name) {
		return errors.New("a setting name must be letters, digits and _, not starting with a digit, at most 128 characters")
	}
	upper := strings.ToUpper(name)
	for _, word := range secretWords {
		if strings.Contains(upper, word) {
			return fmt.Errorf("setting %q reads as a credential (%s): settings are plain configuration, and a credential stays in Vault behind a placeholder", name, word)
		}
	}
	if reservedSettings[upper] || strings.HasSuffix(upper, "_PROXY") || slices.ContainsFunc(reservedPrefixes, func(p string) bool { return strings.HasPrefix(upper, p) }) {
		return fmt.Errorf("setting %q is a name the worker's runtime or Gatehouse sets, or one that changes how programs run", name)
	}
	if !utf8.ValidString(value) || strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return fmt.Errorf("setting %q has a value that is not printable text", name)
	}
	if strings.Contains(strings.ToLower(value), placeholderPrefix) {
		return fmt.Errorf("setting %q has a value holding a Gatehouse placeholder, which only a request through the broker may carry", name)
	}
	if credentialValue.MatchString(value) {
		return fmt.Errorf("setting %q has a value shaped like a credential", name)
	}
	return nil
}

// placeholderPrefix starts every Gatehouse placeholder (__vault_NAME__).
const placeholderPrefix = "__vault_"

// CheckSettings checks every setting, in name order, and their size together
// against limit: the bytes of every name and value.
func CheckSettings(settings map[string]string, limit int) error {
	size := 0
	for _, name := range SettingNames(settings) {
		if err := CheckSetting(name, settings[name]); err != nil {
			return err
		}
		size += len(name) + len(settings[name])
	}
	if size > limit {
		return fmt.Errorf("settings hold %d bytes, more than the %d allowed (--settings-max-bytes or %s)", size, limit, SettingsMaxBytesEnv)
	}
	return nil
}

// SettingNames returns the settings' names in order.
func SettingNames(settings map[string]string) []string {
	names := make([]string, 0, len(settings))
	for name := range settings {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}
