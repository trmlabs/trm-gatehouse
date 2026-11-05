package brokercore

import (
	"strconv"
	"strings"
)

// StartupParameters are the startup parameters a client may send besides user and database: what drivers
// send by default and the pooled broker re-applies. Everything else fails closed, notably "options" and "replication".
var StartupParameters = []string{"application_name", "client_encoding", "DateStyle", "extra_float_digits",
	"search_path", "standard_conforming_strings", "statement_timeout", "TimeZone"}

// StartupParameter reports whether a client may send key with value and returns the canonical pair to forward.
// Keys match case-insensitively; the relay and the broker share it so they cannot disagree.
func StartupParameter(key, value string) (string, string, bool) {
	name, ok := canonicalKeys[strings.ToLower(key)]
	if !ok {
		return "", "", false
	}
	v, ok := StartupValue(name, value)
	if !ok {
		return "", "", false
	}
	return name, v, true
}

var canonicalKeys = func() map[string]string {
	m := make(map[string]string, len(StartupParameters))
	for _, name := range StartupParameters {
		m[strings.ToLower(name)] = name
	}
	return m
}()

// StartupValue checks one value for a canonical key; startup parameters override role settings, so each is bounded and client-only multibyte encodings and off standard_conforming_strings are refused.
func StartupValue(key, value string) (string, bool) {
	switch key {
	case "statement_timeout":
		if value == "" || len(value) > 10 {
			return "", false
		}
		for i := 0; i < len(value); i++ {
			if value[i] < '0' || value[i] > '9' {
				return "", false
			}
		}
		if n, err := strconv.ParseUint(value, 10, 31); err != nil || n == 0 {
			return "", false
		}
		return value, true
	case "application_name":
		if len(value) > 63 || !printable(value) {
			return "", false
		}
		return value, true
	case "client_encoding":
		canonical, ok := encodings[cleanEncoding(value)]
		return canonical, ok
	case "standard_conforming_strings":
		if !strings.EqualFold(value, "on") {
			return "", false
		}
		return "on", true
	case "DateStyle", "extra_float_digits", "search_path", "TimeZone":
		if len(value) > 256 || !printable(value) {
			return "", false
		}
		return value, true
	default:
		return "", false
	}
}

func printable(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// cleanEncoding lowercases and keeps only letters and digits, as PostgreSQL does.
func cleanEncoding(s string) string {
	if len(s) > 32 {
		return ""
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z':
			b.WriteByte(c + 'a' - 'A')
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
			b.WriteByte(c)
		}
	}
	return b.String()
}

// encodings maps cleaned names and aliases to PostgreSQL 16's canonical server encodings, all ASCII-preserving.
var encodings = func() map[string]string {
	canonical := []string{"SQL_ASCII", "EUC_JP", "EUC_CN", "EUC_KR", "EUC_TW", "EUC_JIS_2004", "UTF8", "MULE_INTERNAL",
		"LATIN1", "LATIN2", "LATIN3", "LATIN4", "LATIN5", "LATIN6", "LATIN7", "LATIN8", "LATIN9", "LATIN10",
		"WIN1256", "WIN1258", "WIN866", "WIN874", "KOI8R", "WIN1251", "WIN1252", "ISO_8859_5", "ISO_8859_6",
		"ISO_8859_7", "ISO_8859_8", "WIN1250", "WIN1253", "WIN1254", "WIN1255", "WIN1257", "KOI8U"}
	m := make(map[string]string, len(canonical)+32)
	for _, name := range canonical {
		m[cleanEncoding(name)] = name
	}
	aliases := map[string]string{
		"unicode": "UTF8", "iso88591": "LATIN1", "iso88592": "LATIN2", "iso88593": "LATIN3", "iso88594": "LATIN4",
		"iso88599": "LATIN5", "iso885910": "LATIN6", "iso885913": "LATIN7", "iso885914": "LATIN8", "iso885915": "LATIN9",
		"iso885916": "LATIN10", "koi8": "KOI8R", "win": "WIN1251", "alt": "WIN866", "cp866": "WIN866", "cp874": "WIN874",
		"cp1250": "WIN1250", "cp1251": "WIN1251", "cp1252": "WIN1252",
		"cp1253": "WIN1253", "cp1254": "WIN1254", "cp1255": "WIN1255", "cp1256": "WIN1256", "cp1257": "WIN1257",
		"cp1258": "WIN1258", "tcvn": "WIN1258", "tcvn5712": "WIN1258",
		"vscii": "WIN1258", "abc": "WIN1258",
	}
	for alias, name := range aliases {
		m[alias] = name
	}
	return m
}()
