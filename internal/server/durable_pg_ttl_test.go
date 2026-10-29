package server

import (
	"testing"
	"time"
)

func TestParseSharedRoleMaxTTL(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want time.Duration
		ok   bool
	}{
		{"0", 0, true},
		{"168h", 168 * time.Hour, true},
		{"24h", 24 * time.Hour, true},
		{"23h59m59s", 0, false},
		{"1h", 0, false},
		{"1m", 0, false},
		{"-48h", 0, false},
		{"soon", 0, false},
	} {
		got, err := parseSharedRoleMaxTTL(tc.in)
		if (err == nil) != tc.ok || got != tc.want {
			t.Errorf("parseSharedRoleMaxTTL(%q) = %v, %v; want %v, ok=%v", tc.in, got, err, tc.want, tc.ok)
		}
	}
}
