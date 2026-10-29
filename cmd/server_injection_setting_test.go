package cmd

import "testing"

func TestBoundedSettingRefusesTyposAndOutOfRange(t *testing.T) {
	env := func(v string) func(string) string { return func(string) string { return v } }
	for in, want := range map[string]int{"": 7, "1": 1, "100": 100} {
		if got, err := boundedSetting(env(in), "X", 7, 100); err != nil || got != want {
			t.Errorf("%q: got %d, %v, want %d", in, got, err, want)
		}
	}
	for _, in := range []string{"0", "-1", "101", "64Mi", "true", "1e3", " 5"} {
		if _, err := boundedSetting(env(in), "X", 7, 100); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}
