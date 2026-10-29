package auditchain

import "testing"

// A settings row names settings and never holds a value: anything but
// comma-separated setting names is refused before it is written.
func TestSettingsFieldHoldsNamesOnly(t *testing.T) {
	for _, ok := range []string{"", "API_BASE", "API_BASE,MODE,_x1"} {
		if err := (Event{Event: EventSettings, Settings: ok}).Validate(); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"API_BASE=https://api.example.com", "API_BASE,", ",MODE", "API BASE", "1API", "API_BASE;MODE"} {
		if err := (Event{Event: EventSettings, Settings: bad}).Validate(); err == nil {
			t.Errorf("%q: accepted", bad)
		}
	}
	if got := SettingsField([]string{"API_BASE", "MODE"}); got != "API_BASE,MODE" {
		t.Fatalf("%q", got)
	}
}
