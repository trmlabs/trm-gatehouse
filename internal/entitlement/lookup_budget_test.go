package entitlement

import (
	"context"
	"testing"
	"time"
)

// The per-person budget is the setting when one is given, with no smaller
// cap behind it, and today's 60 a minute when none is.
func TestLookupBudgetIsASetting(t *testing.T) {
	for _, c := range []struct {
		name string
		set  int
		want int
	}{{"default", 0, DefaultLookupsPerMinute}, {"raised well past the default", 5000, 5000}} {
		t.Run(c.name, func(t *testing.T) {
			src := &countingSource{groups: map[string][]string{"sso|carol": {"g2"}}}
			now := time.Now()
			cache := &Cache{Source: src, TTL: time.Minute, LookupsPerMinute: c.set, Now: func() time.Time { return now }}
			ctx := context.Background()
			for i := 0; i < c.want; i++ {
				if d := Decide(ctx, cache, claudePool, t2Entry, carol); !d.Allowed {
					t.Fatalf("lookup %d of %d refused: %s", i+1, c.want, d.Outcome)
				}
			}
			now = now.Add(DefaultRecentAnswer)
			if d := Decide(ctx, cache, claudePool, t2Entry, carol); d.Allowed || d.Outcome != "entitlement_rate_limited" || src.count() != c.want {
				t.Fatalf("past %d: %+v asks=%d", c.want, d, src.count())
			}
		})
	}
}
