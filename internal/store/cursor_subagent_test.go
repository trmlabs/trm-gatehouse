package store

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestCursorSubagents(t *testing.T) { checkCursorSubagents(t, openTestDB(t)) }

func checkCursorSubagents(t *testing.T, s *SQLStore) {
	t.Helper()
	ctx := context.Background()
	hour := time.Now().Add(time.Hour)
	// Unique names, so a real database reused across runs starts clean.
	n := time.Now().Format("150405.000000000")
	parent, other, child := "bc-p-"+n, "bc-q-"+n, "bc-c-"+n
	if p, r, err := s.Subagent(ctx, child); err != nil || p != "" || r != "" {
		t.Fatalf("before registration: %q %q %v", p, r, err)
	}
	if p, r, err := s.RegisterSubagent(ctx, child, parent, "first", hour, 2); err != nil || p != parent || r != "first" {
		t.Fatalf("register: %q %q %v", p, r, err)
	}
	// The first registration wins over both the same parent and another one.
	if p, r, err := s.RegisterSubagent(ctx, child, parent, "again", hour, 2); err != nil || p != parent || r != "first" {
		t.Fatalf("repeat: %q %q %v", p, r, err)
	}
	if p, r, err := s.RegisterSubagent(ctx, child, other, "stolen", hour, 2); err != nil || p != parent || r != "first" {
		t.Fatalf("another parent: %q %q %v", p, r, err)
	}
	if p, r, err := s.Subagent(ctx, child); err != nil || p != parent || r != "first" {
		t.Fatalf("lookup: %q %q %v", p, r, err)
	}
	// A parent at its limit registers no more, and another parent is unaffected.
	if p, _, err := s.RegisterSubagent(ctx, "bc-c2-"+n, parent, "second", hour, 2); err != nil || p != parent {
		t.Fatalf("second child: %q %v", p, err)
	}
	if p, r, err := s.RegisterSubagent(ctx, "bc-c3-"+n, parent, "third", hour, 2); err != nil || p != "" || r != "" {
		t.Fatalf("over the limit: %q %q %v", p, r, err)
	}
	if p, _, err := s.RegisterSubagent(ctx, "bc-c3-"+n, other, "third", hour, 2); err != nil || p != other {
		t.Fatalf("another parent's child: %q %v", p, err)
	}
	// An expired registration is gone, frees its run and counts against no limit.
	if p, _, err := s.RegisterSubagent(ctx, "bc-old-"+n, "bc-r-"+n, "old", time.Now().Add(-time.Second), 1); err != nil || p != "" {
		t.Fatalf("expired registration is in force: %q %v", p, err)
	}
	if p, _, err := s.RegisterSubagent(ctx, "bc-new-"+n, "bc-r-"+n, "new", hour, 1); err != nil || p != "bc-r-"+n {
		t.Fatalf("an expired registration still counts: %q %v", p, err)
	}
	if p, _, err := s.RegisterSubagent(ctx, "bc-old-"+n, "bc-s-"+n, "moved", hour, 1); err != nil || p != "bc-s-"+n {
		t.Fatalf("an expired registration still holds its run: %q %v", p, err)
	}
	for _, bad := range [][3]string{{"", parent, "r"}, {child, "", "r"}, {child, parent, ""}} {
		if _, _, err := s.RegisterSubagent(ctx, bad[0], bad[1], bad[2], hour, 2); err == nil {
			t.Fatalf("incomplete registration %q accepted", bad)
		}
	}
	if _, _, err := s.RegisterSubagent(ctx, "bc-z-"+n, parent, "r", hour, 0); err == nil {
		t.Fatal("a zero limit accepted")
	}
}

// Registrations made at the same moment never keep more than the limit.
func TestCursorSubagentLimitHoldsUnderConcurrency(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()
	hour := time.Now().Add(time.Hour)
	const limit, tries = 3, 24
	var wg sync.WaitGroup
	for i := range tries {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, _ = s.RegisterSubagent(ctx, fmt.Sprintf("bc-race-%d", i), "bc-parent", "r", hour, limit)
		}()
	}
	wg.Wait()
	var held int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM cursor_subagent WHERE parent = 'bc-parent'`).Scan(&held); err != nil || held > limit {
		t.Fatalf("%d registrations kept for a limit of %d (%v)", held, limit, err)
	}
}
