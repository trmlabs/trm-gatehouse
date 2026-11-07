package store

import (
	"context"
	"testing"
	"time"
)

func TestRunnerSessionPins(t *testing.T) { checkRunnerSessionPins(t, openTestDB(t)) }

func checkRunnerSessionPins(t *testing.T, s *SQLStore) {
	t.Helper()
	ctx := context.Background()
	hour := time.Now().Add(time.Hour)
	if pod, err := s.BindRunnerSession(ctx, "tok-1", "pod-a", hour); err != nil || pod != "pod-a" {
		t.Fatalf("first pin: %q %v", pod, err)
	}
	if pod, err := s.BindRunnerSession(ctx, "tok-1", "pod-b", hour); err != nil || pod != "pod-a" {
		t.Fatalf("second Pod got %q %v, want the first Pod", pod, err)
	}
	if pod, err := s.BindRunnerSession(ctx, "tok-2", "pod-b", hour); err != nil || pod != "pod-b" {
		t.Fatalf("another token: %q %v", pod, err)
	}
	// An expired pin frees the token hash (the token itself is expired too).
	if _, err := s.BindRunnerSession(ctx, "tok-3", "pod-a", time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if pod, err := s.BindRunnerSession(ctx, "tok-3", "pod-b", hour); err != nil || pod != "pod-b" {
		t.Fatalf("expired pin still held: %q %v", pod, err)
	}
	if _, err := s.BindRunnerSession(ctx, "", "pod-a", hour); err == nil {
		t.Fatal("empty token pinned")
	}
}

// A Pod has a session once its run owner is pinned, and not after that pin expires.
func TestPodHasSession(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()
	if seen, err := s.PodHasSession(ctx, "pod-x"); err != nil || seen {
		t.Fatalf("before any session: %v %v", seen, err)
	}
	if _, err := s.BindRunnerSession(ctx, "cursor-pod:pod-x", "owner-1", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if seen, err := s.PodHasSession(ctx, "pod-x"); err != nil || !seen {
		t.Fatalf("after a session: %v %v", seen, err)
	}
	if seen, err := s.PodHasSession(ctx, "pod-y"); err != nil || seen {
		t.Fatalf("another Pod: %v %v", seen, err)
	}
	if _, err := s.BindRunnerSession(ctx, "cursor-pod:pod-z", "owner-1", time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if seen, err := s.PodHasSession(ctx, "pod-z"); err != nil || seen {
		t.Fatalf("an expired pin: %v %v", seen, err)
	}
	if _, err := s.PodHasSession(ctx, ""); err == nil {
		t.Fatal("an empty Pod was accepted")
	}
}
