package ratelimit

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// semaphore is a counting semaphore with a short wait budget; callers must call release once, and it is nil on denial.
type semaphore struct {
	slots   chan struct{}
	held    atomic.Int64
	timeout time.Duration
}

func newSemaphore(capacity int, waitBudget time.Duration) *semaphore {
	if capacity < 1 {
		capacity = 1
	}
	if waitBudget <= 0 {
		waitBudget = 2 * time.Second
	}
	return &semaphore{
		slots:   make(chan struct{}, capacity),
		timeout: waitBudget,
	}
}

// acquire tries non-blocking, then waits up to the budget or ctx; release is non-nil only when Allow is true.
func (s *semaphore) acquire(ctx context.Context) (func(), Decision) {
	// Fast path: slot available immediately.
	select {
	case s.slots <- struct{}{}:
		s.held.Add(1)
		return s.releaseOnce(), AllowOK(cap(s.slots)-len(s.slots), cap(s.slots))
	default:
	}

	// Wait up to the budget or until ctx is done.
	budget := s.timeout
	timer := time.NewTimer(budget)
	defer timer.Stop()
	select {
	case s.slots <- struct{}{}:
		s.held.Add(1)
		return s.releaseOnce(), AllowOK(cap(s.slots)-len(s.slots), cap(s.slots))
	case <-ctx.Done():
		return nil, Deny("concurrency", time.Second, cap(s.slots))
	case <-timer.C:
		return nil, Deny("concurrency", time.Second, cap(s.slots))
	}
}

func (s *semaphore) releaseOnce() func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			<-s.slots
			s.held.Add(-1)
		})
	}
}

// held returns the current number of in-flight holders (for gauges).
func (s *semaphore) holders() int64 { return s.held.Load() }

// keyedSemaphore holds per-key semaphores of equal capacity; maxKeys evicts idle ones to bound memory.
type keyedSemaphore struct {
	mu         sync.Mutex
	sems       map[string]*semaphore
	capacity   int
	waitBudget time.Duration
	maxKeys    int
}

func newKeyedSemaphore(cfg TierConfig, waitBudget time.Duration) *keyedSemaphore {
	c := cfg.Concurrency
	if c < 1 {
		c = 1
	}
	mk := cfg.MaxKeys
	if mk <= 0 {
		mk = 10000
	}
	return &keyedSemaphore{
		sems:       make(map[string]*semaphore),
		capacity:   c,
		waitBudget: waitBudget,
		maxKeys:    mk,
	}
}

// reconfigure sets the per-key capacity; existing semaphores keep their old capacity until released.
func (k *keyedSemaphore) reconfigure(cfg TierConfig) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if cfg.Concurrency > 0 {
		k.capacity = cfg.Concurrency
	}
	if cfg.MaxKeys > 0 {
		k.maxKeys = cfg.MaxKeys
	}
}

// acquire returns a release function and decision for a specific key.
func (k *keyedSemaphore) acquire(ctx context.Context, key string) (func(), Decision) {
	k.mu.Lock()
	sem, ok := k.sems[key]
	if !ok {
		sem = newSemaphore(k.capacity, k.waitBudget)
		k.sems[key] = sem
		k.evictLocked(key)
	}
	k.mu.Unlock()
	return sem.acquire(ctx)
}

// evictLocked bounds the sems map, dropping idle entries first, else the weakest-claim one. Called under k.mu.
func (k *keyedSemaphore) evictLocked(skipKey string) {
	if k.maxKeys <= 0 || len(k.sems) <= k.maxKeys {
		return
	}
	for kk, ss := range k.sems {
		if kk == skipKey {
			continue
		}
		if ss.holders() == 0 {
			delete(k.sems, kk)
			if len(k.sems) <= k.maxKeys {
				return
			}
		}
	}
	// Hard fallback: holders captured the sem pointer, so dropping an arbitrary entry is safe.
	for kk := range k.sems {
		if kk == skipKey {
			continue
		}
		delete(k.sems, kk)
		if len(k.sems) <= k.maxKeys {
			return
		}
	}
}
