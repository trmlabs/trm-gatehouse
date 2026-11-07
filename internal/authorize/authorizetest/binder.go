// Package authorizetest holds test doubles for the authorize package.
package authorizetest

import (
	"context"
	"sync"
	"time"
)

// MemBinder pins runner sessions in memory, as the store does across replicas.
type MemBinder struct {
	mu   sync.Mutex
	pins map[string]string
}

func (b *MemBinder) BindRunnerSession(_ context.Context, token, pod string, _ time.Time) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.pins == nil {
		b.pins = map[string]string{}
	}
	if bound, ok := b.pins[token]; ok {
		return bound, nil
	}
	b.pins[token] = pod
	return pod, nil
}

// PodHasSession reports whether a Cursor session was bound for the Pod, as the store's "cursor-pod:" pin does.
func (b *MemBinder) PodHasSession(_ context.Context, pod string) (bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	_, ok := b.pins["cursor-pod:"+pod]
	return ok, nil
}
