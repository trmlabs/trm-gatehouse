package oauth

import "golang.org/x/sync/singleflight"

// RefreshResult is the outcome of a single refresh attempt, shared across all
// concurrent callers for the same key via singleflight.
type RefreshResult struct {
	AccessToken string
	Refreshed   bool
	Err         error
}

// Refresher deduplicates concurrent token refreshes using singleflight so that
// multiple goroutines waiting on the same credential see one network call.
type Refresher struct {
	group singleflight.Group
}

// NewRefresher returns a ready-to-use Refresher.
func NewRefresher() *Refresher {
	return &Refresher{}
}

// Do executes fn at most once per key at a time; concurrent callers wait and share the RefreshResult.
func (r *Refresher) Do(key string, fn func() RefreshResult) RefreshResult {
	v, _, _ := r.group.Do(key, func() (interface{}, error) {
		res := fn()
		return res, nil
	})
	return v.(RefreshResult)
}
