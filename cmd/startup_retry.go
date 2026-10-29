package cmd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"
)

// defaultStartupRetry is how long startup keeps retrying Vault before it
// gives up. It stays under a startup probe of 75 checks 2 s apart (150 s),
// so a Vault blip delays a start instead of crash-looping the Pod.
const defaultStartupRetry = 120 * time.Second

// maxStartupRetry bounds AGENT_VAULT_STARTUP_RETRY_SECONDS.
const maxStartupRetry = 3600

// startupRetryWindow reads AGENT_VAULT_STARTUP_RETRY_SECONDS: 0 tries once,
// unset is 120. Anything else is a misconfiguration and fails startup at once.
func startupRetryWindow(getenv func(string) string) (time.Duration, error) {
	raw := getenv("AGENT_VAULT_STARTUP_RETRY_SECONDS")
	if raw == "" {
		return defaultStartupRetry, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 || n > maxStartupRetry {
		return 0, fmt.Errorf("AGENT_VAULT_STARTUP_RETRY_SECONDS must be 0 to %d", maxStartupRetry)
	}
	return time.Duration(n) * time.Second, nil
}

// startupRetry is the window in force, set once at startup.
var startupRetry = defaultStartupRetry

// startupBackoff is the wait after each failed attempt, doubling to 10 s.
var startupBackoff = time.Second

// retryAtStartup runs attempt until it succeeds or the startup window has
// passed, and returns the last error. Each failure is logged by what failed
// and its error text, which carries no secret values.
func retryAtStartup(logger *slog.Logger, what string, attempt func() error) error {
	deadline := time.Now().Add(startupRetry)
	wait := startupBackoff
	for try := 1; ; try++ {
		err := attempt()
		if errors.As(err, new(stopRetrying)) {
			return err
		}
		if err == nil {
			if try > 1 {
				logger.Info("startup step succeeded after retries", slog.String("step", what), slog.Int("attempts", try))
			}
			return nil
		}
		left := time.Until(deadline)
		if left <= 0 {
			return err
		}
		wait = min(wait, left)
		logger.Warn("startup step failed; retrying", slog.String("step", what), slog.Int("attempt", try),
			slog.Duration("retry_in", wait), slog.String("error", err.Error()))
		time.Sleep(wait)
		wait = min(2*wait, 10*time.Second)
	}
}

// boundedAttempt runs one attempt under a deadline even if it ignores its
// context. A result that arrives after the deadline goes to late, so a client
// it built can be closed instead of left running.
func boundedAttempt[T any](timeout time.Duration, run func(context.Context) (T, error), late func(T)) (T, error) {
	type result struct {
		v   T
		err error
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	done := make(chan result, 1)
	go func() {
		v, err := run(ctx)
		done <- result{v, err}
	}()
	select {
	case r := <-done:
		cancel()
		return r.v, r.err
	case <-time.After(timeout):
		cancel()
		go func() {
			if r := <-done; r.err == nil && late != nil {
				late(r.v)
			}
		}()
		var zero T
		return zero, fmt.Errorf("timed out after %s", timeout)
	}
}

// stopRetrying ends retryAtStartup at once: the failure is a setting, not Vault.
type stopRetrying struct{ err error }

func (s stopRetrying) Error() string { return s.err.Error() }
func (s stopRetrying) Unwrap() error { return s.err }
