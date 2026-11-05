package cmd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"
)

// defaultStartupRetry stays under the startup probe's 150 s so a Vault blip delays a start instead of crash-looping the Pod.
const defaultStartupRetry = 120 * time.Second

const maxStartupRetry = 3600

// startupRetryWindow reads AGENT_VAULT_STARTUP_RETRY_SECONDS: 0 tries once, unset is 120, anything else fails startup.
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

var startupRetry = defaultStartupRetry

// startupBackoff is the wait after each failed attempt, doubling to 10 s.
var startupBackoff = time.Second

// retryAtStartup runs attempt until it succeeds or the window passes and returns the last error; logged errors carry no secrets.
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

// boundedAttempt enforces a deadline even if attempt ignores its context; a late result goes to late so it can be closed.
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
