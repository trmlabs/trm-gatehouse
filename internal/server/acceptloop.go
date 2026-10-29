package server

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"syscall"
	"time"
)

// acceptRetryMax caps the wait between retries after a temporary accept error.
const acceptRetryMax = time.Second

// temporaryAcceptError reports an accept failure that clears by itself: the
// process or the host is out of descriptors or buffers, or a peer gave up
// before the accept finished.
func temporaryAcceptError(err error) bool {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	for _, errno := range []syscall.Errno{syscall.EMFILE, syscall.ENFILE, syscall.ENOBUFS, syscall.ENOMEM, syscall.ECONNABORTED} {
		if errors.Is(err, errno) {
			return true
		}
	}
	return false
}

// acceptLoop hands each connection of l to handle. A closed listener ends it
// quietly. A temporary error is logged and retried with a growing wait, so a
// burst of descriptor exhaustion is visible and recovers. Any other error is
// logged and returned: a listener that cannot accept while its port stays
// bound would refuse every client with nothing in the log, so the caller exits
// and the Pod restarts.
func acceptLoop(l net.Listener, name string, logger *slog.Logger, handle func(net.Conn)) error {
	var wait time.Duration
	for {
		c, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			if !temporaryAcceptError(err) {
				logger.Error("accept failed; the listener is stopping", slog.String("listener", name), slog.String("error", err.Error()))
				return fmt.Errorf("%s listener: %w", name, err)
			}
			wait = min(max(2*wait, 5*time.Millisecond), acceptRetryMax)
			logger.Warn("accept failed; retrying", slog.String("listener", name), slog.String("error", err.Error()), slog.Duration("wait", wait))
			time.Sleep(wait)
			continue
		}
		wait = 0
		handle(c)
	}
}
