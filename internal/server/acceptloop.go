package server

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"syscall"
	"time"
)

const acceptRetryMax = time.Second

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

// acceptLoop serves l until it closes; a permanent accept error is returned so the Pod restarts instead of refusing clients silently.
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
