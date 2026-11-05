package cmd

import "fmt"

// ExitCodeError carries a process exit code through RunE so deferred cleanups run before Execute() calls os.Exit.
type ExitCodeError struct {
	Code int
}

func (e *ExitCodeError) Error() string {
	return fmt.Sprintf("exited with status %d", e.Code)
}
