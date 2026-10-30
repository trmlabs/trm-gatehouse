//go:build !linux

package main

import (
	"errors"
	"os"
	"os/exec"
)

func startShell() (*exec.Cmd, *os.File, error) {
	return nil, nil, errors.New("the shell runs in the Linux sandbox container")
}
