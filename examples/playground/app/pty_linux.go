package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"golang.org/x/sys/unix"
)

func startShell() (*exec.Cmd, *os.File, error) {
	master, e := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if e != nil {
		return nil, nil, e
	}
	fail := func(e error) (*exec.Cmd, *os.File, error) { _ = master.Close(); return nil, nil, e }
	if e = unix.IoctlSetPointerInt(int(master.Fd()), unix.TIOCSPTLCK, 0); e != nil {
		return fail(e)
	}
	n, e := unix.IoctlGetInt(int(master.Fd()), unix.TIOCGPTN)
	if e != nil {
		return fail(e)
	}
	slave, e := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|syscall.O_NOCTTY, 0)
	if e != nil {
		return fail(e)
	}
	defer func() { _ = slave.Close() }()
	settings, e := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
	if e != nil {
		return fail(e)
	}
	settings.Lflag &^= unix.ECHO
	if e = unix.IoctlSetTermios(int(slave.Fd()), unix.TCSETS, settings); e != nil {
		return fail(e)
	}
	_ = unix.IoctlSetWinsize(int(master.Fd()), unix.TIOCSWINSZ, &unix.Winsize{Row: 32, Col: 100})
	cmd := exec.Command("/bin/bash", "--noprofile", "--norc", "--noediting", "-i")
	cmd.Env = append(os.Environ(), "TERM=dumb", "PS1=", "PS2=", "HTTPS_PROXY=http://relay:8080", "SSL_CERT_FILE=/public/interception.crt")
	cmd.Stdin = slave
	cmd.Stdout = slave
	cmd.Stderr = slave
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if e = cmd.Start(); e != nil {
		return fail(e)
	}
	return cmd, master, nil
}
