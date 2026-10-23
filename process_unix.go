//go:build unix

package main

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// Keep the command and its ordinary descendants in a private process group.
// WaitDelay also bounds inherited pipe waits if a descendant creates a new group.
// This is lifecycle cleanup, not containment of an adversarial process tree.
func configureChildProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = 250 * time.Millisecond
	cmd.Cancel = func() error { return signalChildProcesses(cmd, syscall.SIGKILL) }
}

func signalChildProcesses(cmd *exec.Cmd, sig os.Signal) error {
	if cmd.Process == nil {
		return os.ErrProcessDone
	}
	// Interactive CLI commands keep their foreground terminal process group.
	if cmd.SysProcAttr == nil || !cmd.SysProcAttr.Setpgid {
		return cmd.Process.Signal(sig)
	}
	s, ok := sig.(syscall.Signal)
	if !ok {
		return cmd.Process.Signal(sig)
	}
	err := syscall.Kill(-cmd.Process.Pid, s)
	if errors.Is(err, syscall.ESRCH) {
		return os.ErrProcessDone
	}
	return err
}

func stopChildProcesses(cmd *exec.Cmd) {
	_ = signalChildProcesses(cmd, syscall.SIGKILL)
}
