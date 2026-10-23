//go:build !unix

package main

import (
	"os"
	"os/exec"
	"time"
)

func configureChildProcess(cmd *exec.Cmd) {
	cmd.WaitDelay = 250 * time.Millisecond
}

func signalChildProcesses(cmd *exec.Cmd, sig os.Signal) error {
	if cmd.Process == nil {
		return os.ErrProcessDone
	}
	return cmd.Process.Signal(sig)
}

func stopChildProcesses(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}
