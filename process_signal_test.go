//go:build unix

package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestCLIInterruptCleansPrivateChildGroup(t *testing.T) {
	if os.Getenv("OPQ_TEST_CLI_SIGNAL_HELPER") == "1" {
		os.Args = []string{"opq", "exec", "--", "/bin/sh", "-c", `
finish() {
 printf '%s' "$1" > "$TEST_SIGNAL_FILE"
 kill "$leaf" 2>/dev/null
 wait "$leaf" 2>/dev/null
 exit 0
}
trap 'finish INT' INT
trap 'finish TERM' TERM
trap 'finish HUP' HUP
/bin/sleep 20 & leaf=$!
printf '%s %s\n' "$$" "$leaf" > "$TEST_READY_FILE"
while :; do wait "$leaf"; done
`}
		os.Exit(run())
	}
	for _, tc := range []struct {
		signal syscall.Signal
		name   string
	}{{syscall.SIGINT, "INT"}, {syscall.SIGTERM, "TERM"}, {syscall.SIGHUP, "HUP"}} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			ready := filepath.Join(root, "ready")
			handled := filepath.Join(root, "handled")
			ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCLIInterruptCleansPrivateChildGroup$", "-test.timeout=10s")
			cmd.Env = append(os.Environ(), "OPQ_TEST_CLI_SIGNAL_HELPER=1", "TEST_READY_FILE="+ready, "TEST_SIGNAL_FILE="+handled, "XDG_STATE_HOME="+root)
			// Give the helper no controlling tty so the real CLI creates a private
			// child process group. This test never accesses a real secret or keyring.
			cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
			var output bytes.Buffer
			cmd.Stdout, cmd.Stderr = &output, &output
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { cmd.Process.Kill(); cmd.Wait() }()
			var childPID, leafPID int
			deadline := time.Now().Add(5 * time.Second)
			for time.Now().Before(deadline) {
				data, err := os.ReadFile(ready)
				if err == nil {
					if n, _ := fmt.Sscanf(string(data), "%d %d", &childPID, &leafPID); n == 2 {
						break
					}
				}
				time.Sleep(10 * time.Millisecond)
			}
			if childPID == 0 || leafPID == 0 {
				t.Fatalf("CLI child did not become ready: %s", output.String())
			}
			defer syscall.Kill(-childPID, syscall.SIGKILL)
			if err := cmd.Process.Signal(tc.signal); err != nil {
				t.Fatal(err)
			}
			waitErr := cmd.Wait()
			if ctx.Err() != nil {
				t.Fatalf("CLI did not shut down after %s: %s", tc.name, output.String())
			}
			got, err := os.ReadFile(handled)
			if err != nil || string(got) != tc.name {
				t.Fatalf("original signal not handled gracefully: %q / %v; helper exit %v; %s", got, err, waitErr, output.String())
			}
			deadline = time.Now().Add(time.Second)
			for syscall.Kill(-childPID, 0) == nil && time.Now().Before(deadline) {
				time.Sleep(10 * time.Millisecond)
			}
			if err := syscall.Kill(-childPID, 0); err != syscall.ESRCH {
				t.Fatalf("child group survives CLI %s: %v", tc.name, err)
			}
		})
	}
}
