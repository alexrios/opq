//go:build integration

package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func runUnderSandbox(t *testing.T, profile SandboxProfile, cmd string, args ...string) (string, int, error) {
	t.Helper()
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bwrap not available")
	}
	wrapCmd, wrapArgs, err := WrapCommand(profile, cmd, args)
	if err != nil {
		return "", -1, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, wrapCmd, wrapArgs...)
	c.Env = []string{"PATH=/usr/bin:/usr/sbin:/bin:/sbin", "HOME=/tmp"}
	var buf bytes.Buffer
	c.Stdout = &buf
	c.Stderr = &buf
	runErr := c.Run()
	code := 0
	if runErr != nil {
		if ee, ok := runErr.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			code = -1
		}
	}
	return buf.String(), code, nil
}

func hasInternet(t *testing.T) bool {
	t.Helper()
	d := net.Dialer{Timeout: 2 * time.Second}
	conn, err := d.Dial("tcp", "1.1.1.1:443")
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func TestSandboxNet_BlocksNetwork(t *testing.T) {
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl not available")
	}
	out, code, err := runUnderSandbox(t, SandboxNet, "curl",
		"-s", "-o", "/dev/null",
		"-w", "%{http_code}",
		"--connect-timeout", "3",
		"https://1.1.1.1",
	)
	if err != nil {
		t.Fatalf("wrap err: %v", err)
	}
	if code == 0 {
		t.Fatalf("expected curl to fail under SandboxNet, code=0 out=%q", out)
	}
	if strings.Contains(out, "200") {
		t.Fatalf("response 200 leaked through sandbox: %q", out)
	}
}

func TestSandboxNet_AllowsHostFS(t *testing.T) {
	out, code, err := runUnderSandbox(t, SandboxNet, "cat", "/etc/hostname")
	if err != nil {
		t.Fatalf("wrap err: %v", err)
	}
	if code != 0 {
		t.Fatalf("cat /etc/hostname under SandboxNet failed (code=%d): %q", code, out)
	}
	if strings.TrimSpace(out) == "" {
		t.Fatalf("empty hostname output: %q", out)
	}
}

func TestSandboxFull_BlocksNetwork(t *testing.T) {
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl not available")
	}
	out, code, err := runUnderSandbox(t, SandboxFull, "curl",
		"-s", "-o", "/dev/null",
		"-w", "%{http_code}",
		"--connect-timeout", "3",
		"https://1.1.1.1",
	)
	if err != nil {
		t.Fatalf("wrap err: %v", err)
	}
	if code == 0 {
		t.Fatalf("expected curl to fail under SandboxFull, code=0 out=%q", out)
	}
	if strings.Contains(out, "200") {
		t.Fatalf("response 200 leaked through sandbox: %q", out)
	}
}

func TestSandboxFull_BlocksHomeRead(t *testing.T) {
	user := os.Getenv("USER")
	if user == "" {
		t.Skip("USER unset")
	}
	target := "/home/" + user + "/.ssh"
	out, code, err := runUnderSandbox(t, SandboxFull, "ls", target)
	if err != nil {
		t.Fatalf("wrap err: %v", err)
	}
	// Either the directory is missing (tmpfs overlay) or ls fails;
	// either way the host's real .ssh contents must not appear.
	if code == 0 && strings.Contains(out, "id_") {
		t.Fatalf("SandboxFull leaked $HOME/.ssh contents: %q", out)
	}
}

func TestSandboxNone_AllowsNetwork(t *testing.T) {
	if !hasInternet(t) {
		t.Skip("no internet")
	}
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl not available")
	}
	out, code, err := runUnderSandbox(t, SandboxNone, "curl",
		"-s", "-o", "/dev/null",
		"-w", "%{http_code}",
		"--connect-timeout", "5",
		"https://1.1.1.1",
	)
	if err != nil {
		t.Fatalf("wrap err: %v", err)
	}
	if code != 0 {
		t.Fatalf("expected curl to succeed without sandbox, code=%d out=%q", code, out)
	}
	if !strings.Contains(out, "200") && !strings.Contains(out, "301") && !strings.Contains(out, "302") {
		t.Fatalf("expected HTTP response from 1.1.1.1, got %q", out)
	}
}

// TestSandboxNet_SiblingProcIsolation verifies fix for finding C2 (v1.1.1 security review):
// a sibling SandboxNet subprocess must not be able to read another sibling's
// /proc/<pid>/environ (which would expose injected secrets).
//
// Strategy: launch subprocess A (sleep 30) under SandboxNet, confirm it is still alive,
// then launch subprocess B that attempts to grep /proc/*/environ for a canary value.
// B must not find A's environ.
func TestSandboxNet_SiblingProcIsolation(t *testing.T) {
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("bwrap not available")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not available")
	}
	if _, err := exec.LookPath("grep"); err != nil {
		t.Skip("grep not available")
	}

	// Canary value that subprocess A will carry in its environment.
	// We deliberately do NOT put this in the test process's env, so any match
	// in B's output means cross-namespace /proc leakage.
	const canary = "OPQ_C2_CANARY_32chars_unique_value"

	// Build argv for A: sleep long enough for B to run its grep.
	wrapCmdA, wrapArgsA, err := WrapCommand(SandboxNet, "sh", []string{"-c", "sleep 30"})
	if err != nil {
		t.Fatalf("WrapCommand A: %v", err)
	}

	// Build argv for B: grep all /proc/*/environ for the canary.
	// B runs with a clean env (no canary), so a hit means it read A's env.
	wrapCmdB, wrapArgsB, err := WrapCommand(SandboxNet, "sh", []string{"-c",
		fmt.Sprintf("grep -rl '%s' /proc/*/environ 2>/dev/null || true", canary),
	})
	if err != nil {
		t.Fatalf("WrapCommand B: %v", err)
	}

	// Start A with the canary in its env.
	ctxA, cancelA := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelA()
	cmdA := exec.CommandContext(ctxA, wrapCmdA, wrapArgsA...)
	cmdA.Env = []string{
		"PATH=/usr/bin:/usr/sbin:/bin:/sbin",
		"HOME=/tmp",
		canary + "=supersecretvalue",
	}
	if err := cmdA.Start(); err != nil {
		t.Fatalf("start A: %v", err)
	}
	defer func() { _ = cmdA.Process.Kill(); _ = cmdA.Wait() }()

	// Give A time to settle in its sandbox.
	time.Sleep(500 * time.Millisecond)
	// Verify A is still running. cmd.ProcessState is only populated after
	// Wait() returns, so cannot be used here; signal 0 on a live pid is a
	// no-op that returns nil, on a dead pid it returns ESRCH. A live A is
	// load-bearing for this test: without it, B's "canary not found in
	// /proc" would pass vacuously because A's environ has already
	// disappeared.
	if err := cmdA.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatalf("subprocess A is not alive (signal 0 failed: %v) — isolation not tested", err)
	}

	// Run B and collect output.
	var wg sync.WaitGroup
	var outB string
	wg.Add(1)
	go func() {
		defer wg.Done()
		ctxB, cancelB := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancelB()
		cmdB := exec.CommandContext(ctxB, wrapCmdB, wrapArgsB...)
		cmdB.Env = []string{"PATH=/usr/bin:/usr/sbin:/bin:/sbin", "HOME=/tmp"}
		var buf bytes.Buffer
		cmdB.Stdout = &buf
		cmdB.Stderr = &buf
		_ = cmdB.Run()
		outB = buf.String()
	}()
	wg.Wait()

	if strings.Contains(outB, canary) {
		t.Errorf("SandboxNet sibling /proc leakage: subprocess B found canary in output:\n%s", outB)
	}
}
