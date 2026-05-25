//go:build integration

package main

import (
	"bytes"
	"context"
	"net"
	"os"
	"os/exec"
	"strings"
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
