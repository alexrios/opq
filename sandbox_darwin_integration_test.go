//go:build darwin && integration

package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// These tests exercise the real Seatbelt policy with synthetic local fixtures.
// A missing or broken sandbox is a failure when integration tests are selected.
func runSeatbeltSandbox(t *testing.T, profile SandboxProfile, command string, args ...string) (string, error) {
	t.Helper()
	if err := VerifySandboxAvailable(); err != nil {
		t.Fatalf("integration tests require a working Seatbelt sandbox: %v", err)
	}
	wrapped, wrappedArgs, err := WrapCommand(profile, command, args)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, wrapped, wrappedArgs...)
	configureChildProcess(cmd)
	defer stopChildProcesses(cmd)
	cmd.Env = []string{"PATH=/usr/bin:/usr/sbin:/bin:/sbin", "HOME=/tmp"}
	cmd.Dir = "/"
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	err = cmd.Run()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatal("sandbox integration command timed out")
	}
	return output.String(), err
}

func TestSandboxSeatbelt_NetworkPolicy(t *testing.T) {
	withAuditTmpDir(t)
	const marker = "opq-synthetic-local-http"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(marker)) }))
	defer server.Close()
	args := []string{"--noproxy", "*", "--connect-timeout", "1", "--max-time", "2", "--silent", "--show-error", server.URL}
	out, err := runSeatbeltSandbox(t, SandboxNetAllowed, "/usr/bin/curl", args...)
	if err != nil || out != marker {
		t.Fatalf("network-positive control failed: %v out=%q", err, out)
	}
	for _, profile := range []SandboxProfile{SandboxNet, SandboxFull} {
		t.Run(profile.String(), func(t *testing.T) {
			out, err := runSeatbeltSandbox(t, profile, "/usr/bin/curl", args...)
			if err == nil || strings.Contains(out, marker) {
				t.Fatalf("network restriction failed: err=%v out=%q", err, out)
			}
		})
	}
}

func serveSeatbeltUnixFixture(t *testing.T, path, marker string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{
		Handler:           http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(marker)) }),
		ReadHeaderTimeout: time.Second,
	}
	done := make(chan struct{})
	go func() { defer close(done); _ = server.Serve(listener) }()
	t.Cleanup(func() { server.Close(); <-done })
}

func TestSandboxSeatbelt_NetworkAllowedBlocksProtectedUnixSockets(t *testing.T) {
	withAuditTmpDir(t)
	// Darwin limits Unix-socket paths to 104 bytes; t.TempDir may exceed that.
	root, err := os.MkdirTemp("/tmp", "opq-unix-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	home := filepath.Join(root, "home")
	originalHomeLookup := homeDirForMask
	homeDirForMask = func() (string, error) { return home, nil }
	t.Cleanup(func() { homeDirForMask = originalHomeLookup })
	sshSocket := filepath.Join(root, "agent.sock")
	t.Setenv("SSH_AUTH_SOCK", sshSocket)
	const marker = "opq-synthetic-unix-socket"
	for _, tc := range []struct {
		name      string
		path      string
		protected bool
	}{
		{"docker", filepath.Join(home, ".docker", "run", "docker.sock"), true},
		{"gpg", filepath.Join(home, ".gnupg", "S.gpg-agent"), true},
		{"ssh_home", filepath.Join(home, ".ssh", "agent.sock"), true},
		{"ssh_auth_sock", sshSocket, true},
		{"custom_socket", filepath.Join(root, "custom.sock"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			serveSeatbeltUnixFixture(t, tc.path, marker)
			curlArgs := func(path string) []string {
				return []string{"--noproxy", "*", "--max-time", "2", "--silent", "--show-error", "--unix-socket", path, "http://localhost/"}
			}
			out, err := runSeatbeltSandbox(t, SandboxNone, "/usr/bin/curl", curlArgs(tc.path)...)
			if err != nil || out != marker {
				t.Fatalf("socket-positive control failed: %v out=%q", err, out)
			}
			canonical, err := filepath.EvalSymlinks(tc.path)
			if err != nil {
				t.Fatal(err)
			}
			alias := filepath.Join(root, tc.name+"-alias.sock")
			if err := os.Symlink(tc.path, alias); err != nil {
				t.Fatal(err)
			}
			for _, path := range []string{tc.path, canonical, alias} {
				out, err = runSeatbeltSandbox(t, SandboxNetAllowed, "/usr/bin/curl", curlArgs(path)...)
				if tc.protected {
					if err == nil || strings.Contains(out, marker) {
						t.Fatalf("protected socket accepted a connection through %q: %v out=%q", path, err, out)
					}
				} else if err != nil || out != marker {
					t.Fatalf("custom socket unexpectedly blocked: %v out=%q", err, out)
				}
			}
		})
	}
}

func TestSandboxSeatbelt_NetworkAllowedBlocksSymlinkedDockerSocket(t *testing.T) {
	withAuditTmpDir(t)
	root, err := os.MkdirTemp("/tmp", "opq-docker-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	home := filepath.Join(root, "home")
	originalHomeLookup := homeDirForMask
	homeDirForMask = func() (string, error) { return home, nil }
	t.Cleanup(func() { homeDirForMask = originalHomeLookup })
	protected := filepath.Join(home, ".docker", "run", "docker.sock")
	if err := os.MkdirAll(filepath.Dir(protected), 0700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "external.sock")
	const marker = "opq-synthetic-docker-alias"
	serveSeatbeltUnixFixture(t, target, marker)
	if err := os.Symlink(target, protected); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{protected, target} {
		args := []string{"--noproxy", "*", "--max-time", "2", "--silent", "--show-error", "--unix-socket", path, "http://localhost/"}
		out, err := runSeatbeltSandbox(t, SandboxNone, "/usr/bin/curl", args...)
		if err != nil || out != marker {
			t.Fatalf("socket-positive control failed: %v out=%q", err, out)
		}
		out, err = runSeatbeltSandbox(t, SandboxNetAllowed, "/usr/bin/curl", args...)
		if err == nil || strings.Contains(out, marker) {
			t.Fatalf("symlinked Docker socket accepted a connection: %v out=%q", err, out)
		}
	}
}

func TestSandboxSeatbelt_HostReadOnly(t *testing.T) {
	root := withAuditTmpDir(t)
	target := filepath.Join(root, "synthetic.txt")
	const marker = "opq-synthetic-host-file"
	if err := os.WriteFile(target, []byte(marker), 0600); err != nil {
		t.Fatal(err)
	}
	for _, profile := range []SandboxProfile{SandboxNet, SandboxNetAllowed} {
		t.Run(profile.String(), func(t *testing.T) {
			out, err := runSeatbeltSandbox(t, profile, "/bin/cat", target)
			if err != nil || out != marker {
				t.Fatalf("host read unexpectedly denied: %v out=%q", err, out)
			}
			out, err = runSeatbeltSandbox(t, profile, "/bin/sh", "-c", `printf replacement > "$1"`, "sh", target)
			if err == nil {
				t.Fatalf("persistent host write allowed: %q", out)
			}
			data, err := os.ReadFile(target)
			if err != nil || string(data) != marker {
				t.Fatalf("host fixture changed: %v contents=%q", err, data)
			}
		})
	}
}

func TestSandboxSeatbelt_HomeReadRestrictions(t *testing.T) {
	root := withAuditTmpDir(t)
	home := filepath.Join(root, "synthetic-home")
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0700); err != nil {
		t.Fatal(err)
	}
	originalHomeLookup := homeDirForMask
	homeDirForMask = func() (string, error) { return home, nil }
	t.Cleanup(func() { homeDirForMask = originalHomeLookup })
	const marker = "opq-synthetic-home-material"
	credential := filepath.Join(home, ".ssh", "synthetic.txt")
	ordinary := filepath.Join(home, "ordinary.txt")
	for _, target := range []string{credential, ordinary} {
		if err := os.WriteFile(target, []byte(marker), 0600); err != nil {
			t.Fatal(err)
		}
	}
	// Net isolation permits ordinary host reads while masking credential paths.
	out, err := runSeatbeltSandbox(t, SandboxNet, "/bin/cat", ordinary)
	if err != nil || out != marker {
		t.Fatalf("ordinary-home control failed: %v out=%q", err, out)
	}
	for _, tc := range []struct {
		profile SandboxProfile
		target  string
	}{{SandboxNet, credential}, {SandboxNetAllowed, credential}, {SandboxFull, ordinary}} {
		t.Run(tc.profile.String(), func(t *testing.T) {
			out, err := runSeatbeltSandbox(t, tc.profile, "/bin/cat", tc.target)
			if err == nil || strings.Contains(out, marker) {
				t.Fatalf("home read restriction failed: %v out=%q", err, out)
			}
		})
	}
}

func TestSandboxSeatbelt_StateDirectoriesMasked(t *testing.T) {
	withAuditTmpDir(t)
	auditPath, err := auditLogPath()
	if err != nil {
		t.Fatal(err)
	}
	policyDir, err := policyLockDir()
	if err != nil {
		t.Fatal(err)
	}
	const marker = "opq-synthetic-private-state"
	targets := []string{auditPath, filepath.Join(policyDir, "synthetic.txt")}
	for _, target := range targets {
		if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, []byte(marker), 0600); err != nil {
			t.Fatal(err)
		}
		out, err := runSeatbeltSandbox(t, SandboxNone, "/bin/cat", target)
		if err != nil || out != marker {
			t.Fatalf("state fixture control failed: %v out=%q", err, out)
		}
	}
	for _, profile := range []SandboxProfile{SandboxNet, SandboxNetAllowed, SandboxFull} {
		t.Run(profile.String(), func(t *testing.T) {
			for _, target := range targets {
				out, err := runSeatbeltSandbox(t, profile, "/bin/cat", target)
				if err == nil || strings.Contains(out, marker) {
					t.Fatalf("state dir readable: %v out=%q", err, out)
				}
			}
		})
	}
}

func TestSandboxSeatbelt_DeadlineClosesDescendantPipes(t *testing.T) {
	withAuditTmpDir(t)
	if err := VerifySandboxAvailable(); err != nil {
		t.Fatal(err)
	}
	wrapped, args, err := WrapCommand(SandboxNet, "/bin/sh", []string{"-c", "/bin/sleep 10 | /bin/cat"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	cmd := exec.CommandContext(ctx, wrapped, args...)
	configureChildProcess(cmd)
	defer stopChildProcesses(cmd)
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	start := time.Now()
	err = cmd.Run()
	if err == nil || !errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatalf("expected deadline cancellation: %v / %v out=%q", err, ctx.Err(), output.String())
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("descendant kept sandbox pipes open: %v", elapsed)
	}
}
