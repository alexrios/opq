//go:build integration && (darwin || linux)

package main

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestSandboxMCP_ReturnsUnpaddedOutputWithoutKeyring(t *testing.T) {
	withAuditTmpDir(t)
	if err := VerifySandboxAvailable(); err != nil {
		t.Fatal(err)
	}
	result, out, err := handleRunWithSecrets(t.Context(), nil, runWithSecretsInput{
		Command: "/bin/sh",
		Args:    []string{"-c", "printf synthetic-output"},
	})
	if err != nil || result == nil || result.IsError || !out.Succeeded {
		t.Fatalf("keyring-free MCP run failed: %v %v %+v", err, result, out)
	}
	if out.Stdout != "synthetic-output" || out.Stderr != "" {
		t.Fatalf("output was padded or changed: %+v", out)
	}
}

func TestSandboxMCP_DeadlineKillsDescendantsAndAudits(t *testing.T) {
	withAuditTmpDir(t)
	if err := VerifySandboxAvailable(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	// A foreground pipeline creates descendants without requiring the shell
	// to reopen protected /dev/null during asynchronous-job setup.
	result, out, err := handleRunWithSecrets(ctx, nil, runWithSecretsInput{
		Command: "/bin/sh",
		Args:    []string{"-c", "/bin/sleep 10 | /bin/cat"},
	})
	if err != nil || result == nil || result.IsError || !out.TimedOut || out.Succeeded || out.ExitCode != 1 {
		t.Fatalf("deadline result incorrect: %v %v %+v", err, result, out)
	}
	if elapsed := time.Since(start); elapsed >= 2*time.Second {
		t.Fatalf("MCP deadline exceeded cleanup budget: %v", elapsed)
	}
	lines, err := tailAudit(10)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(lines, "\n"), "timed_out=true") {
		t.Fatalf("canceled run has no completion audit: %v", lines)
	}
}
