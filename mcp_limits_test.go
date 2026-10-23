package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestRunWithSecretsRejectsExcessArgumentBytes(t *testing.T) {
	result, _, err := handleRunWithSecrets(t.Context(), nil, runWithSecretsInput{
		Command: "/bin/true",
		Args:    []string{strings.Repeat("x", mcpMaxArgBytes)},
	})
	if err != nil || result == nil || !result.IsError {
		t.Fatalf("oversized request was not rejected: %v, %v", result, err)
	}
	if text := result.Content[0].(*mcp.TextContent).Text; !strings.Contains(text, "exceed 1 MiB") {
		t.Fatalf("unexpected result: %s", text)
	}
}

func TestRunWithSecretsRejectsWhenBusy(t *testing.T) {
	for i := 0; i < mcpMaxConcurrentRuns; i++ {
		mcpRunSlots <- struct{}{}
	}
	defer func() {
		for i := 0; i < mcpMaxConcurrentRuns; i++ {
			<-mcpRunSlots
		}
	}()
	result, _, err := handleRunWithSecrets(t.Context(), nil, runWithSecretsInput{Command: "/bin/true"})
	if err != nil || result == nil || !result.IsError {
		t.Fatalf("busy server accepted request: %v, %v", result, err)
	}
	if text := result.Content[0].(*mcp.TextContent).Text; !strings.Contains(text, "server_busy") {
		t.Fatalf("unexpected result: %s", text)
	}
}

func TestRunWithSecretsCanceledBeforePreparation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	result, _, err := handleRunWithSecrets(ctx, nil, runWithSecretsInput{Command: "/bin/true"})
	if err != nil || result == nil || !result.IsError {
		t.Fatalf("canceled request accepted: %v, %v", result, err)
	}
	if len(mcpRunSlots) != 0 {
		t.Fatal("canceled request retained a run slot")
	}
}

func TestRunWithSecretsDeadlineReleasesSlotWhileAuditLocked(t *testing.T) {
	withAuditTmpDir(t)
	path, err := auditLogPath()
	if err != nil {
		t.Fatal(err)
	}
	if err := prepareAuditDir(filepath.Dir(path)); err != nil {
		t.Fatal(err)
	}
	lock, err := os.OpenFile(filepath.Join(filepath.Dir(path), auditLockFileName), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	// A rescue release makes the regression fail promptly on the old blocking
	// implementation instead of hanging the suite.
	release, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		timer := time.NewTimer(500 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-release:
		}
		_ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	}()
	defer func() { close(release); <-done }()
	ctx, cancel := context.WithTimeout(t.Context(), 25*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, _, _ = handleRunWithSecrets(ctx, nil, runWithSecretsInput{})
	if elapsed := time.Since(start); elapsed >= 250*time.Millisecond {
		t.Fatalf("audit lock kept the run slot beyond deadline: %v", elapsed)
	}
	if len(mcpRunSlots) != 0 {
		t.Fatal("deadline retained the MCP run slot")
	}
}
