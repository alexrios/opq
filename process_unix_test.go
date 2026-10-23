//go:build unix

package main

import (
	"context"
	"errors"
	"io"
	"os/exec"
	"testing"
	"time"
)

func TestProcessDeadlineClosesDescendantPipes(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", "sleep 10 & wait")
	configureChildProcess(cmd)
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	start := time.Now()
	err := cmd.Run()
	stopChildProcesses(cmd)
	if err == nil || !errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatalf("expected deadline cancellation, got %v / %v", err, ctx.Err())
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("descendant kept pipes open after deadline: %v", elapsed)
	}
}

func TestProcessSuccessfulParentClosesDescendantPipes(t *testing.T) {
	cmd := exec.CommandContext(t.Context(), "/bin/sh", "-c", "sleep 10 & exit 0")
	configureChildProcess(cmd)
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	start := time.Now()
	err := cmd.Run()
	stopChildProcesses(cmd)
	if !errors.Is(err, exec.ErrWaitDelay) {
		t.Fatalf("expected bounded pipe wait, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("successful parent left an unbounded pipe wait: %v", elapsed)
	}
}
