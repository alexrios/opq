//go:build darwin || linux

package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"golang.org/x/term"
)

func TestCLIProcessReadsControllingTTYWithRedirectedStdin(t *testing.T) {
	if os.Getenv("OPQ_TEST_REDIRECTED_TTY") == "1" {
		if term.IsTerminal(int(os.Stdin.Fd())) {
			t.Fatal("helper stdin should be redirected")
		}
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "/bin/sh", "-c", `IFS= read -r value </dev/tty; test "$value" = synthetic-line`)
		cmd.Stdin = os.Stdin
		var output bytes.Buffer
		cmd.Stdout, cmd.Stderr = &output, &output
		configureCLIChildProcess(cmd)
		err := cmd.Run()
		stopChildProcesses(cmd)
		if err != nil {
			t.Fatalf("redirected child could not read its controlling tty: %v: %s", err, output.String())
		}
		return
	}
	master, slave := openTestPTY(t)
	// Drain terminal echo so macOS can finish closing the slave on helper exit.
	go io.Copy(io.Discard, master)
	input, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCLIProcessReadsControllingTTYWithRedirectedStdin$")
	cmd.Env = append(os.Environ(), "OPQ_TEST_REDIRECTED_TTY=1")
	cmd.Stdin = input
	// Give the helper its own session and synthetic controlling terminal while
	// leaving stdin redirected. Never attach to or read the operator's terminal.
	cmd.ExtraFiles = []*os.File{slave}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 3}
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	if _, err := master.Write([]byte("synthetic-line\n")); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("PTY helper: %v: %s", err, output.String())
	}
}

func TestControllingTTYReadCanBeCanceled(t *testing.T) {
	if os.Getenv("OPQ_TEST_TTY_CANCEL_HELPER") == "1" {
		r, _, closer, err := openControllingTTY()
		if err != nil {
			t.Fatal(err)
		}
		defer closer.Close()
		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
		defer cancel()
		closed := make(chan struct{})
		stopClose := context.AfterFunc(ctx, func() { closer.Close(); close(closed) })
		defer func() {
			if !stopClose() {
				<-closed
			}
		}()
		started := time.Now()
		var one [1]byte
		if _, err := r.Read(one[:]); err == nil {
			t.Fatal("canceled terminal read succeeded")
		}
		if elapsed := time.Since(started); elapsed > time.Second {
			t.Fatalf("terminal read ignored close: %v", elapsed)
		}
		return
	}
	master, slave := openTestPTY(t)
	go io.Copy(io.Discard, master)
	input, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestControllingTTYReadCanBeCanceled$")
	cmd.Env = append(os.Environ(), "OPQ_TEST_TTY_CANCEL_HELPER=1")
	cmd.Stdin = input
	cmd.ExtraFiles = []*os.File{slave}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 3}
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("synthetic terminal cancellation failed: %v: %s", err, output)
	}
}
