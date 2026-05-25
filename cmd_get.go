package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

type GetCmd struct {
	Name      string `arg:"" help:"Secret name."`
	Plaintext bool   `name:"plaintext" help:"Print the secret value. REQUIRED — refuses to run unless stdout is a TTY AND OPQ_I_AM_HUMAN=1 is set in the environment AND the user confirms on the controlling terminal."`
}

// envHumanConfirm is the env-var a human must inline-set to prove they (not
// an AI agent in a PTY) are running 'opq get --plaintext'. The check exists
// because modern agent runtimes (Claude Code, Cursor, tmux, script(1),
// expect, pexpect) allocate a PTY, so isatty(stdout) is bypassable — but
// such runtimes will not by default inherit an inline env override unless
// the human consciously prepends it on the command line.
const envHumanConfirm = "OPQ_I_AM_HUMAN"

// confirmInputPrompt is the canonical prompt copy. Exported as a constant
// so tests don't have to mirror it.
const confirmInputPrompt = "Type the secret name to confirm release: "

// errInteractiveGate is returned when any of the layered gates fail. The
// outer Run() converts it into the user-facing error and audit message.
var errInteractiveGate = errors.New("interactive release gate")

// getGateConfig holds the dependencies that the gate uses, factored out so
// tests can drive the logic without touching real TTYs or env vars.
type getGateConfig struct {
	stdoutIsTTY  bool
	envHumanFlag string // value of OPQ_I_AM_HUMAN as read by caller
	// openConfirmTTY returns a reader/writer pair representing the
	// controlling terminal (/dev/tty in production), plus a closer the
	// caller must invoke. If the TTY cannot be opened, err is returned and
	// the gate fails — humans always have a /dev/tty even when stdin is
	// redirected; AI runtimes that redirect both ends do not.
	openConfirmTTY func() (io.Reader, io.Writer, io.Closer, error)
}

// checkInteractiveGate runs the layered checks. On success, returns
// (nil, ""). On failure, returns errInteractiveGate plus a short reason
// string suitable for the audit log message.
func checkInteractiveGate(name string, cfg getGateConfig) (error, string) {
	if !cfg.stdoutIsTTY {
		return errInteractiveGate, "stdout not a tty"
	}
	if cfg.envHumanFlag != "1" {
		return errInteractiveGate, "missing OPQ_I_AM_HUMAN=1"
	}
	r, w, closer, err := cfg.openConfirmTTY()
	if err != nil {
		return errInteractiveGate, "no controlling tty: " + err.Error()
	}
	defer closer.Close()
	// Prompt and read a line from the controlling terminal. The /dev/tty
	// detour means redirected stdin (e.g. </dev/null) cannot satisfy this.
	// In an interactive PTY the AI master can still see the prompt and
	// reply, but combined with the inline env-var override the bar is
	// "AI must explicitly prepend an env var AND type the secret name" —
	// both visible in shell history and audit log.
	if _, err := fmt.Fprintf(w, "%s", confirmInputPrompt); err != nil {
		return errInteractiveGate, "tty write: " + err.Error()
	}
	br := bufio.NewReader(r)
	line, err := br.ReadString('\n')
	if err != nil && err != io.EOF {
		return errInteractiveGate, "tty read: " + err.Error()
	}
	got := strings.TrimRight(line, "\r\n")
	if got != name {
		return errInteractiveGate, "confirmation mismatch"
	}
	return nil, ""
}

// openControllingTTY opens /dev/tty for read/write. It returns an error if
// the process has no controlling terminal (e.g. detached / daemonized /
// some CI runners). On systems without /dev/tty (Windows) this will fail —
// acceptable because opaque's production target is linux.
func openControllingTTY() (io.Reader, io.Writer, io.Closer, error) {
	f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, nil, nil, err
	}
	return f, f, f, nil
}

func (c *GetCmd) Run() error {
	if !c.Plaintext {
		return errors.New("refusing to print a secret without --plaintext; use `opq exec` to use the secret without exposing it")
	}

	cfg := getGateConfig{
		stdoutIsTTY:    term.IsTerminal(int(os.Stdout.Fd())),
		envHumanFlag:   os.Getenv(envHumanConfirm),
		openConfirmTTY: openControllingTTY,
	}
	if err, reason := checkInteractiveGate(c.Name, cfg); err != nil {
		_ = AppendAudit(AuditEvent{Action: ActionDenied, SecretName: c.Name, Caller: callerTag(), Message: "get plaintext refused: " + reason})
		return fmt.Errorf("refusing to release plaintext secret (%s). "+
			"This command is gated to human operators: stdout must be a TTY, "+
			"%s=1 must be set inline on the command (do NOT export it), and you "+
			"must retype the secret name on the controlling terminal. "+
			"Use `opq exec` to use the secret without exposing the value", reason, envHumanConfirm)
	}

	ctx := context.Background()
	backend, err := OpenDefaultBackend()
	if err != nil {
		return err
	}
	val, err := backend.Get(ctx, c.Name)
	if err != nil {
		_ = AppendAudit(AuditEvent{Action: ActionDenied, SecretName: c.Name, Caller: callerTag(), Message: err.Error()})
		return err
	}
	defer val.Destroy()

	_ = AppendAudit(AuditEvent{Action: ActionGet, SecretName: c.Name, Caller: callerTag()})

	// Write directly to the TTY; do not use fmt.Println which goes through
	// formatting that may allocate string copies.
	if _, err := os.Stdout.Write(val.Bytes()); err != nil {
		return fmt.Errorf("write secret: %w", err)
	}
	if _, err := os.Stdout.Write([]byte{'\n'}); err != nil {
		return fmt.Errorf("write newline: %w", err)
	}
	return nil
}
