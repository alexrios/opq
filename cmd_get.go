package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"golang.org/x/term"
)

type GetCmd struct {
	Name      string `arg:"" help:"Secret name."`
	Plaintext bool   `name:"plaintext" help:"Print the secret value. REQUIRED — refuses to run unless stdout is a TTY AND OPQ_I_AM_HUMAN=1 is set in the environment AND the user confirms on the controlling terminal."`
}

// envHumanConfirm is the env var a human must inline-set to prove they (not an
// AI agent in a PTY) are running 'opq get --plaintext'. Agent runtimes allocate
// a PTY, so isatty(stdout) alone is bypassable; they won't inherit an inline
// override the operator consciously prepends.
const envHumanConfirm = "OPQ_I_AM_HUMAN"

// confirmInputPrompt is the canonical prompt copy. Exported as a constant
// so tests don't have to mirror it.
const confirmInputPrompt = "Type the secret name to confirm release: "

// errInteractiveGate is returned when any of the layered gates fail. The
// outer Run() converts it into the user-facing error and audit message.
var errInteractiveGate = errors.New("interactive release gate")

func (c *GetCmd) Run() error {
	if !c.Plaintext {
		return errors.New("refusing to print a secret without --plaintext; use `opq exec` to use the secret without exposing it")
	}
	if !validSecretName(c.Name) {
		return fmt.Errorf("invalid secret name %q (must match [A-Za-z0-9_.-]{1,128})", c.Name)
	}

	cfg := retypeGateConfig{
		stdoutIsTTY:    term.IsTerminal(int(os.Stdout.Fd())),
		envHumanFlag:   os.Getenv(envHumanConfirm),
		openConfirmTTY: openControllingTTY,
	}
	if userReason, auditReason, err := checkRetypeGate(cfg, confirmInputPrompt, c.Name, errInteractiveGate); err != nil {
		_ = AppendAudit(AuditEvent{Action: ActionDenied, SecretName: c.Name, Caller: callerTag(), Message: "get_plaintext_refused:" + auditReason})
		return fmt.Errorf("refusing to release plaintext secret (%s). "+
			"This command is gated to human operators: stdout must be a TTY, "+
			"%s=1 must be set inline on the command (do NOT export it), and you "+
			"must retype the secret name on the controlling terminal. "+
			"Use `opq exec` to use the secret without exposing the value", userReason, envHumanConfirm)
	}

	ctx := context.Background()
	backend, err := OpenDefaultBackend()
	if err != nil {
		return err
	}
	val, err := resolveSecret(ctx, backend, c.Name, time.Now().UTC())
	if err != nil {
		_ = AppendAudit(AuditEvent{Action: ActionDenied, SecretName: c.Name, Caller: callerTag(), Message: sanitizePolicyErr(err)})
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
