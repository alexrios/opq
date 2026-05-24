package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"golang.org/x/term"
)

type GetCmd struct {
	Name      string `arg:"" help:"Secret name."`
	Plaintext bool   `name:"plaintext" help:"Print the secret value. REQUIRED — refuses to run unless stdout is a TTY, so the value cannot be piped to a file or another process."`
}

func (c *GetCmd) Run() error {
	if !c.Plaintext {
		return errors.New("refusing to print a secret without --plaintext; use `opq exec` to use the secret without exposing it")
	}
	if !term.IsTerminal(int(os.Stdout.Fd())) {
		_ = AppendAudit(AuditEvent{Action: ActionDenied, SecretName: c.Name, Caller: callerTag(), Message: "non-tty stdout"})
		return errors.New("refusing to write secret to a non-terminal; use `opq exec` to inject the secret as an environment variable without exposing the value")
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
