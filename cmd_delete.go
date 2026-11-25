package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
)

type DeleteCmd struct {
	Names []string `arg:"" help:"One or more secret names to delete."`
}

func (c *DeleteCmd) Run() error {
	if err := c.validateNames(); err != nil {
		return err
	}
	ctx := context.Background()
	backend, err := OpenDefaultBackend()
	if err != nil {
		return err
	}
	return c.runWith(ctx, backend, os.Stderr)
}

func (c *DeleteCmd) validateNames() error {
	if len(c.Names) == 0 {
		return errors.New("missing secret name")
	}
	for _, name := range c.Names {
		if !validSecretName(name) {
			return fmt.Errorf("invalid secret name %q (must match [A-Za-z0-9_.-]{1,128})", name)
		}
	}
	return nil
}

func (c *DeleteCmd) runWith(ctx context.Context, backend Backend, stderr io.Writer) error {
	if err := c.validateNames(); err != nil {
		return err
	}

	failed := 0
	var firstErr error
	for _, name := range c.Names {
		if err := deleteSecret(ctx, backend, name); err != nil {
			_ = AppendAudit(AuditEvent{Action: ActionDenied, SecretName: name, Caller: callerTag(), Message: sanitizeBackendErr(err)})
			wrapped := formatDeleteErr(name, err)
			if len(c.Names) == 1 {
				return wrapped
			}
			fmt.Fprintf(stderr, "%v\n", wrapped)
			if firstErr == nil {
				firstErr = wrapped
			}
			failed++
			continue
		}

		_ = AppendAudit(AuditEvent{Action: ActionDelete, SecretName: name, Caller: callerTag()})
		fmt.Fprintf(stderr, "deleted %q\n", name)
	}

	if failed > 0 {
		return fmt.Errorf("failed to delete %d of %d secret(s): %w", failed, len(c.Names), firstErr)
	}
	return nil
}

func formatDeleteErr(name string, err error) error {
	if errors.Is(err, ErrSecretNotFound) {
		return fmt.Errorf("delete %q: %w (run 'opq list' to see stored secrets)", name, err)
	}
	return fmt.Errorf("delete %q: %w", name, err)
}
