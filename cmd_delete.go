package main

import (
	"context"
	"fmt"
	"os"
)

type DeleteCmd struct {
	Name string `arg:"" help:"Secret name to delete."`
}

func (c *DeleteCmd) Run() error {
	if !validSecretName(c.Name) {
		return fmt.Errorf("invalid secret name %q (must match [A-Za-z0-9_.-]{1,128})", c.Name)
	}
	ctx := context.Background()
	backend, err := OpenDefaultBackend()
	if err != nil {
		return err
	}
	if err := backend.Delete(ctx, c.Name); err != nil {
		_ = AppendAudit(AuditEvent{Action: ActionDenied, SecretName: c.Name, Caller: callerTag(), Message: sanitizeBackendErr(err)})
		return err
	}
	_ = AppendAudit(AuditEvent{Action: ActionDelete, SecretName: c.Name, Caller: callerTag()})
	fmt.Fprintf(os.Stderr, "deleted %q\n", c.Name)
	return nil
}
