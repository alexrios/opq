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
	ctx := context.Background()
	backend, err := OpenDefaultBackend()
	if err != nil {
		return err
	}
	if err := backend.Delete(ctx, c.Name); err != nil {
		_ = AppendAudit(AuditEvent{Action: ActionDenied, SecretName: c.Name, Caller: callerTag(), Message: err.Error()})
		return err
	}
	_ = AppendAudit(AuditEvent{Action: ActionDelete, SecretName: c.Name, Caller: callerTag()})
	fmt.Fprintf(os.Stderr, "deleted %q\n", c.Name)
	return nil
}
