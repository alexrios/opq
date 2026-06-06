package main

import (
	"context"
	"errors"
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
	// A revoked name has had its value wiped but its tombstone metadata
	// survives; delete must clear that record too. Note whether any record
	// (value or tombstone) exists so deleting a tombstone-only name reports
	// success rather than a misleading not-found.
	metaExisted := false
	if m, _ := loadMeta(ctx, backend, c.Name); m != nil {
		metaExisted = true
	}

	secretErr := backend.Delete(ctx, c.Name)
	_ = deleteMeta(ctx, backend, c.Name) // best-effort: clear policy/tombstone

	if secretErr != nil {
		if errors.Is(secretErr, ErrSecretNotFound) && metaExisted {
			// Tombstone-only (revoked) name: the value was already gone and we
			// cleared the record above. Treat as a successful delete.
			_ = AppendAudit(AuditEvent{Action: ActionDelete, SecretName: c.Name, Caller: callerTag()})
			fmt.Fprintf(os.Stderr, "deleted %q\n", c.Name)
			return nil
		}
		_ = AppendAudit(AuditEvent{Action: ActionDenied, SecretName: c.Name, Caller: callerTag(), Message: sanitizeBackendErr(secretErr)})
		return secretErr
	}
	_ = AppendAudit(AuditEvent{Action: ActionDelete, SecretName: c.Name, Caller: callerTag()})
	fmt.Fprintf(os.Stderr, "deleted %q\n", c.Name)
	return nil
}
