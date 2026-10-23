package main

import (
	"context"
	"fmt"
	"os"
	"time"
)

type RevokeCmd struct {
	Name string `arg:"" help:"Secret name to revoke. Immediately wipes the stored value and leaves a revoked tombstone; reads are refused until the name is re-set or deleted."`
}

// Run revokes a secret: it wipes the stored value from the keyring at once and
// records a revoked tombstone so future reads report "revoked" (distinct from
// "never existed") and `list` shows the name as burned. This is the "this
// secret leaked, kill it now" tool: eager destruction, unlike a TTL (which is
// refused lazily on read) and unlike `delete` (which removes the record
// silently with no trace beyond the audit log).
func (c *RevokeCmd) Run() error {
	if !validSecretName(c.Name) {
		return fmt.Errorf("invalid secret name %q (must match [A-Za-z0-9_.-]{1,128})", c.Name)
	}

	ctx := context.Background()
	backend, err := OpenDefaultBackend()
	if err != nil {
		return err
	}

	if err := revokeSecret(ctx, backend, c.Name, time.Now().UTC()); err != nil {
		_ = AppendAudit(AuditEvent{Action: ActionDenied, SecretName: c.Name, Caller: callerTag(), Message: sanitizeBackendErr(err)})
		return fmt.Errorf("revoke %q: %w", c.Name, err)
	}

	_ = AppendAudit(AuditEvent{Action: ActionRevoke, SecretName: c.Name, Caller: callerTag()})
	fmt.Fprintf(os.Stderr, "revoked %q (value wiped; tombstone retained; run `opq delete %s` to remove the record)\n", c.Name, c.Name)
	return nil
}
