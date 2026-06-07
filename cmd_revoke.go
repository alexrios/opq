package main

import (
	"context"
	"errors"
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

	// Read existing policy first: it tells us whether there is anything to
	// revoke and lets us carry CreatedAt/ExpiresAt onto the tombstone.
	existing, _ := loadMeta(ctx, backend, c.Name)

	// Wipe the value (the whole point of revoke). A missing value is tolerated
	// (the name may already be a tombstone, or its value removed out of band)
	// as long as some record exists; otherwise there is nothing to revoke.
	delErr := backend.Delete(ctx, c.Name)
	valueExisted := delErr == nil
	if delErr != nil && !errors.Is(delErr, ErrSecretNotFound) {
		_ = AppendAudit(AuditEvent{Action: ActionDenied, SecretName: c.Name, Caller: callerTag(), Message: sanitizeBackendErr(delErr)})
		return fmt.Errorf("revoke %q: %w", c.Name, delErr)
	}
	if !valueExisted && existing == nil {
		_ = AppendAudit(AuditEvent{Action: ActionDenied, SecretName: c.Name, Caller: callerTag(), Message: "not_found"})
		return fmt.Errorf("revoke %q: %w", c.Name, ErrSecretNotFound)
	}

	now := time.Now().UTC()
	tomb := &SecretMeta{V: secretMetaVersion, RevokedAt: now}
	if existing != nil {
		tomb.CreatedAt = existing.CreatedAt
		tomb.ExpiresAt = existing.ExpiresAt
	}
	if err := storeMeta(ctx, backend, c.Name, tomb); err != nil {
		// The value is already wiped (security goal met); only the forensic
		// tombstone failed to persist. Surface it so the operator can retry.
		_ = AppendAudit(AuditEvent{Action: ActionDenied, SecretName: c.Name, Caller: callerTag(), Message: "revoke_tombstone_write_failed"})
		return fmt.Errorf("revoke %q: value wiped but tombstone write failed: %w", c.Name, err)
	}

	_ = AppendAudit(AuditEvent{Action: ActionRevoke, SecretName: c.Name, Caller: callerTag()})
	fmt.Fprintf(os.Stderr, "revoked %q (value wiped; tombstone retained; run `opq delete %s` to remove the record)\n", c.Name, c.Name)
	return nil
}
