package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
)

type MigrateCmd struct {
	Names        []string `arg:"" optional:"" help:"Optional secret names to migrate selectively. Omit to migrate all legacy Keychain secrets."`
	DryRun       bool     `name:"dry-run" help:"Preview legacy Keychain secrets that would be migrated without reading secret values or modifying storage."`
	Overwrite    bool     `name:"overwrite" help:"Overwrite secrets that already exist in the encrypted vault."`
	DeleteLegacy bool     `name:"delete-legacy" help:"Remove each migrated secret (and its metadata) from the legacy macOS Keychain after verifying it is stored in the encrypted vault."`
}

type migrateDeps struct {
	lockPolicy  func(ctx context.Context, exclusive bool) (func(), error)
	appendAudit func(AuditEvent) error
}

func defaultMigrateDeps() migrateDeps {
	return migrateDeps{
		lockPolicy:  lockPolicy,
		appendAudit: AppendAudit,
	}
}

type migrateOutcome int

const (
	migrateCopied migrateOutcome = iota
	migrateSkipped
	migrateCleanedLegacy
)

func (c *MigrateCmd) runWith(
	ctx context.Context,
	legacy Backend,
	vault Backend,
	stdout io.Writer,
	stderr io.Writer,
	deps migrateDeps,
) error {
	if deps.lockPolicy == nil {
		deps.lockPolicy = lockPolicy
	}
	if deps.appendAudit == nil {
		deps.appendAudit = AppendAudit
	}

	legacyKeys, err := legacy.List(ctx)
	if err != nil {
		return fmt.Errorf("list legacy secrets: %w", err)
	}
	allLegacyNames := collectLogicalSecretNames(legacyKeys)

	var names []string
	var missingRequested int
	if len(c.Names) > 0 {
		seen := make(map[string]bool, len(c.Names))
		legacyNameSet := make(map[string]bool, len(allLegacyNames))
		for _, n := range allLegacyNames {
			legacyNameSet[n] = true
		}
		for _, req := range c.Names {
			if !validSecretName(req) {
				return fmt.Errorf("invalid secret name %q (must match [A-Za-z0-9_.-]{1,128})", req)
			}
			if seen[req] {
				continue
			}
			seen[req] = true
			if !legacyNameSet[req] {
				fmt.Fprintf(stderr, "migrate %s: not found in legacy Keychain\n", req)
				missingRequested++
				continue
			}
			names = append(names, req)
		}
		if len(names) == 0 && missingRequested > 0 {
			return fmt.Errorf("failed to migrate %d secret(s)", missingRequested)
		}
	} else {
		names = allLegacyNames
		if len(names) == 0 {
			fmt.Fprintln(stderr, "no legacy Keychain secrets found; nothing to migrate")
			return nil
		}
	}

	vaultKeys, err := vault.List(ctx)
	if err != nil {
		return fmt.Errorf("list vault secrets: %w", err)
	}

	legacySet := make(map[string]bool, len(legacyKeys))
	for _, k := range legacyKeys {
		legacySet[k] = true
	}
	vaultSet := make(map[string]bool, len(vaultKeys))
	for _, k := range vaultKeys {
		vaultSet[k] = true
	}

	var migrated, skipped, deletedLegacy, failed int
	failed = missingRequested
	for _, name := range names {
		if !validSecretName(name) {
			fmt.Fprintf(stderr, "migrate %s: skipping invalid secret name\n", name)
			skipped++
			continue
		}

		mk := metaKey(name)
		hasVal := legacySet[name]
		hasMeta := legacySet[mk]
		inVault := vaultSet[name] || vaultSet[mk]

		kind := "value"
		switch {
		case hasVal && hasMeta:
			kind = "value + policy"
		case !hasVal && hasMeta:
			kind = "policy/revoked record"
		}

		if c.DryRun {
			switch {
			case inVault && !c.Overwrite:
				if c.DeleteLegacy {
					fmt.Fprintf(stdout, "would remove legacy %s (already in vault)\n", name)
					deletedLegacy++
				} else {
					fmt.Fprintf(stdout, "would skip %s (already in vault; pass --overwrite to replace)\n", name)
				}
				skipped++
			case inVault && c.Overwrite:
				fmt.Fprintf(stdout, "would overwrite %s (%s)\n", name, kind)
				migrated++
				if c.DeleteLegacy {
					deletedLegacy++
				}
			default:
				fmt.Fprintf(stdout, "would migrate %s (%s)\n", name, kind)
				migrated++
				if c.DeleteLegacy {
					deletedLegacy++
				}
			}
			continue
		}

		outcome, err := c.migrateOne(ctx, legacy, vault, name, hasVal, hasMeta, deps)
		if err != nil {
			fmt.Fprintf(stderr, "migrate %s: %v\n", name, err)
			failed++
			continue
		}

		switch outcome {
		case migrateCleanedLegacy:
			fmt.Fprintf(stdout, "cleaned legacy %s (already in vault)\n", name)
			deletedLegacy++
			skipped++
		case migrateSkipped:
			fmt.Fprintf(stdout, "skipped %s (already in vault)\n", name)
			skipped++
		case migrateCopied:
			if c.DeleteLegacy {
				fmt.Fprintf(stdout, "migrated %s (%s; removed legacy copy)\n", name, kind)
				deletedLegacy++
			} else {
				fmt.Fprintf(stdout, "migrated %s (%s)\n", name, kind)
			}
			migrated++
		}
	}

	if c.DryRun {
		fmt.Fprintf(stderr, "%d secret(s) would be migrated, %d skipped", migrated, skipped)
		if c.DeleteLegacy {
			fmt.Fprintf(stderr, ", %d legacy Keychain item(s) would be removed", deletedLegacy)
		}
		fmt.Fprintln(stderr)
		return nil
	}

	fmt.Fprintf(stderr, "migrated %d secret(s) to %s (%d skipped", migrated, vault.Name(), skipped)
	if c.DeleteLegacy {
		fmt.Fprintf(stderr, ", %d legacy removed", deletedLegacy)
	}
	fmt.Fprintln(stderr, ")")
	if !c.DeleteLegacy && (migrated > 0 || skipped > 0) && failed == 0 {
		fmt.Fprintln(stderr, "verify with 'opq list' and 'opq doctor', then run 'opq migrate --delete-legacy' to remove legacy Keychain items")
	}
	if failed > 0 {
		return fmt.Errorf("failed to migrate %d secret(s)", failed)
	}
	return nil
}

// migrateOne transfers a single secret and its companion policy metadata under
// the exclusive policy lock, preserving TTL, revocation tombstones, and pending
// markers atomically. Never prints or logs secret values.
func (c *MigrateCmd) migrateOne(
	ctx context.Context,
	legacy Backend,
	vault Backend,
	name string,
	hasVal bool,
	hasMeta bool,
	deps migrateDeps,
) (migrateOutcome, error) {
	unlock, err := deps.lockPolicy(ctx, true)
	if err != nil {
		return migrateSkipped, err
	}
	defer unlock()

	// Re-check vault presence under the exclusive lock to stay consistent with
	// concurrent writers.
	currentVaultKeys, err := vault.List(ctx)
	if err != nil {
		return migrateSkipped, fmt.Errorf("inspect vault: %w", err)
	}
	mk := metaKey(name)
	inVaultNow := slices.Contains(currentVaultKeys, name) || slices.Contains(currentVaultKeys, mk)
	if inVaultNow && !c.Overwrite {
		if !c.DeleteLegacy {
			return migrateSkipped, nil
		}
		if err := deleteLegacyEntry(ctx, legacy, name, hasVal, hasMeta); err != nil {
			return migrateSkipped, fmt.Errorf("remove legacy copy: %w", err)
		}
		_ = deps.appendAudit(AuditEvent{Action: ActionMigrate, SecretName: name, Caller: callerTag(), Message: "deleted_legacy"})
		return migrateCleanedLegacy, nil
	}

	if err := copySecretFromLegacyLocked(ctx, legacy, vault, name, hasVal, hasMeta); err != nil {
		return migrateSkipped, err
	}

	auditMsg := "migrated"
	if c.DeleteLegacy {
		if err := deleteLegacyEntry(ctx, legacy, name, hasVal, hasMeta); err != nil {
			_ = deps.appendAudit(AuditEvent{Action: ActionMigrate, SecretName: name, Caller: callerTag(), Message: auditMsg})
			return migrateCopied, fmt.Errorf("migrated to vault, but failed to delete legacy copy: %w", err)
		}
		auditMsg = "migrated_deleted_legacy"
	}
	_ = deps.appendAudit(AuditEvent{Action: ActionMigrate, SecretName: name, Caller: callerTag(), Message: auditMsg})
	return migrateCopied, nil
}

// copySecretFromLegacyLocked transfers a single secret (value and/or companion
// meta/<name>) from legacy into vault using the crash-safe pending-update
// protocol. Caller MUST hold exclusive policy.lock. Never prints or logs values.
func copySecretFromLegacyLocked(
	ctx context.Context,
	legacy Backend,
	vault Backend,
	name string,
	hasVal bool,
	hasMeta bool,
) error {
	mk := metaKey(name)

	var metaBuf *Buffer
	if hasMeta {
		var err error
		metaBuf, err = legacy.Get(ctx, mk)
		if err != nil && !errors.Is(err, ErrSecretNotFound) {
			return fmt.Errorf("read legacy metadata: %w", err)
		}
		if metaBuf != nil {
			defer metaBuf.Destroy()
		}
	}

	var valBuf *Buffer
	if hasVal {
		var err error
		valBuf, err = legacy.Get(ctx, name)
		if err != nil && !errors.Is(err, ErrSecretNotFound) {
			return fmt.Errorf("read legacy secret: %w", err)
		}
		if valBuf != nil {
			defer valBuf.Destroy()
		}
	}

	if valBuf == nil && metaBuf == nil {
		return ErrSecretNotFound
	}

	if valBuf != nil {
		// Mirror storeSecret's crash-safe pending-update protocol: mark pending
		// before writing value, then commit the exact legacy metadata (or clear
		// metadata for a plain secret).
		if err := storeMeta(ctx, vault, name, &SecretMeta{V: secretMetaVersion, Pending: true}); err != nil {
			return fmt.Errorf("prepare vault update: %w", err)
		}
		if err := vault.Set(ctx, name, valBuf); err != nil {
			return fmt.Errorf("write secret to vault: %w", err)
		}
		if metaBuf != nil {
			if err := vault.Set(ctx, mk, metaBuf); err != nil {
				return fmt.Errorf("write metadata to vault: %w", err)
			}
		} else {
			if err := deleteMeta(ctx, vault, name); err != nil {
				return fmt.Errorf("clear stale metadata in vault: %w", err)
			}
		}
		return nil
	}

	// Meta-only record (e.g. REVOKED tombstone or UPDATE-PENDING without value):
	// remove any prior value in vault before writing the tombstone.
	if derr := vault.Delete(ctx, name); derr != nil && !errors.Is(derr, ErrSecretNotFound) {
		return fmt.Errorf("clear prior value in vault: %w", derr)
	}
	if err := vault.Set(ctx, mk, metaBuf); err != nil {
		return fmt.Errorf("write metadata to vault: %w", err)
	}
	return nil
}

func deleteLegacyEntry(ctx context.Context, legacy Backend, name string, hasVal, hasMeta bool) error {
	if hasVal {
		if err := legacy.Delete(ctx, name); err != nil && !errors.Is(err, ErrSecretNotFound) {
			return err
		}
	}
	if hasMeta {
		if err := legacy.Delete(ctx, metaKey(name)); err != nil && !errors.Is(err, ErrSecretNotFound) {
			return err
		}
	}
	return nil
}
