package main

import (
	"context"
	"fmt"
	"os"
	"sort"
	"time"
)

type PruneCmd struct {
	DryRun bool `name:"dry-run" help:"Show what would be pruned without deleting anything."`
}

// Run sweeps expired secrets, wiping each lapsed value and its policy metadata.
// It is the destructive counterpart to lazy TTL enforcement: `resolveSecret`
// only refuses to RETURN an expired secret (the read path stays read-only), so
// the plaintext lingers in the keyring until `prune` (or `delete`) removes it.
//
// Prune targets EXPIRED secrets only. Revoked tombstones are deliberately left
// alone: they are an intentional forensic record and are cleared with
// `opq delete`. (A revoked secret's value is already gone, so it never appears
// as a live key here anyway.)
func (c *PruneCmd) Run() error {
	ctx := context.Background()
	backend, err := OpenDefaultBackend()
	if err != nil {
		return err
	}
	keys, err := backend.List(ctx)
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	seen := map[string]bool{}
	var names []string
	for _, k := range keys {
		if isMetaKey(k) {
			continue
		}
		if !seen[k] {
			seen[k] = true
			names = append(names, k)
		}
	}
	sort.Strings(names)

	pruned := 0
	for _, n := range names {
		m, err := loadMeta(ctx, backend, n)
		if err != nil {
			// Don't silently skip a secret whose policy we couldn't read; the
			// operator relies on prune to clear lapsed values, so make the gap
			// visible rather than reporting a clean sweep that missed one.
			fmt.Fprintf(os.Stderr, "prune %s: cannot read policy, skipped: %v\n", n, err)
			continue
		}
		if !m.IsExpiredAt(now) {
			continue
		}
		if c.DryRun {
			fmt.Fprintf(os.Stdout, "would prune %s (expired %s)\n", n, m.ExpiresAt.Format(time.RFC3339))
			pruned++
			continue
		}
		if err := backend.Delete(ctx, n); err != nil {
			fmt.Fprintf(os.Stderr, "prune %s: %v\n", n, err)
			continue
		}
		_ = deleteMeta(ctx, backend, n)
		_ = AppendAudit(AuditEvent{Action: ActionPrune, SecretName: n, Caller: callerTag()})
		fmt.Fprintf(os.Stdout, "pruned %s\n", n)
		pruned++
	}

	verb := "pruned"
	if c.DryRun {
		verb = "would be pruned"
	}
	fmt.Fprintf(os.Stderr, "%d secret(s) %s\n", pruned, verb)
	return nil
}
