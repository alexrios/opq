package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"time"
)

type PruneCmd struct {
	DryRun         bool `name:"dry-run" help:"Show what would be pruned without deleting anything."`
	IncludeRevoked bool `name:"include-revoked" help:"Also delete revoked tombstones (normally retained as forensic records)."`
}

// Run sweeps expired secrets, wiping each lapsed value and its policy metadata.
// It is the destructive counterpart to lazy TTL enforcement: `resolveSecret`
// only refuses to RETURN an expired secret (the read path stays read-only), so
// the plaintext lingers in the keyring until `prune` (or `delete`) removes it.
//
// By default, prune targets EXPIRED secrets only and leaves REVOKED tombstones
// intact as a forensic record. Pass --include-revoked to explicitly remove
// revoked tombstones as well.
func (c *PruneCmd) Run() error {
	ctx := context.Background()
	backend, err := OpenDefaultBackend()
	if err != nil {
		return err
	}
	return c.runWith(ctx, backend, os.Stdout, os.Stderr, time.Now().UTC())
}

// pruneSecretIncludingRevoked checks and deletes an expired secret OR revoked
// tombstone under a single policy lock, preserving the concurrency guarantee
// that a concurrently re-set secret cannot be deleted using a prior
// generation's metadata.
func pruneSecretIncludingRevoked(ctx context.Context, backend Backend, name string, now time.Time, dryRun bool) (*SecretMeta, string, error) {
	unlock, err := lockPolicy(ctx, !dryRun)
	if err != nil {
		return nil, "", err
	}
	defer unlock()

	m, err := loadMeta(ctx, backend, name)
	if err != nil {
		return nil, "", err
	}
	if m != nil && m.Pending {
		return nil, "", ErrSecretUpdatePending
	}
	reason := ""
	switch {
	case m.IsRevoked():
		reason = "revoked"
	case m.IsExpiredAt(now):
		reason = "expired"
	default:
		return m, "", nil
	}
	if !dryRun {
		if err := deleteSecretLocked(ctx, backend, name); err != nil {
			return nil, "", err
		}
	}
	return m, reason, nil
}

func (c *PruneCmd) runWith(ctx context.Context, backend Backend, stdout, stderr io.Writer, now time.Time) error {
	keys, err := backend.List(ctx)
	if err != nil {
		return err
	}

	seen := map[string]bool{}
	var names []string
	add := func(n string) {
		if !seen[n] {
			seen[n] = true
			names = append(names, n)
		}
	}
	for _, k := range keys {
		if name, ok := secretNameFromMetaKey(k); ok {
			if c.IncludeRevoked {
				add(name)
			}
			continue
		}
		add(k)
	}
	sort.Strings(names)

	pruned := 0
	failed := 0
	for _, n := range names {
		var (
			m      *SecretMeta
			reason string
			perr   error
		)
		if c.IncludeRevoked {
			m, reason, perr = pruneSecretIncludingRevoked(ctx, backend, n, now, c.DryRun)
		} else {
			var expired bool
			m, expired, perr = pruneSecret(ctx, backend, n, now, c.DryRun)
			if expired {
				reason = "expired"
			}
		}
		if perr != nil {
			fmt.Fprintf(stderr, "prune %s: %v\n", n, perr)
			failed++
			continue
		}
		if reason == "" {
			continue
		}
		if c.DryRun {
			if reason == "revoked" {
				fmt.Fprintf(stdout, "would prune %s (revoked %s)\n", n, m.RevokedAt.Format(time.RFC3339))
			} else {
				fmt.Fprintf(stdout, "would prune %s (expired %s)\n", n, m.ExpiresAt.Format(time.RFC3339))
			}
			pruned++
			continue
		}

		_ = AppendAudit(AuditEvent{Action: ActionPrune, SecretName: n, Caller: callerTag()})
		fmt.Fprintf(stdout, "pruned %s\n", n)
		pruned++
	}

	verb := "pruned"
	if c.DryRun {
		verb = "would be pruned"
	}
	fmt.Fprintf(stderr, "%d secret(s) %s\n", pruned, verb)
	if failed > 0 {
		return fmt.Errorf("failed to prune %d secret(s)", failed)
	}
	return nil
}
