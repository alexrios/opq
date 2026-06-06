package main

import (
	"context"
	"fmt"
	"os"
	"sort"
	"time"
)

type ListCmd struct{}

func (c *ListCmd) Run() error {
	ctx := context.Background()
	backend, err := OpenDefaultBackend()
	if err != nil {
		return err
	}
	keys, err := backend.List(ctx)
	if err != nil {
		return err
	}
	_ = AppendAudit(AuditEvent{Action: ActionList, Caller: callerTag()})

	// backend.List returns the raw keyspace, interleaving secret keys and
	// companion "meta/<name>" policy items. Build the display set: every real
	// secret, plus any name that exists only as a tombstone (its value was
	// wiped by `opq revoke` but the record survives).
	now := time.Now().UTC()
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
			add(name)
		} else {
			add(k)
		}
	}
	sort.Strings(names)

	for _, n := range names {
		m, err := loadMeta(ctx, backend, n)
		status := ""
		switch {
		case err != nil:
			// Don't render an unreadable/corrupt policy item as a healthy live
			// secret — that would hide a revoked/expired status from the
			// operator. resolveSecret still fails closed on the same error.
			status = "meta-error"
		case m.IsRevoked():
			status = "REVOKED"
		case m.IsExpiredAt(now):
			status = "EXPIRED"
		case m.HasExpiry():
			status = "expires " + m.ExpiresAt.Format(time.RFC3339)
		}
		if status == "" {
			fmt.Fprintln(os.Stdout, n)
		} else {
			fmt.Fprintf(os.Stdout, "%s\t%s\n", n, status)
		}
	}
	return nil
}
