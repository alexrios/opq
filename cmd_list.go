package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"time"
)

type ListCmd struct {
	Long   bool   `name:"long" short:"l" help:"Show detailed metadata columns (status, created, expires/revoked). Never reads secret values."`
	JSON   bool   `name:"json" help:"Output a JSON array of secret metadata. Never includes secret values."`
	Status string `name:"status" enum:"all,active,expired,revoked,pending" default:"all" help:"Filter secrets by status: all, active, expired, revoked, or pending."`
}

// listJSONEntry is the structured JSON representation emitted by `opq list --json`.
// It carries metadata only and NEVER includes secret values.
type listJSONEntry struct {
	Name      string     `json:"name"`
	Status    string     `json:"status"`
	CreatedAt *time.Time `json:"created_at,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
	Pending   bool       `json:"pending,omitempty"`
	MetaError bool       `json:"meta_error,omitempty"`
}

type listRow struct {
	name      string
	category  string // active | expired | revoked | pending | meta-error
	rawStatus string // non-TTY default backwards-compatible status string
	meta      *SecretMeta
	metaErr   error
}

func validateListStatusFilter(status string) (string, error) {
	if status == "" {
		return "all", nil
	}
	switch status {
	case "all", "active", "expired", "revoked", "pending":
		return status, nil
	default:
		return "", fmt.Errorf("invalid --status %q (want all|active|expired|revoked|pending)", status)
	}
}

func classifyListRow(name string, m *SecretMeta, err error, now time.Time) listRow {
	row := listRow{name: name, meta: m, metaErr: err}
	switch {
	case err != nil:
		// Don't render an unreadable/corrupt policy item as a healthy live
		// secret, which would hide a revoked/expired status from the operator.
		// resolveSecret still fails closed on the same error.
		row.category = "meta-error"
		row.rawStatus = "meta-error"
	case m != nil && m.Pending:
		row.category = "pending"
		row.rawStatus = "UPDATE-PENDING"
	case m.IsRevoked():
		row.category = "revoked"
		row.rawStatus = "REVOKED"
	case m.IsExpiredAt(now):
		row.category = "expired"
		row.rawStatus = "EXPIRED"
	case m.HasExpiry():
		row.category = "active"
		row.rawStatus = "expires " + m.ExpiresAt.Format(time.RFC3339)
	default:
		row.category = "active"
		row.rawStatus = ""
	}
	return row
}

func (c *ListCmd) Run() error {
	if _, err := validateListStatusFilter(c.Status); err != nil {
		return err
	}
	ctx := context.Background()
	backend, err := OpenDefaultBackend()
	if err != nil {
		return err
	}
	if err := c.runWith(ctx, backend, os.Stdout, os.Stderr, uiIsTTY(os.Stdout), time.Now().UTC()); err != nil {
		return err
	}
	if uiIsTTY(os.Stdout) && !c.JSON {
		if n, err := legacyKeychainCount(ctx); err == nil && n > 0 {
			fmt.Fprintf(os.Stderr, "note: %d legacy macOS Keychain secret(s) not yet migrated; run 'opq migrate'\n", n)
		}
	}
	return nil
}

func (c *ListCmd) runWith(ctx context.Context, backend Backend, stdout, stderr io.Writer, stdoutIsTTY bool, now time.Time) error {
	filter, err := validateListStatusFilter(c.Status)
	if err != nil {
		return err
	}

	unlock, err := lockPolicy(ctx, false)
	if err != nil {
		return err
	}
	defer unlock()

	keys, err := backend.List(ctx)
	if err != nil {
		return err
	}
	_ = AppendAudit(AuditEvent{Action: ActionList, Caller: callerTag()})

	// backend.List returns the raw keyspace, interleaving secret keys and
	// companion "meta/<name>" policy items. Build the display set: every real
	// secret, plus any name that exists only as a tombstone (its value was
	// wiped by `opq revoke` but the record survives).
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

	allRows := make([]listRow, 0, len(names))
	filtered := make([]listRow, 0, len(names))
	for _, n := range names {
		// NEVER read the secret value itself; only companion policy metadata.
		m, merr := loadMeta(ctx, backend, n)
		row := classifyListRow(n, m, merr, now)
		allRows = append(allRows, row)
		if filter == "all" || row.category == filter {
			filtered = append(filtered, row)
		}
	}

	if c.JSON {
		items := make([]listJSONEntry, 0, len(filtered))
		for _, r := range filtered {
			item := listJSONEntry{
				Name:      r.name,
				Status:    r.category,
				MetaError: r.metaErr != nil,
			}
			if r.meta != nil {
				item.Pending = r.meta.Pending
				if !r.meta.CreatedAt.IsZero() {
					t := r.meta.CreatedAt.UTC()
					item.CreatedAt = &t
				}
				if !r.meta.ExpiresAt.IsZero() {
					t := r.meta.ExpiresAt.UTC()
					item.ExpiresAt = &t
				}
				if !r.meta.RevokedAt.IsZero() {
					t := r.meta.RevokedAt.UTC()
					item.RevokedAt = &t
				}
			}
			items = append(items, item)
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(items)
	}

	if c.Long {
		if len(filtered) == 0 {
			if stdoutIsTTY {
				writeListEmptyHint(stderr, filter, len(allRows))
			}
			return nil
		}
		styler := newUIStyler(stdoutIsTTY)
		tableRows := make([][]uiCell, 0, len(filtered))
		for _, r := range filtered {
			statusText, statusStyle := listLongStatusCell(r, styler)
			created := "-"
			if r.meta != nil && !r.meta.CreatedAt.IsZero() {
				created = uiFormatUTC(r.meta.CreatedAt)
			}
			detail := listLongExpiryCell(r, now)
			tableRows = append(tableRows, []uiCell{
				{text: r.name},
				{text: statusText, style: statusStyle},
				{text: created},
				{text: detail},
			})
		}
		return uiRenderTable(stdout, []string{"NAME", "STATUS", "CREATED", "EXPIRES / REVOKED"}, styler.dim, tableRows)
	}

	// Default non-TTY mode: preserve exact `<name>` / `<name>\t<status>` format
	// so existing scripts, shell completions, and tests stay 100% compatible.
	if !stdoutIsTTY {
		for _, r := range filtered {
			if r.rawStatus == "" {
				fmt.Fprintln(stdout, r.name)
			} else {
				fmt.Fprintf(stdout, "%s\t%s\n", r.name, r.rawStatus)
			}
		}
		return nil
	}

	// Default TTY mode: aligned columns with relative expiry and subtle ANSI emphasis.
	if len(filtered) == 0 {
		writeListEmptyHint(stderr, filter, len(allRows))
		return nil
	}
	styler := newUIStyler(true)
	tableRows := make([][]uiCell, 0, len(filtered))
	for _, r := range filtered {
		statusCell := listTTYStatusCell(r, now, styler)
		tableRows = append(tableRows, []uiCell{
			{text: r.name},
			statusCell,
		})
	}
	return uiRenderTable(stdout, nil, nil, tableRows)
}

func writeListEmptyHint(stderr io.Writer, filter string, total int) {
	if total == 0 {
		fmt.Fprintln(stderr, "no secrets stored; run 'opq set <name>' to store one")
		return
	}
	fmt.Fprintf(stderr, "no secrets with status %q (%d total; run 'opq list' to see all)\n", filter, total)
}

func listTTYStatusCell(r listRow, now time.Time, styler uiStyler) uiCell {
	switch r.category {
	case "meta-error":
		return uiCell{text: "meta-error", style: styler.boldRed}
	case "pending":
		return uiCell{text: "UPDATE-PENDING", style: styler.yellow}
	case "revoked":
		return uiCell{text: "REVOKED", style: styler.red}
	case "expired":
		return uiCell{text: "EXPIRED", style: styler.yellow}
	default:
		if r.meta.HasExpiry() {
			return uiCell{text: uiFormatExpiry(r.meta.ExpiresAt, now)}
		}
		return uiCell{text: ""}
	}
}

func listLongStatusCell(r listRow, styler uiStyler) (string, func(string) string) {
	switch r.category {
	case "meta-error":
		return "meta-error", styler.boldRed
	case "pending":
		return "UPDATE-PENDING", styler.yellow
	case "revoked":
		return "REVOKED", styler.red
	case "expired":
		return "EXPIRED", styler.yellow
	default:
		return "active", styler.green
	}
}

func listLongExpiryCell(r listRow, now time.Time) string {
	switch r.category {
	case "meta-error":
		return "metadata unreadable"
	case "pending":
		return "incomplete update (retry set or delete)"
	case "revoked":
		if r.meta != nil && !r.meta.RevokedAt.IsZero() {
			return "revoked " + uiFormatUTC(r.meta.RevokedAt)
		}
		return "revoked"
	case "expired":
		if r.meta.HasExpiry() {
			return uiFormatExpiry(r.meta.ExpiresAt, now)
		}
		return "expired"
	default:
		if r.meta.HasExpiry() {
			return uiFormatExpiry(r.meta.ExpiresAt, now)
		}
		return "-"
	}
}
