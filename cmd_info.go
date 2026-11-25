package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"text/tabwriter"
	"time"

	"golang.org/x/term"
)

type InfoCmd struct {
	Name string `arg:"" help:"Secret name to inspect."`
	JSON bool   `name:"json" help:"Output secret metadata as JSON."`
}

type secretInfo struct {
	Name      string     `json:"name"`
	Backend   string     `json:"backend"`
	Status    string     `json:"status"`
	HasValue  bool       `json:"has_value"`
	CreatedAt *time.Time `json:"created_at,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
	Pending   bool       `json:"pending,omitempty"`
	MetaError string     `json:"meta_error,omitempty"`
}

// infoDeps injects external dependencies so unit tests can run without a real
// OS keyring or shared host state.
type infoDeps struct {
	openBackend func() (Backend, error)
	lockPolicy  func(ctx context.Context, exclusive bool) (func(), error)
	appendAudit func(AuditEvent) error
	now         func() time.Time
	stdout      io.Writer
	isTTY       bool
	noColor     bool
}

func defaultInfoDeps() infoDeps {
	return infoDeps{
		openBackend: OpenDefaultBackend,
		lockPolicy:  lockPolicy,
		appendAudit: AppendAudit,
		now:         func() time.Time { return time.Now().UTC() },
		stdout:      os.Stdout,
		isTTY:       term.IsTerminal(int(os.Stdout.Fd())),
		noColor:     os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb",
	}
}

func (c *InfoCmd) Run() error {
	return runInfo(context.Background(), c.Name, c.JSON, defaultInfoDeps())
}

// runInfo inspects metadata for a single secret without ever reading its
// plaintext value from the keyring. Existence is checked via backend.List and
// companion policy is read via loadMeta ("meta/<name>") under a shared policy
// lock.
func runInfo(ctx context.Context, name string, asJSON bool, deps infoDeps) error {
	if !validSecretName(name) {
		return fmt.Errorf("invalid secret name %q (must match [A-Za-z0-9_.-]{1,128})", name)
	}
	if deps.openBackend == nil {
		deps.openBackend = OpenDefaultBackend
	}
	if deps.lockPolicy == nil {
		deps.lockPolicy = lockPolicy
	}
	if deps.appendAudit == nil {
		deps.appendAudit = AppendAudit
	}
	if deps.now == nil {
		deps.now = func() time.Time { return time.Now().UTC() }
	}
	if deps.stdout == nil {
		deps.stdout = os.Stdout
	}

	backend, err := deps.openBackend()
	if err != nil {
		return err
	}

	unlock, err := deps.lockPolicy(ctx, false)
	if err != nil {
		return err
	}
	defer unlock()

	keys, err := backend.List(ctx)
	if err != nil {
		return err
	}

	mk := metaKey(name)
	var hasValue, hasMeta bool
	for _, k := range keys {
		if k == name {
			hasValue = true
		} else if k == mk {
			hasMeta = true
		}
	}
	if !hasValue && !hasMeta {
		return fmt.Errorf("secret %q not found; run 'opq list' to see stored secrets", name)
	}

	// Never call backend.Get(ctx, name). loadMeta only reads metaKey(name).
	meta, metaErr := loadMeta(ctx, backend, name)
	if !hasValue && meta == nil && metaErr == nil {
		return fmt.Errorf("secret %q not found; run 'opq list' to see stored secrets", name)
	}

	_ = deps.appendAudit(AuditEvent{Action: ActionList, SecretName: name, Caller: callerTag()})

	now := deps.now().UTC()
	info := secretInfo{
		Name:     name,
		Backend:  backend.Name(),
		HasValue: hasValue,
	}

	if meta != nil {
		info.Pending = meta.Pending
		if !meta.CreatedAt.IsZero() {
			t := meta.CreatedAt.UTC()
			info.CreatedAt = &t
		}
		if !meta.ExpiresAt.IsZero() {
			t := meta.ExpiresAt.UTC()
			info.ExpiresAt = &t
		}
		if !meta.RevokedAt.IsZero() {
			t := meta.RevokedAt.UTC()
			info.RevokedAt = &t
		}
	}

	switch {
	case metaErr != nil:
		info.Status = "meta-error"
		info.MetaError = metaErr.Error()
	case meta != nil && meta.Pending:
		info.Status = "UPDATE-PENDING"
	case meta.IsRevoked():
		info.Status = "REVOKED"
	case meta.IsExpiredAt(now):
		info.Status = "EXPIRED"
	case meta.HasExpiry():
		info.Status = "expires " + meta.ExpiresAt.UTC().Format(time.RFC3339)
	default:
		info.Status = "active"
	}

	if asJSON {
		enc := json.NewEncoder(deps.stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(info); err != nil {
			return fmt.Errorf("encode secret info: %w", err)
		}
		return nil
	}

	return infoRenderText(deps.stdout, info, now, deps.isTTY && !deps.noColor)
}

func infoRenderText(w io.Writer, info secretInfo, now time.Time, useColor bool) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	statusText := infoStyleStatus(info.Status, useColor)

	fmt.Fprintf(tw, "Name:\t%s\n", info.Name)
	fmt.Fprintf(tw, "Backend:\t%s\n", info.Backend)
	fmt.Fprintf(tw, "Status:\t%s\n", statusText)

	if info.CreatedAt != nil {
		fmt.Fprintf(tw, "Created:\t%s (%s)\n", info.CreatedAt.Format(time.RFC3339), infoFormatRelative(*info.CreatedAt, now))
	} else {
		fmt.Fprintf(tw, "Created:\t-\n")
	}

	if info.ExpiresAt != nil {
		fmt.Fprintf(tw, "Expires:\t%s (%s)\n", info.ExpiresAt.Format(time.RFC3339), infoFormatRelative(*info.ExpiresAt, now))
	} else {
		fmt.Fprintf(tw, "Expires:\tnever\n")
	}

	if info.RevokedAt != nil {
		fmt.Fprintf(tw, "Revoked:\t%s (%s)\n", info.RevokedAt.Format(time.RFC3339), infoFormatRelative(*info.RevokedAt, now))
	}

	if info.MetaError != "" {
		fmt.Fprintf(tw, "Meta error:\t%s\n", info.MetaError)
	}

	switch info.Status {
	case "UPDATE-PENDING":
		fmt.Fprintf(tw, "Hint:\tupdate incomplete; retry 'opq set %s' or run 'opq delete %s'\n", info.Name, info.Name)
	case "meta-error":
		fmt.Fprintf(tw, "Hint:\tmetadata unreadable; run 'opq delete %s' to clear it\n", info.Name)
	case "EXPIRED":
		fmt.Fprintf(tw, "Hint:\trun 'opq prune' to remove expired secrets or 'opq set %s' to rotate\n", info.Name)
	case "REVOKED":
		fmt.Fprintf(tw, "Hint:\tvalue wiped; run 'opq delete %s' to clear tombstone or 'opq set %s' to store a new value\n", info.Name, info.Name)
	}

	return tw.Flush()
}

func infoStyleStatus(status string, useColor bool) string {
	if !useColor {
		return status
	}
	switch status {
	case "active":
		return "\x1b[32m" + status + "\x1b[0m"
	case "EXPIRED", "UPDATE-PENDING":
		return "\x1b[33m" + status + "\x1b[0m"
	case "REVOKED", "meta-error":
		return "\x1b[31m" + status + "\x1b[0m"
	default:
		return status
	}
}

// infoFormatRelative formats t relative to now as "in <dur>", "<dur> ago", or "now".
func infoFormatRelative(t, now time.Time) string {
	diff := t.Sub(now)
	if diff == 0 {
		return "now"
	}
	if diff > 0 {
		return "in " + infoFormatDuration(diff)
	}
	return infoFormatDuration(-diff) + " ago"
}

// infoFormatDuration renders a positive duration in concise human-friendly
// two-unit form (e.g. "3d 5h", "4h 12m", "5m 30s", "45s", "<1s").
func infoFormatDuration(d time.Duration) string {
	if d < time.Second {
		return "<1s"
	}
	const day = 24 * time.Hour
	if d >= day {
		days := d / day
		hours := (d % day) / time.Hour
		if hours > 0 {
			return fmt.Sprintf("%dd %dh", days, hours)
		}
		return fmt.Sprintf("%dd", days)
	}
	if d >= time.Hour {
		hours := d / time.Hour
		mins := (d % time.Hour) / time.Minute
		if mins > 0 {
			return fmt.Sprintf("%dh %dm", hours, mins)
		}
		return fmt.Sprintf("%dh", hours)
	}
	if d >= time.Minute {
		mins := d / time.Minute
		secs := (d % time.Minute) / time.Second
		if secs > 0 {
			return fmt.Sprintf("%dm %ds", mins, secs)
		}
		return fmt.Sprintf("%dm", mins)
	}
	return fmt.Sprintf("%ds", d/time.Second)
}
