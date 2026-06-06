package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sync/atomic"
	"time"

	"github.com/awnumar/memguard"
	"golang.org/x/term"
)

type SetCmd struct {
	Name string `arg:"" help:"Secret name (e.g. openai_api_key)."`
	TTL  string `name:"ttl" help:"Optional time-to-live after which reads are refused (e.g. 24h, 90m, 7d, 2w). Omit for no expiry."`
}

// maxSecretSize bounds the buffer we read for a single secret. Generous for
// API tokens and certs; rejects accidental piping of large files.
const maxSecretSize = 64 * 1024

// Bracketed-paste sequences: shells wrap a paste in ESC[200~ … ESC[201~, and
// term.ReadPassword's raw mode doesn't strip them, so they'd corrupt the value.
// We disable the mode during the read and strip any markers defensively.
const (
	bracketedPasteDisable = "\x1b[?2004l"
	bracketedPasteEnable  = "\x1b[?2004h"
	bracketedPasteStart   = "\x1b[200~"
	bracketedPasteEnd     = "\x1b[201~"
)

// stripBytesInPlace removes every occurrence of sep from b, compacting the
// surviving bytes toward the front, and returns the compacted prefix. It does
// not allocate (so no extra heap copy of the secret is made); bytes past the
// returned length are stale residue the caller must wipe.
func stripBytesInPlace(b, sep []byte) []byte {
	if len(sep) == 0 {
		return b
	}
	w := 0
	for i := 0; i < len(b); {
		if i+len(sep) <= len(b) && bytes.Equal(b[i:i+len(sep)], sep) {
			i += len(sep)
			continue
		}
		b[w] = b[i]
		w++
		i++
	}
	return b[:w]
}

// sanitizePastedSecret strips bracketed-paste markers that survived raw-mode
// reading, then trims surrounding whitespace a paste often carries. Works in
// place on raw's backing array. Only the interactive path trims; the piped path
// stores bytes verbatim, so a value needing surrounding whitespace must come via
// stdin.
func sanitizePastedSecret(raw []byte) []byte {
	b := stripBytesInPlace(raw, []byte(bracketedPasteStart))
	b = stripBytesInPlace(b, []byte(bracketedPasteEnd))
	return bytes.TrimSpace(b)
}

func (c *SetCmd) Run() error {
	if !validSecretName(c.Name) {
		return fmt.Errorf("invalid secret name %q (must match [A-Za-z0-9_.-]{1,128})", c.Name)
	}

	// Validate the TTL up front so a bad value fails before we prompt for or
	// store anything.
	var ttl time.Duration
	if c.TTL != "" {
		d, err := parseTTL(c.TTL)
		if err != nil {
			return err
		}
		ttl = d
	}

	ctx := context.Background()
	backend, err := OpenDefaultBackend()
	if err != nil {
		return err
	}

	var value *Buffer
	stdinFd := int(os.Stdin.Fd())
	if term.IsTerminal(stdinFd) {
		// Disable bracketed-paste while reading (only when stderr is the
		// terminal); restore after.
		if term.IsTerminal(int(os.Stderr.Fd())) {
			fmt.Fprint(os.Stderr, bracketedPasteDisable)
			defer fmt.Fprint(os.Stderr, bracketedPasteEnable)
		}
		fmt.Fprintf(os.Stderr, "Enter value for %q (input hidden): ", c.Name)
		raw, err := term.ReadPassword(stdinFd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return fmt.Errorf("read password: %w", err)
		}
		cleaned := sanitizePastedSecret(raw)
		if len(cleaned) == 0 {
			memguard.WipeBytes(raw)
			return errors.New("empty secret value")
		}
		// NewBufferFromBytes wipes cleaned (a subslice of raw); WipeBytes(raw)
		// then clears any residue left by stripping/trimming.
		value, err = NewBufferFromBytes(cleaned)
		memguard.WipeBytes(raw)
		if err != nil {
			return fmt.Errorf("buffer: %w", err)
		}
	} else {
		value, err = NewBufferFromReader(io.LimitReader(os.Stdin, maxSecretSize+1))
		if err != nil {
			return fmt.Errorf("read stdin: %w", err)
		}
		if value.Size() > maxSecretSize {
			value.Destroy()
			return fmt.Errorf("secret too large (>%d bytes)", maxSecretSize)
		}
	}
	defer value.Destroy()

	if err := backend.Set(ctx, c.Name, value); err != nil {
		_ = AppendAudit(AuditEvent{Action: ActionDenied, SecretName: c.Name, Caller: callerTag(), Message: sanitizeBackendErr(err)})
		return err
	}

	// Reconcile policy metadata. A plain secret carries NO companion item; a
	// TTL'd secret gets one. Either way the prior policy for this name is
	// cleared — in particular a revoked tombstone — so re-storing a revoked
	// secret makes it usable again.
	now := time.Now().UTC()
	var expiresAt time.Time
	if ttl > 0 {
		expiresAt = now.Add(ttl)
		meta := &SecretMeta{V: secretMetaVersion, CreatedAt: now, ExpiresAt: expiresAt}
		if err := storeMeta(ctx, backend, c.Name, meta); err != nil {
			// Fail closed: never leave a secret whose requested TTL was not
			// recorded (it would be usable forever). Roll back the value — and
			// if the rollback ALSO fails, say so loudly, because a no-TTL value
			// is now live in the keyring and the operator must remove it.
			rbErr := backend.Delete(ctx, c.Name)
			_ = AppendAudit(AuditEvent{Action: ActionDenied, SecretName: c.Name, Caller: callerTag(), Message: "ttl_write_failed"})
			if rbErr != nil && !errors.Is(rbErr, ErrSecretNotFound) {
				return fmt.Errorf("set %q: failed to record TTL AND failed to roll back the stored value (%v); the secret is present WITHOUT a TTL — run `opq delete %s`: %w", c.Name, rbErr, c.Name, err)
			}
			return fmt.Errorf("set %q: failed to record TTL; secret rolled back: %w", c.Name, err)
		}
	} else if err := deleteMeta(ctx, backend, c.Name); err != nil {
		// The value is stored, but a stale tombstone may survive and wrongly
		// refuse it as revoked. Surface so the operator can retry.
		_ = AppendAudit(AuditEvent{Action: ActionDenied, SecretName: c.Name, Caller: callerTag(), Message: "meta_clear_failed"})
		return fmt.Errorf("set %q: secret stored but prior policy could not be cleared (it may still be refused); retry: %w", c.Name, err)
	}

	auditMsg := ""
	if ttl > 0 {
		auditMsg = "expires_at=" + expiresAt.Format(time.RFC3339)
	}
	_ = AppendAudit(AuditEvent{Action: ActionSet, SecretName: c.Name, Caller: callerTag(), Message: auditMsg})
	fmt.Fprintf(os.Stderr, "stored %q in %s", c.Name, backend.Name())
	if ttl > 0 {
		fmt.Fprintf(os.Stderr, " (expires %s)", expiresAt.Format(time.RFC3339))
	}
	fmt.Fprintln(os.Stderr)
	return nil
}

// callerTag returns a short label describing the invoking context. Refined
// in MCP mode via SetCallerTag. Backed by atomic.Pointer[string] so the MCP
// server (which spawns goroutines for tool handlers) can safely re-tag from
// any goroutine without racing readers in other handlers.
var currentCallerTag atomic.Pointer[string]

func init() {
	def := "cli"
	currentCallerTag.Store(&def)
}

func callerTag() string {
	if p := currentCallerTag.Load(); p != nil {
		return *p
	}
	return "cli"
}

// SetCallerTag overrides the tag used in audit entries for this process.
func SetCallerTag(tag string) { currentCallerTag.Store(&tag) }
