package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"sync/atomic"
	"time"

	"github.com/awnumar/memguard"
	"golang.org/x/term"
)

type SetCmd struct {
	Name      string `arg:"" help:"Secret name (e.g. openai_api_key)."`
	TTL       string `name:"ttl" help:"Optional time-to-live after which reads are refused (e.g. 24h, 90m, 7d, 2w). Omit for no expiry."`
	KeepTTL   bool   `name:"keep-ttl" help:"Preserve the existing unexpired expiry timestamp when updating a secret. Cannot be combined with --ttl."`
	NoClobber bool   `name:"no-clobber" help:"Refuse to overwrite an existing live secret."`
	Trim      bool   `name:"trim" help:"Strip trailing newlines (\\r\\n and \\n) from piped stdin before storing."`
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

// trailingNewlineWarning is emitted on stderr when piped stdin ends in \n or
// \r\n and --trim was not passed, catching the common `echo ... | opq set`
// pitfall while still preserving verbatim storage by default.
const trailingNewlineWarning = "warning: stored value ends with a newline; use printf instead of echo or pass --trim"

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
// stores bytes verbatim unless --trim is passed, so a value needing surrounding
// whitespace must come via stdin.
func sanitizePastedSecret(raw []byte) []byte {
	b := stripBytesInPlace(raw, []byte(bracketedPasteStart))
	b = stripBytesInPlace(b, []byte(bracketedPasteEnd))
	return bytes.TrimSpace(b)
}

// trimTrailingNewlines strips trailing \r\n and \n line endings without
// touching other whitespace or interior newlines.
func trimTrailingNewlines(b []byte) []byte {
	for len(b) > 0 {
		if bytes.HasSuffix(b, []byte("\r\n")) {
			b = b[:len(b)-2]
		} else if b[len(b)-1] == '\n' {
			b = b[:len(b)-1]
		} else {
			break
		}
	}
	return b
}

// existingSecretState captures a secret's current presence and policy metadata
// WITHOUT ever reading the plaintext secret value.
type existingSecretState struct {
	hasKey  bool
	meta    *SecretMeta
	metaErr error
}

func (s existingSecretState) isLiveAt(now time.Time) bool {
	if !s.hasKey || s.metaErr != nil {
		return false
	}
	if s.meta == nil {
		return true
	}
	return !s.meta.Pending && !s.meta.IsRevoked() && !s.meta.IsExpiredAt(now)
}

// inspectExistingSecret checks key presence (via List) and companion metadata
// (via loadMeta) under a shared policy lock. It NEVER calls backend.Get on the
// secret key itself.
func inspectExistingSecret(ctx context.Context, backend Backend, name string) (existingSecretState, error) {
	unlock, err := lockPolicy(ctx, false)
	if err != nil {
		return existingSecretState{}, err
	}
	defer unlock()

	keys, err := backend.List(ctx)
	if err != nil {
		return existingSecretState{}, err
	}
	hasKey := slices.Contains(keys, name)
	meta, metaErr := loadMeta(ctx, backend, name)
	return existingSecretState{
		hasKey:  hasKey,
		meta:    meta,
		metaErr: metaErr,
	}, nil
}

func (c *SetCmd) validateFlags() (time.Duration, error) {
	if !validSecretName(c.Name) {
		return 0, fmt.Errorf("invalid secret name %q (must match [A-Za-z0-9_.-]{1,128})", c.Name)
	}
	if c.TTL != "" && c.KeepTTL {
		return 0, errors.New("--keep-ttl cannot be combined with --ttl")
	}
	if c.TTL != "" {
		d, err := parseTTL(c.TTL)
		if err != nil {
			return 0, err
		}
		return d, nil
	}
	return 0, nil
}

func checkSetPreconditions(name string, existing existingSecretState, now time.Time, noClobber, keepTTL bool) (time.Time, error) {
	if noClobber {
		if existing.hasKey && existing.metaErr != nil {
			return time.Time{}, fmt.Errorf("secret %q already exists with unreadable metadata; refusing --no-clobber (run 'opq delete %s' to clear)", name, name)
		}
		if existing.isLiveAt(now) {
			return time.Time{}, fmt.Errorf("secret %q already exists (omit --no-clobber to overwrite)", name)
		}
	}
	if keepTTL {
		if existing.metaErr != nil {
			return time.Time{}, fmt.Errorf("cannot use --keep-ttl: unreadable metadata for %q: %w", name, existing.metaErr)
		}
		if existing.meta != nil && existing.meta.Pending {
			return time.Time{}, fmt.Errorf("cannot use --keep-ttl: secret %q has an incomplete update (UPDATE-PENDING)", name)
		}
		if existing.meta.IsRevoked() {
			return time.Time{}, fmt.Errorf("cannot use --keep-ttl: secret %q is revoked; pass --ttl to set a new TTL", name)
		}
		if !existing.hasKey {
			return time.Time{}, fmt.Errorf("cannot use --keep-ttl: secret %q does not exist", name)
		}
		if !existing.meta.HasExpiry() {
			return time.Time{}, fmt.Errorf("cannot use --keep-ttl: secret %q has no active TTL", name)
		}
		if existing.meta.IsExpiredAt(now) {
			return time.Time{}, fmt.Errorf("cannot use --keep-ttl: secret %q has already expired (%s); pass --ttl to set a new TTL", name, uiFormatUTC(existing.meta.ExpiresAt))
		}
		return existing.meta.ExpiresAt, nil
	}
	return time.Time{}, nil
}

func printSetExistingNote(stderr io.Writer, name string, existing existingSecretState, now time.Time, ttl time.Duration, keepTTL bool) {
	switch {
	case existing.metaErr != nil:
		fmt.Fprintf(stderr, "note: secret %q has unreadable metadata; storing will replace it\n", name)
	case existing.meta != nil && existing.meta.Pending:
		fmt.Fprintf(stderr, "note: recovering %q from incomplete update (UPDATE-PENDING)\n", name)
	case existing.meta.IsRevoked():
		fmt.Fprintf(stderr, "note: reviving previously REVOKED secret %q\n", name)
	case existing.meta.IsExpiredAt(now):
		fmt.Fprintf(stderr, "note: replacing EXPIRED secret %q (expired %s)\n", name, uiFormatUTC(existing.meta.ExpiresAt))
	case existing.hasKey && existing.meta.HasExpiry():
		exp := uiFormatUTC(existing.meta.ExpiresAt)
		switch {
		case keepTTL:
			fmt.Fprintf(stderr, "note: overwriting existing secret %q (preserving expiry %s)\n", name, exp)
		case ttl > 0:
			fmt.Fprintf(stderr, "note: overwriting existing secret %q (replacing TTL that expires %s)\n", name, exp)
		default:
			fmt.Fprintf(stderr, "note: overwriting existing secret %q (clearing existing TTL that expires %s; pass --keep-ttl to preserve it)\n", name, exp)
		}
	case existing.hasKey:
		if ttl > 0 {
			fmt.Fprintf(stderr, "note: overwriting existing secret %q (adding TTL)\n", name)
		} else {
			fmt.Fprintf(stderr, "note: overwriting existing secret %q\n", name)
		}
	}
}

func (c *SetCmd) Run() error {
	// Validate name and flags up front so bad arguments fail before opening
	// the keyring or prompting for anything.
	if _, err := c.validateFlags(); err != nil {
		return err
	}

	ctx := context.Background()
	backend, err := OpenDefaultBackend()
	if err != nil {
		return err
	}

	stdinFd := int(os.Stdin.Fd())
	stdinIsTTY := term.IsTerminal(stdinFd)
	stderrIsTTY := term.IsTerminal(int(os.Stderr.Fd()))
	readPassword := func() ([]byte, error) {
		return term.ReadPassword(stdinFd)
	}
	return c.runWith(ctx, backend, os.Stdin, stdinIsTTY, os.Stderr, stderrIsTTY, readPassword, time.Now)
}

func (c *SetCmd) runWith(
	ctx context.Context,
	backend Backend,
	stdin io.Reader,
	stdinIsTTY bool,
	stderr io.Writer,
	stderrIsTTY bool,
	readPassword func() ([]byte, error),
	nowFn func() time.Time,
) error {
	ttl, err := c.validateFlags()
	if err != nil {
		return err
	}

	existing, err := inspectExistingSecret(ctx, backend, c.Name)
	if err != nil {
		return err
	}

	checkNow := nowFn().UTC()
	keptExpiresAt, err := checkSetPreconditions(c.Name, existing, checkNow, c.NoClobber, c.KeepTTL)
	if err != nil {
		return err
	}

	// Show overwrite / TTL / revive notices before prompting in interactive mode
	// and before storing in piped mode.
	printSetExistingNote(stderr, c.Name, existing, checkNow, ttl, c.KeepTTL)

	var value *Buffer
	var warnTrailingNewline bool
	if stdinIsTTY {
		// Disable bracketed-paste while reading (only when stderr is the
		// terminal); restore after.
		if stderrIsTTY {
			fmt.Fprint(stderr, bracketedPasteDisable)
			defer fmt.Fprint(stderr, bracketedPasteEnable)
		}
		fmt.Fprintf(stderr, "Enter value for %q (input hidden): ", c.Name)
		raw, err := readPassword()
		fmt.Fprintln(stderr)
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
		value, err = NewBufferFromReader(io.LimitReader(stdin, maxSecretSize+1))
		if err != nil {
			return fmt.Errorf("read stdin: %w", err)
		}
		if value.Size() > maxSecretSize {
			value.Destroy()
			return fmt.Errorf("secret too large (>%d bytes)", maxSecretSize)
		}
		rawBytes := value.Bytes()
		hasTrailingNewline := len(rawBytes) > 0 && rawBytes[len(rawBytes)-1] == '\n'
		if c.Trim {
			trimmed := trimTrailingNewlines(rawBytes)
			if len(trimmed) == 0 {
				value.Destroy()
				return errors.New("empty secret value")
			}
			if len(trimmed) < len(rawBytes) {
				cp := make([]byte, len(trimmed))
				copy(cp, trimmed)
				// NewBufferFromBytes moves cp into a locked buffer and wipes cp.
				newBuf, berr := NewBufferFromBytes(cp)
				memguard.WipeBytes(cp)
				value.Destroy()
				if berr != nil {
					return fmt.Errorf("buffer: %w", berr)
				}
				value = newBuf
			}
		} else if hasTrailingNewline {
			warnTrailingNewline = true
		}
	}
	defer value.Destroy()

	now := nowFn().UTC()
	if stdinIsTTY && (c.NoClobber || c.KeepTTL) {
		// Re-check preconditions after an interactive prompt in case the secret
		// was created or its TTL lapsed while waiting for user input.
		latest, err := inspectExistingSecret(ctx, backend, c.Name)
		if err != nil {
			return err
		}
		keptExpiresAt, err = checkSetPreconditions(c.Name, latest, now, c.NoClobber, c.KeepTTL)
		if err != nil {
			return err
		}
	}

	var expiresAt time.Time
	var meta *SecretMeta
	switch {
	case c.KeepTTL:
		if !now.Before(keptExpiresAt) {
			return fmt.Errorf("cannot use --keep-ttl: secret %q has already expired (%s); pass --ttl to set a new TTL", c.Name, uiFormatUTC(keptExpiresAt))
		}
		expiresAt = keptExpiresAt
		meta = &SecretMeta{V: secretMetaVersion, CreatedAt: now, ExpiresAt: expiresAt}
	case ttl > 0:
		expiresAt = now.Add(ttl)
		meta = &SecretMeta{V: secretMetaVersion, CreatedAt: now, ExpiresAt: expiresAt}
	}

	if err := storeSecret(ctx, backend, c.Name, value, meta); err != nil {
		_ = AppendAudit(AuditEvent{Action: ActionDenied, SecretName: c.Name, Caller: callerTag(), Message: sanitizeBackendErr(err)})
		return err
	}

	auditMsg := ""
	if !expiresAt.IsZero() {
		auditMsg = "expires_at=" + expiresAt.Format(time.RFC3339)
	}
	_ = AppendAudit(AuditEvent{Action: ActionSet, SecretName: c.Name, Caller: callerTag(), Message: auditMsg})
	fmt.Fprintf(stderr, "stored %q in %s", c.Name, backend.Name())
	if !expiresAt.IsZero() {
		fmt.Fprintf(stderr, " (expires %s)", expiresAt.Format(time.RFC3339))
	}
	fmt.Fprintln(stderr)
	if warnTrailingNewline {
		fmt.Fprintln(stderr, trailingNewlineWarning)
	}
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
