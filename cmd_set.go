package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sync/atomic"

	"github.com/awnumar/memguard"
	"golang.org/x/term"
)

type SetCmd struct {
	Name string `arg:"" help:"Secret name (e.g. openai_api_key)."`
}

// maxSecretSize bounds the buffer we read for a single secret. Generous for
// API tokens and certs; rejects accidental piping of large files.
const maxSecretSize = 64 * 1024

// Bracketed-paste terminal sequences. Shells (fish, bash w/ readline) put the
// terminal into bracketed-paste mode, so a paste arrives wrapped in
// ESC[200~ ... ESC[201~. term.ReadPassword runs the tty in raw mode and does
// not interpret these, so the markers land verbatim in the read bytes and the
// value is corrupted. We disable the mode for the duration of the read and
// strip any markers defensively.
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

// sanitizePastedSecret cleans bytes read from the hidden TTY prompt: it strips
// any bracketed-paste markers that survived raw-mode reading, then trims
// surrounding whitespace (spaces, tabs, CR, LF) that a paste commonly carries
// when a token is copied from a web page or a `.env` line. All work is in
// place on raw's backing array; the result is a subslice of raw. Only the
// interactive path trims — the piped path (NewBufferFromReader) stores exact
// bytes, so a value that legitimately needs surrounding whitespace can be
// supplied via stdin.
func sanitizePastedSecret(raw []byte) []byte {
	b := stripBytesInPlace(raw, []byte(bracketedPasteStart))
	b = stripBytesInPlace(b, []byte(bracketedPasteEnd))
	return bytes.TrimSpace(b)
}

func (c *SetCmd) Run() error {
	if !validSecretName(c.Name) {
		return fmt.Errorf("invalid secret name %q (must match [A-Za-z0-9_.-]{1,128})", c.Name)
	}

	ctx := context.Background()
	backend, err := OpenDefaultBackend()
	if err != nil {
		return err
	}

	var value *Buffer
	stdinFd := int(os.Stdin.Fd())
	if term.IsTerminal(stdinFd) {
		// Disable bracketed-paste mode while reading so a paste delivers clean
		// bytes instead of ESC[200~...ESC[201~-wrapped ones. Only emit when
		// stderr is the terminal (the prompt also goes there); restore after.
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
		// NewBufferFromBytes copies cleaned into the locked buffer and wipes
		// cleaned (a subslice of raw); WipeBytes(raw) then clears any residue
		// left by marker stripping / whitespace trimming.
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
	_ = AppendAudit(AuditEvent{Action: ActionSet, SecretName: c.Name, Caller: callerTag()})
	fmt.Fprintf(os.Stderr, "stored %q in %s\n", c.Name, backend.Name())
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
