package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sync/atomic"

	"golang.org/x/term"
)

type SetCmd struct {
	Name string `arg:"" help:"Secret name (e.g. openai_api_key)."`
}

// maxSecretSize bounds the buffer we read for a single secret. Generous for
// API tokens and certs; rejects accidental piping of large files.
const maxSecretSize = 64 * 1024

func (c *SetCmd) Run() error {
	if c.Name == "" {
		return errors.New("name must not be empty")
	}

	ctx := context.Background()
	backend, err := OpenDefaultBackend()
	if err != nil {
		return err
	}

	var value *Buffer
	stdinFd := int(os.Stdin.Fd())
	if term.IsTerminal(stdinFd) {
		fmt.Fprintf(os.Stderr, "Enter value for %q (input hidden): ", c.Name)
		raw, err := term.ReadPassword(stdinFd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return fmt.Errorf("read password: %w", err)
		}
		if len(raw) == 0 {
			return errors.New("empty secret value")
		}
		value = NewBufferFromBytes(raw)
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
