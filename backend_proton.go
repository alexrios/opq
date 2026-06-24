package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"time"

	"github.com/awnumar/memguard"
)

// protonCommandTimeout bounds each pass-cli invocation. pass-cli talks to Proton
// servers, so the backend self-limits (mirroring the vault client) rather than
// trusting the caller's context — the CLI exec path resolves with
// context.Background(), and the MCP per-call timeout is created only after
// secret resolution.
const protonCommandTimeout = 15 * time.Second

// maxProtonOutput bounds the pass-cli stdout opq buffers. `item view` returns a
// single value, but `item list` on pass-cli 1.x embeds full item content, so
// this must fit a large vault while still capping a runaway or hostile CLI from
// growing the heap unboundedly inside the trusted opq process.
const maxProtonOutput = 8 << 20 // 8 MiB

// protonRunner runs pass-cli and returns its stdout. It is the test seam:
// production uses execProtonRunner; tests inject a fake returning canned output
// so pass-cli is never needed in CI.
type protonRunner func(ctx context.Context, name string, args ...string) ([]byte, error)

// protonBackend is a READ-ONLY Backend backed by the official Proton Pass CLI
// (pass-cli, https://protonpass.github.io/pass-cli/). opq reads and execs
// secrets the operator manages in the Proton Pass app; it never mutates the
// vault (Set/Delete return ErrBackendReadOnly). The policy layer degrades
// cleanly: a read-only backend has no companion meta/<name> items, so loadMeta
// finds nothing and there is no TTL/revocation.
//
// pass-cli runs in opq's own process context, NOT inside the exec/MCP sandbox:
// resolveSecret runs before the sandboxed child is spawned, so the backend uses
// the operator's Proton session. It is part of opq's trusted core, the same
// trust level as the keyring's D-Bus call.
//
// Command surface verified against pass-cli 1.4.1: `item list <vault> --output
// json` returns {"items":[...]} and `item view --share-id S --item-id I --field
// F` prints only field F's raw value (newline-terminated), avoiding the
// externally-tagged content enum entirely. The list item's title location is
// version-dependent (see protonItem); the value is always read via --field.
//
// Item titles are the opq secret names. Proton does not enforce unique titles
// within a vault, so Get fails closed (ambiguity error) if two items share the
// requested title rather than return an arbitrary one.
type protonBackend struct {
	bin   string       // resolved pass-cli path
	vault string       // OPQ_PROTON_VAULT (the Proton vault NAME to read)
	field string       // OPQ_PROTON_FIELD (default "password")
	run   protonRunner // injectable for tests
}

func openProtonBackend() (Backend, error) {
	bin := envOr("OPQ_PROTON_PASS_CLI", "pass-cli")
	if err := preflightExecutable(bin); err != nil {
		return nil, fmt.Errorf("proton-pass backend: %w", err)
	}
	vault := os.Getenv("OPQ_PROTON_VAULT")
	if vault == "" {
		return nil, errors.New("proton-pass backend requires OPQ_PROTON_VAULT (the Proton Pass vault to read)")
	}
	return &protonBackend{
		bin:   bin,
		vault: vault,
		field: envOr("OPQ_PROTON_FIELD", "password"),
		run:   execProtonRunner,
	}, nil
}

func (b *protonBackend) Name() string { return "proton-pass" }

// execProtonRunner runs pass-cli, capturing stdout and DISCARDING stderr.
// pass-cli stderr can echo item data, and any error opq surfaces (operator
// stderr, audit) must never carry secret-adjacent bytes, so the error names
// only the subcommand, never stderr or arguments such as item IDs.
func execProtonRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, protonCommandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	var out bytes.Buffer
	cw := newCappedWriter(&out, maxProtonOutput)
	cmd.Stdout = cw
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		memguard.WipeBytes(out.Bytes()) // partial output may be secret-bearing
		return nil, fmt.Errorf("pass-cli %s failed", subcommandLabel(args))
	}
	if cw.Truncated() {
		// Fail closed rather than return a truncated (and possibly
		// secret-bearing) value once the cap is hit.
		memguard.WipeBytes(out.Bytes())
		return nil, fmt.Errorf("pass-cli %s output exceeded %d bytes", subcommandLabel(args), maxProtonOutput)
	}
	return out.Bytes(), nil
}

// subcommandLabel returns a non-sensitive label (e.g. "item view") for error
// messages, omitting any vault name / item IDs that follow.
func subcommandLabel(args []string) string {
	switch {
	case len(args) >= 2:
		return args[0] + " " + args[1]
	case len(args) == 1:
		return args[0]
	default:
		return "command"
	}
}

// Set is unsupported: the Proton backend is read-only.
func (b *protonBackend) Set(_ context.Context, name string, _ *Buffer) error {
	return fmt.Errorf("proton-pass is read-only; manage %q in the Proton Pass app: %w", name, ErrBackendReadOnly)
}

// Delete is unsupported: the Proton backend is read-only.
func (b *protonBackend) Delete(_ context.Context, name string) error {
	return fmt.Errorf("proton-pass is read-only; manage %q in the Proton Pass app: %w", name, ErrBackendReadOnly)
}

// protonListResponse / protonItem are the minimal shape opq needs from
// `item list --output json`. The title's location varies by pass-cli version:
// 1.x embeds the full item content in the listing (title at content.title), so
// that listing also carries secret VALUES; 2.x returns a flat summary with a
// top-level title and no values. We read both and prefer the top-level one.
// Verified against pass-cli 1.4.1.
type protonListResponse struct {
	Items []protonItem `json:"items"`
}

type protonItem struct {
	ID      string `json:"id"`
	ShareID string `json:"share_id"`
	Title   string `json:"title"` // pass-cli 2.x summary
	Content struct {
		Title string `json:"title"` // pass-cli 1.x embeds full content
	} `json:"content"`
}

// title returns the item title across pass-cli versions.
func (it protonItem) title() string {
	if it.Title != "" {
		return it.Title
	}
	return it.Content.Title
}

func (b *protonBackend) list(ctx context.Context) ([]protonItem, error) {
	out, err := b.run(ctx, b.bin, "item", "list", b.vault, "--output", "json")
	if err != nil {
		return nil, fmt.Errorf("proton-pass list: %w", err)
	}
	defer memguard.WipeBytes(out) // pass-cli 1.x embeds full item content (secret values) in the listing
	var resp protonListResponse
	if err := json.Unmarshal(out, &resp); err != nil {
		return nil, errors.New("proton-pass list: parse response")
	}
	return resp.Items, nil
}

func (b *protonBackend) List(ctx context.Context) ([]string, error) {
	items, err := b.list(ctx)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(items))
	seen := map[string]bool{}
	for _, it := range items {
		t := it.title()
		// Skip titles that aren't valid opq secret names: they can't be
		// addressed via get/exec anyway, and keeping control characters,
		// overlong names, or a meta/ prefix out of the (AI-visible) listing
		// bounds the namespace, the same name-shape guard cmd_set enforces.
		if validSecretName(t) && !seen[t] {
			seen[t] = true
			names = append(names, t)
		}
	}
	sort.Strings(names)
	return names, nil
}

func (b *protonBackend) Get(ctx context.Context, name string) (*Buffer, error) {
	// Read-only Proton has no companion meta/ items; short-circuit so loadMeta
	// (which probes Get("meta/"+name)) returns "no policy" with no pass-cli call.
	if isMetaKey(name) {
		return nil, ErrSecretNotFound
	}
	// Defense in depth: only ever match a valid opq secret name against a title,
	// mirroring resolveSecret's own guard, so a caller that bypassed it can't
	// reach an out-of-shape title.
	if !validSecretName(name) {
		return nil, ErrSecretNotFound
	}
	// Resolve the title to (shareID, itemID) from the listing. A missing title
	// is a clean not-found with no second pass-cli call. (pass-cli has no
	// distinct not-found exit code, so determining existence from the list
	// avoids having to parse stderr, which we discard for safety.)
	items, err := b.list(ctx)
	if err != nil {
		return nil, err
	}
	var found *protonItem
	matches := 0
	for i := range items {
		if items[i].title() == name {
			if found == nil {
				found = &items[i]
			}
			matches++
		}
	}
	if matches > 1 {
		// Proton item titles aren't unique within a vault. Fail closed rather
		// than inject an arbitrary item's value — a credential tool must hand
		// over the RIGHT secret. The operator disambiguates by renaming in the
		// Proton Pass app.
		return nil, fmt.Errorf("proton-pass: %q is ambiguous: %d items in vault %q share this title", name, matches, b.vault)
	}
	if found == nil {
		return nil, ErrSecretNotFound
	}

	// --field prints only the field's raw value (no JSON, no enum-walking),
	// newline-terminated. The default field is "password" (a login item's
	// value); OPQ_PROTON_FIELD selects another (case-insensitive in pass-cli).
	out, err := b.run(ctx, b.bin, "item", "view",
		"--share-id", found.ShareID, "--item-id", found.ID, "--field", b.field)
	if err != nil {
		return nil, fmt.Errorf("proton-pass get: %w", err)
	}
	defer memguard.WipeBytes(out) // view output carries the plaintext value

	// pass-cli appends a single trailing newline; strip exactly one. (A value
	// that itself ends in a newline cannot round-trip through --field; such a
	// value should be stored in the keyring/Vault backend instead.)
	val := bytes.TrimSuffix(out, []byte("\n"))
	if len(val) == 0 {
		return nil, ErrSecretNotFound // absent/empty field
	}
	buf, err := NewBufferFromBytes(val) // copies into a locked buffer, wipes val
	if err != nil {
		return nil, fmt.Errorf("proton-pass get: %w", err)
	}
	return buf, nil
}
