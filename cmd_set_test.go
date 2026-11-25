package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/99designs/keyring"
	"github.com/alecthomas/kong"
)

// TestSanitizePastedSecret covers the cleaning applied to bytes read from the
// hidden TTY prompt: bracketed-paste marker stripping plus whitespace trimming.
func TestSanitizePastedSecret(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain", "sk-abc123", "sk-abc123"},
		{"trailing newline", "sk-abc123\n", "sk-abc123"},
		{"trailing crlf", "sk-abc123\r\n", "sk-abc123"},
		{"leading and trailing spaces", "  sk-abc123  ", "sk-abc123"},
		{"surrounding whitespace mix", "\t sk-abc123 \r\n", "sk-abc123"},
		{"bracketed paste wrapped", "\x1b[200~sk-abc123\x1b[201~", "sk-abc123"},
		{"bracketed paste with newline", "\x1b[200~sk-abc123\n\x1b[201~", "sk-abc123"},
		{"only whitespace", "  \r\n\t ", ""},
		{"only paste markers", "\x1b[200~\x1b[201~", ""},
		{"empty", "", ""},
		{"internal spaces preserved", "  a b c  ", "a b c"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := sanitizePastedSecret([]byte(tc.in))
			if string(got) != tc.want {
				t.Fatalf("sanitizePastedSecret(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestStripBytesInPlace verifies in-place separator removal and that no extra
// backing array is allocated (the result aliases the input).
func TestStripBytesInPlace(t *testing.T) {
	in := []byte("aXXbXXc")
	got := stripBytesInPlace(in, []byte("XX"))
	if string(got) != "abc" {
		t.Fatalf("stripBytesInPlace = %q, want %q", got, "abc")
	}
	// Result must alias the input's backing array (no allocation).
	if len(got) > 0 && &got[0] != &in[0] {
		t.Fatalf("stripBytesInPlace allocated a new array; want in-place")
	}
	// Empty separator is a no-op.
	if g := stripBytesInPlace([]byte("abc"), nil); string(g) != "abc" {
		t.Fatalf("stripBytesInPlace with empty sep = %q, want %q", g, "abc")
	}
}

// TestSanitizePastedSecret_WipeableResidue documents that sanitize works in
// place: the returned slice is a subslice of the input, so wiping the input
// array after constructing the buffer clears all secret residue.
func TestSanitizePastedSecret_WipeableResidue(t *testing.T) {
	raw := []byte("\x1b[200~secret\n\x1b[201~")
	cleaned := sanitizePastedSecret(raw)
	if string(cleaned) != "secret" {
		t.Fatalf("cleaned = %q, want %q", cleaned, "secret")
	}
	// cleaned aliases raw's backing array, so wiping raw clears it.
	for i := range raw {
		raw[i] = 0
	}
	if !bytes.Equal(cleaned, make([]byte, len(cleaned))) {
		t.Fatalf("cleaned not zeroed after wiping raw; aliasing assumption broken")
	}
}

// TestCallerTagRace exercises concurrent SetCallerTag/callerTag access so the
// race detector can flag any regression away from atomic.Pointer[string].
func TestCallerTagRace(t *testing.T) {
	t.Cleanup(func() { SetCallerTag("cli") })

	const goroutines = 16
	const iters = 1000

	tags := []string{"cli", "mcp", "test-a", "test-b"}

	var wg sync.WaitGroup
	wg.Add(goroutines * 2)

	for i := 0; i < goroutines; i++ {
		i := i
		go func() {
			defer wg.Done()
			for j := 0; j < iters; j++ {
				SetCallerTag(tags[(i+j)%len(tags)])
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < iters; j++ {
				got := callerTag()
				if got == "" {
					t.Errorf("callerTag returned empty string")
					return
				}
			}
		}()
	}

	wg.Wait()
}

// TestCallerTagDefault verifies the package-level default is "cli" before any
// SetCallerTag override.
func TestCallerTagDefault(t *testing.T) {
	SetCallerTag("cli")
	if got := callerTag(); got != "cli" {
		t.Fatalf("default caller tag: got %q, want %q", got, "cli")
	}
}

// TestCallerTagOverride verifies SetCallerTag is observed by subsequent reads.
func TestCallerTagOverride(t *testing.T) {
	t.Cleanup(func() { SetCallerTag("cli") })

	SetCallerTag("mcp")
	if got := callerTag(); got != "mcp" {
		t.Fatalf("after SetCallerTag(\"mcp\"): got %q, want %q", got, "mcp")
	}
}

// noSecretReadBackend wraps memBackend and fails the test if Backend.Get is
// ever called on a non-meta key (proving set pre-checks and list never read
// secret values).
type noSecretReadBackend struct {
	*memBackend
	t *testing.T
}

func (b *noSecretReadBackend) Get(ctx context.Context, name string) (*Buffer, error) {
	if !isMetaKey(name) {
		b.t.Fatalf("unexpected Backend.Get on secret value %q (invariant violation)", name)
	}
	return b.memBackend.Get(ctx, name)
}

func TestSetCmd_TrimAndTrailingNewlineWarning(t *testing.T) {
	baseNow := time.Date(2026, 6, 14, 8, 0, 0, 0, time.UTC)

	t.Run("piped newline stored verbatim with warning", func(t *testing.T) {
		b := newMemBackend(t)
		spy := &noSecretReadBackend{memBackend: b, t: t}
		var stderr bytes.Buffer
		cmd := &SetCmd{Name: "api_key"}
		err := cmd.runWith(context.Background(), spy, strings.NewReader("sk-abc\n"), false, &stderr, false, nil, func() time.Time { return baseNow })
		if err != nil {
			t.Fatalf("runWith: %v", err)
		}
		got, err := b.Get(context.Background(), "api_key")
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		defer got.Destroy()
		if string(got.Bytes()) != "sk-abc\n" {
			t.Fatalf("stored value = %q, want verbatim %q", got.Bytes(), "sk-abc\n")
		}
		if !strings.Contains(stderr.String(), trailingNewlineWarning) {
			t.Fatalf("stderr missing trailing-newline warning:\n%s", stderr.String())
		}
	})

	t.Run("piped CRLF stored verbatim with warning", func(t *testing.T) {
		b := newMemBackend(t)
		var stderr bytes.Buffer
		cmd := &SetCmd{Name: "api_key"}
		err := cmd.runWith(context.Background(), b, strings.NewReader("sk-abc\r\n"), false, &stderr, false, nil, func() time.Time { return baseNow })
		if err != nil {
			t.Fatalf("runWith: %v", err)
		}
		got, err := b.Get(context.Background(), "api_key")
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		defer got.Destroy()
		if string(got.Bytes()) != "sk-abc\r\n" {
			t.Fatalf("stored value = %q, want %q", got.Bytes(), "sk-abc\r\n")
		}
		if !strings.Contains(stderr.String(), trailingNewlineWarning) {
			t.Fatalf("stderr missing trailing-newline warning:\n%s", stderr.String())
		}
	})

	t.Run("piped without newline has no warning", func(t *testing.T) {
		b := newMemBackend(t)
		var stderr bytes.Buffer
		cmd := &SetCmd{Name: "api_key"}
		err := cmd.runWith(context.Background(), b, strings.NewReader("sk-abc"), false, &stderr, false, nil, func() time.Time { return baseNow })
		if err != nil {
			t.Fatalf("runWith: %v", err)
		}
		if strings.Contains(stderr.String(), "warning:") {
			t.Fatalf("unexpected warning in stderr:\n%s", stderr.String())
		}
	})

	t.Run("--trim strips trailing LF and CRLF without warning", func(t *testing.T) {
		for _, tc := range []struct {
			in   string
			want string
		}{
			{"sk-abc\n", "sk-abc"},
			{"sk-abc\r\n", "sk-abc"},
			{"sk-abc\r\n\n", "sk-abc"},
			{"  sk-abc  \n", "  sk-abc  "}, // preserves spaces, strips only newlines
			{"line1\nline2\n", "line1\nline2"},
			{"sk-abc", "sk-abc"},
		} {
			b := newMemBackend(t)
			var stderr bytes.Buffer
			cmd := &SetCmd{Name: "api_key", Trim: true}
			err := cmd.runWith(context.Background(), b, strings.NewReader(tc.in), false, &stderr, false, nil, func() time.Time { return baseNow })
			if err != nil {
				t.Fatalf("in=%q: runWith: %v", tc.in, err)
			}
			got, err := b.Get(context.Background(), "api_key")
			if err != nil {
				t.Fatalf("in=%q: Get: %v", tc.in, err)
			}
			if string(got.Bytes()) != tc.want {
				got.Destroy()
				t.Fatalf("in=%q: stored %q, want %q", tc.in, got.Bytes(), tc.want)
			}
			got.Destroy()
			if strings.Contains(stderr.String(), "warning:") {
				t.Fatalf("in=%q: unexpected warning with --trim:\n%s", tc.in, stderr.String())
			}
		}
	})

	t.Run("--trim rejects whitespace-only newline input as empty", func(t *testing.T) {
		b := newMemBackend(t)
		var stderr bytes.Buffer
		cmd := &SetCmd{Name: "api_key", Trim: true}
		err := cmd.runWith(context.Background(), b, strings.NewReader("\r\n\n"), false, &stderr, false, nil, func() time.Time { return baseNow })
		if err == nil || !strings.Contains(err.Error(), "empty") {
			t.Fatalf("expected empty secret error, got %v", err)
		}
	})
}

func TestSetCmd_KeepTTL(t *testing.T) {
	baseNow := time.Date(2026, 6, 14, 8, 0, 0, 0, time.UTC)
	origExpiry := baseNow.Add(4 * time.Hour)

	t.Run("preserves active unexpired ExpiresAt", func(t *testing.T) {
		b := newMemBackend(t)
		spy := &noSecretReadBackend{memBackend: b, t: t}
		ctx := context.Background()
		mustSet(t, b, "k", "old-val")
		if err := storeMeta(ctx, b, "k", &SecretMeta{V: secretMetaVersion, CreatedAt: baseNow.Add(-time.Hour), ExpiresAt: origExpiry}); err != nil {
			t.Fatal(err)
		}

		later := baseNow.Add(30 * time.Minute)
		var stderr bytes.Buffer
		cmd := &SetCmd{Name: "k", KeepTTL: true}
		if err := cmd.runWith(ctx, spy, strings.NewReader("new-val"), false, &stderr, false, nil, func() time.Time { return later }); err != nil {
			t.Fatalf("runWith: %v", err)
		}
		got, err := resolveSecret(ctx, b, "k", later)
		if err != nil {
			t.Fatalf("resolveSecret: %v", err)
		}
		defer got.Destroy()
		if string(got.Bytes()) != "new-val" {
			t.Fatalf("value = %q, want new-val", got.Bytes())
		}
		m, err := loadMeta(ctx, b, "k")
		if err != nil || m == nil {
			t.Fatalf("loadMeta: meta=%+v err=%v", m, err)
		}
		if !m.ExpiresAt.Equal(origExpiry) {
			t.Fatalf("ExpiresAt = %v, want preserved %v", m.ExpiresAt, origExpiry)
		}
		if !strings.Contains(stderr.String(), "preserving expiry") {
			t.Fatalf("stderr should mention preserving expiry:\n%s", stderr.String())
		}
		// Audit entry records the preserved expires_at.
		data, err := os.ReadFile(filepath.Join(os.Getenv("XDG_STATE_HOME"), "opq", "audit.log"))
		if err != nil {
			t.Fatalf("read audit.log: %v", err)
		}
		var ev AuditEvent
		if err := json.Unmarshal(bytes.TrimSpace(data), &ev); err != nil {
			t.Fatalf("unmarshal audit: %v", err)
		}
		if ev.Action != ActionSet || ev.Message != "expires_at="+origExpiry.Format(time.RFC3339) {
			t.Fatalf("unexpected audit event: %+v", ev)
		}
	})

	t.Run("rejects --keep-ttl combined with --ttl", func(t *testing.T) {
		b := newMemBackend(t)
		var stderr bytes.Buffer
		cmd := &SetCmd{Name: "k", TTL: "1h", KeepTTL: true}
		err := cmd.runWith(context.Background(), b, strings.NewReader("v"), false, &stderr, false, nil, func() time.Time { return baseNow })
		if err == nil || !strings.Contains(err.Error(), "--keep-ttl cannot be combined with --ttl") {
			t.Fatalf("unexpected err: %v", err)
		}
	})

	t.Run("rejects when secret does not exist", func(t *testing.T) {
		b := newMemBackend(t)
		var stderr bytes.Buffer
		cmd := &SetCmd{Name: "missing", KeepTTL: true}
		err := cmd.runWith(context.Background(), b, strings.NewReader("v"), false, &stderr, false, nil, func() time.Time { return baseNow })
		if err == nil || !strings.Contains(err.Error(), "does not exist") {
			t.Fatalf("unexpected err: %v", err)
		}
	})

	t.Run("rejects when secret has no TTL", func(t *testing.T) {
		b := newMemBackend(t)
		mustSet(t, b, "k", "old")
		var stderr bytes.Buffer
		cmd := &SetCmd{Name: "k", KeepTTL: true}
		err := cmd.runWith(context.Background(), b, strings.NewReader("new"), false, &stderr, false, nil, func() time.Time { return baseNow })
		if err == nil || !strings.Contains(err.Error(), "no active TTL") {
			t.Fatalf("unexpected err: %v", err)
		}
	})

	t.Run("rejects when secret is already expired", func(t *testing.T) {
		b := newMemBackend(t)
		mustSet(t, b, "k", "old")
		if err := storeMeta(context.Background(), b, "k", &SecretMeta{V: secretMetaVersion, ExpiresAt: baseNow.Add(-time.Minute)}); err != nil {
			t.Fatal(err)
		}
		var stderr bytes.Buffer
		cmd := &SetCmd{Name: "k", KeepTTL: true}
		err := cmd.runWith(context.Background(), b, strings.NewReader("new"), false, &stderr, false, nil, func() time.Time { return baseNow })
		if err == nil || !strings.Contains(err.Error(), "already expired") {
			t.Fatalf("unexpected err: %v", err)
		}
	})

	t.Run("rejects when secret is revoked", func(t *testing.T) {
		b := newMemBackend(t)
		if err := storeMeta(context.Background(), b, "k", &SecretMeta{V: secretMetaVersion, ExpiresAt: origExpiry, RevokedAt: baseNow.Add(-time.Minute)}); err != nil {
			t.Fatal(err)
		}
		var stderr bytes.Buffer
		cmd := &SetCmd{Name: "k", KeepTTL: true}
		err := cmd.runWith(context.Background(), b, strings.NewReader("new"), false, &stderr, false, nil, func() time.Time { return baseNow })
		if err == nil || !strings.Contains(err.Error(), "revoked") {
			t.Fatalf("unexpected err: %v", err)
		}
	})

	t.Run("rejects when secret is UPDATE-PENDING", func(t *testing.T) {
		b := newMemBackend(t)
		mustSet(t, b, "k", "old")
		if err := storeMeta(context.Background(), b, "k", &SecretMeta{V: secretMetaVersion, Pending: true}); err != nil {
			t.Fatal(err)
		}
		var stderr bytes.Buffer
		cmd := &SetCmd{Name: "k", KeepTTL: true}
		err := cmd.runWith(context.Background(), b, strings.NewReader("new"), false, &stderr, false, nil, func() time.Time { return baseNow })
		if err == nil || !strings.Contains(err.Error(), "UPDATE-PENDING") {
			t.Fatalf("unexpected err: %v", err)
		}
	})
}

func TestSetCmd_NoClobber(t *testing.T) {
	baseNow := time.Date(2026, 6, 14, 8, 0, 0, 0, time.UTC)

	t.Run("refuses overwriting an active live secret", func(t *testing.T) {
		b := newMemBackend(t)
		spy := &noSecretReadBackend{memBackend: b, t: t}
		mustSet(t, b, "k", "orig")
		var stderr bytes.Buffer
		cmd := &SetCmd{Name: "k", NoClobber: true}
		err := cmd.runWith(context.Background(), spy, strings.NewReader("new"), false, &stderr, false, nil, func() time.Time { return baseNow })
		if err == nil || !strings.Contains(err.Error(), "already exists") {
			t.Fatalf("expected already exists error, got %v", err)
		}
		got, _ := b.Get(context.Background(), "k")
		defer got.Destroy()
		if string(got.Bytes()) != "orig" {
			t.Fatalf("secret was clobbered: got %q", got.Bytes())
		}
	})

	t.Run("allows storing when secret does not exist", func(t *testing.T) {
		b := newMemBackend(t)
		var stderr bytes.Buffer
		cmd := &SetCmd{Name: "k", NoClobber: true}
		if err := cmd.runWith(context.Background(), b, strings.NewReader("fresh"), false, &stderr, false, nil, func() time.Time { return baseNow }); err != nil {
			t.Fatalf("runWith: %v", err)
		}
		got, _ := b.Get(context.Background(), "k")
		defer got.Destroy()
		if string(got.Bytes()) != "fresh" {
			t.Fatalf("got %q, want fresh", got.Bytes())
		}
	})

	t.Run("allows reviving REVOKED tombstone and replacing EXPIRED secret", func(t *testing.T) {
		ctx := context.Background()
		b := newMemBackend(t)
		if err := storeMeta(ctx, b, "rev", &SecretMeta{V: secretMetaVersion, RevokedAt: baseNow.Add(-time.Hour)}); err != nil {
			t.Fatal(err)
		}
		mustSet(t, b, "exp", "stale")
		if err := storeMeta(ctx, b, "exp", &SecretMeta{V: secretMetaVersion, ExpiresAt: baseNow.Add(-time.Hour)}); err != nil {
			t.Fatal(err)
		}

		var stderr bytes.Buffer
		if err := (&SetCmd{Name: "rev", NoClobber: true}).runWith(ctx, b, strings.NewReader("v1"), false, &stderr, false, nil, func() time.Time { return baseNow }); err != nil {
			t.Fatalf("revive revoked with --no-clobber: %v", err)
		}
		if !strings.Contains(stderr.String(), "reviving previously REVOKED") {
			t.Fatalf("missing REVOKED note:\n%s", stderr.String())
		}

		stderr.Reset()
		if err := (&SetCmd{Name: "exp", NoClobber: true}).runWith(ctx, b, strings.NewReader("v2"), false, &stderr, false, nil, func() time.Time { return baseNow }); err != nil {
			t.Fatalf("replace expired with --no-clobber: %v", err)
		}
		if !strings.Contains(stderr.String(), "replacing EXPIRED") {
			t.Fatalf("missing EXPIRED note:\n%s", stderr.String())
		}
	})

	t.Run("fails closed when existing secret has corrupt metadata", func(t *testing.T) {
		b := newMemBackend(t)
		mustSet(t, b, "k", "orig")
		mustSet(t, b, metaKey("k"), `{bad-json`)
		var stderr bytes.Buffer
		err := (&SetCmd{Name: "k", NoClobber: true}).runWith(context.Background(), b, strings.NewReader("new"), false, &stderr, false, nil, func() time.Time { return baseNow })
		if err == nil || !strings.Contains(err.Error(), "unreadable metadata") {
			t.Fatalf("expected unreadable metadata error, got %v", err)
		}
	})
}

func TestSetCmd_PreStoreNotesShownBeforeInteractivePrompt(t *testing.T) {
	baseNow := time.Date(2026, 6, 14, 8, 0, 0, 0, time.UTC)

	cases := []struct {
		name     string
		setup    func(t *testing.T, b *memBackend)
		ttl      string
		wantNote string
	}{
		{
			name: "overwrite plain secret",
			setup: func(t *testing.T, b *memBackend) {
				mustSet(t, b, "k", "old")
			},
			wantNote: `overwriting existing secret "k"`,
		},
		{
			name: "overwrite secret clearing existing TTL",
			setup: func(t *testing.T, b *memBackend) {
				mustSet(t, b, "k", "old")
				if err := storeMeta(context.Background(), b, "k", &SecretMeta{V: secretMetaVersion, ExpiresAt: baseNow.Add(2 * time.Hour)}); err != nil {
					t.Fatal(err)
				}
			},
			wantNote: "clearing existing TTL",
		},
		{
			name: "overwrite secret replacing TTL",
			setup: func(t *testing.T, b *memBackend) {
				mustSet(t, b, "k", "old")
				if err := storeMeta(context.Background(), b, "k", &SecretMeta{V: secretMetaVersion, ExpiresAt: baseNow.Add(2 * time.Hour)}); err != nil {
					t.Fatal(err)
				}
			},
			ttl:      "24h",
			wantNote: "replacing TTL",
		},
		{
			name: "revive revoked tombstone",
			setup: func(t *testing.T, b *memBackend) {
				if err := storeMeta(context.Background(), b, "k", &SecretMeta{V: secretMetaVersion, RevokedAt: baseNow.Add(-time.Hour)}); err != nil {
					t.Fatal(err)
				}
			},
			wantNote: "reviving previously REVOKED",
		},
		{
			name: "recover UPDATE-PENDING",
			setup: func(t *testing.T, b *memBackend) {
				mustSet(t, b, "k", "partial")
				if err := storeMeta(context.Background(), b, "k", &SecretMeta{V: secretMetaVersion, Pending: true}); err != nil {
					t.Fatal(err)
				}
			},
			wantNote: "UPDATE-PENDING",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := newMemBackend(t)
			tc.setup(t, b)
			spy := &noSecretReadBackend{memBackend: b, t: t}

			var stderr bytes.Buffer
			noteSeenBeforePrompt := false
			readPassword := func() ([]byte, error) {
				// At the moment the prompt runs, the note MUST already be on stderr.
				if strings.Contains(stderr.String(), tc.wantNote) {
					noteSeenBeforePrompt = true
				}
				return []byte("sk-interactive-value"), nil
			}
			cmd := &SetCmd{Name: "k", TTL: tc.ttl}
			if err := cmd.runWith(context.Background(), spy, nil, true, &stderr, false, readPassword, func() time.Time { return baseNow }); err != nil {
				t.Fatalf("runWith: %v", err)
			}
			if !noteSeenBeforePrompt {
				t.Fatalf("expected note %q on stderr BEFORE prompting; got:\n%s", tc.wantNote, stderr.String())
			}
		})
	}
}

func TestSetCmd_KongFlags(t *testing.T) {
	var cli CLI
	p, err := kong.New(&cli)
	if err != nil {
		t.Fatalf("kong.New: %v", err)
	}
	if _, err := p.Parse([]string{"set", "my_secret", "--keep-ttl", "--no-clobber", "--trim"}); err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if cli.Set.Name != "my_secret" || !cli.Set.KeepTTL || !cli.Set.NoClobber || !cli.Set.Trim {
		t.Fatalf("unexpected parsed SetCmd: %+v", cli.Set)
	}
}

// stubKeyring records Items written to Set so backend metadata (Description,
// Label) can be verified without touching an OS keyring.
type stubKeyring struct {
	lastSet keyring.Item
}

func (s *stubKeyring) Get(string) (keyring.Item, error) {
	return keyring.Item{}, keyring.ErrKeyNotFound
}
func (s *stubKeyring) GetMetadata(string) (keyring.Metadata, error) {
	return keyring.Metadata{}, errors.New("unused")
}
func (s *stubKeyring) Set(item keyring.Item) error {
	s.lastSet = item
	return nil
}
func (s *stubKeyring) Remove(string) error     { return nil }
func (s *stubKeyring) Keys() ([]string, error) { return nil, nil }

func TestKeyringBackend_SetDescriptionManagedByOpq(t *testing.T) {
	kr := &stubKeyring{}
	b := &keyringBackend{kr: kr, name: "stub"}
	buf, err := NewBufferFromBytes([]byte("secret-val"))
	if err != nil {
		t.Fatal(err)
	}
	defer buf.Destroy()
	if err := b.Set(context.Background(), "api_key", buf); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if kr.lastSet.Description != "managed by opq" {
		t.Fatalf("Description = %q, want %q", kr.lastSet.Description, "managed by opq")
	}
	if kr.lastSet.Label != "opq:api_key" {
		t.Fatalf("Label = %q, want %q", kr.lastSet.Label, "opq:api_key")
	}
}
