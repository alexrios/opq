package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/alecthomas/kong"
)

func seedListFixture(t *testing.T, b *memBackend, now time.Time) {
	t.Helper()
	ctx := context.Background()

	// 1. Plain active secret (no metadata)
	mustSet(t, b, "alpha_plain", "val-alpha")

	// 2. Active secret with future TTL
	mustSet(t, b, "beta_ttl", "val-beta")
	if err := storeMeta(ctx, b, "beta_ttl", &SecretMeta{
		V:         secretMetaVersion,
		CreatedAt: now.Add(-2 * time.Hour),
		ExpiresAt: now.Add(4 * time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	// 3. Expired secret
	mustSet(t, b, "gamma_expired", "val-gamma")
	if err := storeMeta(ctx, b, "gamma_expired", &SecretMeta{
		V:         secretMetaVersion,
		CreatedAt: now.Add(-24 * time.Hour),
		ExpiresAt: now.Add(-2 * time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	// 4. Revoked tombstone (no secret key, only meta)
	if err := storeMeta(ctx, b, "delta_revoked", &SecretMeta{
		V:         secretMetaVersion,
		CreatedAt: now.Add(-48 * time.Hour),
		RevokedAt: now.Add(-1 * time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	// 5. UPDATE-PENDING entry
	mustSet(t, b, "epsilon_pending", "val-epsilon")
	if err := storeMeta(ctx, b, "epsilon_pending", &SecretMeta{
		V:       secretMetaVersion,
		Pending: true,
	}); err != nil {
		t.Fatal(err)
	}

	// 6. Corrupt metadata
	mustSet(t, b, "zeta_corrupt", "val-zeta")
	mustSet(t, b, metaKey("zeta_corrupt"), `{corrupt`)
}

func TestListCmd_NonTTYBackwardsCompat(t *testing.T) {
	now := time.Date(2026, 6, 14, 8, 0, 0, 0, time.UTC)
	b := newMemBackend(t)
	seedListFixture(t, b, now)
	spy := &noSecretReadBackend{memBackend: b, t: t}

	var stdout, stderr bytes.Buffer
	cmd := &ListCmd{Status: "all"}
	if err := cmd.runWith(context.Background(), spy, &stdout, &stderr, false, now); err != nil {
		t.Fatalf("runWith: %v", err)
	}

	wantLines := []string{
		"alpha_plain",
		"beta_ttl\texpires " + now.Add(4*time.Hour).Format(time.RFC3339),
		"delta_revoked\tREVOKED",
		"epsilon_pending\tUPDATE-PENDING",
		"gamma_expired\tEXPIRED",
		"zeta_corrupt\tmeta-error",
	}
	want := strings.Join(wantLines, "\n") + "\n"
	if stdout.String() != want {
		t.Fatalf("non-TTY output mismatch:\ngot:\n%q\nwant:\n%q", stdout.String(), want)
	}
	if stderr.Len() != 0 {
		t.Fatalf("unexpected stderr on non-TTY: %q", stderr.String())
	}
}

func TestListCmd_TTYAlignmentRelativeExpiryAndNoColor(t *testing.T) {
	now := time.Date(2026, 6, 14, 8, 0, 0, 0, time.UTC)
	b := newMemBackend(t)
	seedListFixture(t, b, now)
	spy := &noSecretReadBackend{memBackend: b, t: t}

	t.Run("with ANSI colors on TTY", func(t *testing.T) {
		t.Setenv("NO_COLOR", "")
		t.Setenv("TERM", "xterm-256color")
		var stdout, stderr bytes.Buffer
		cmd := &ListCmd{Status: "all"}
		if err := cmd.runWith(context.Background(), spy, &stdout, &stderr, true, now); err != nil {
			t.Fatalf("runWith: %v", err)
		}
		out := stdout.String()
		if !strings.Contains(out, "expires in 4h (2026-06-14 12:00 UTC)") {
			t.Errorf("missing relative expiry in TTY output:\n%s", out)
		}
		if !strings.Contains(out, "\x1b[") {
			t.Errorf("expected ANSI styling on TTY when NO_COLOR is unset:\n%q", out)
		}
		// Never leak values.
		for _, val := range []string{"val-alpha", "val-beta", "val-gamma", "val-epsilon", "val-zeta"} {
			if strings.Contains(out, val) {
				t.Fatalf("secret value %q leaked into list output!", val)
			}
		}
		// Plain secret row should not have trailing spaces.
		lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
		if lines[0] != "alpha_plain" {
			t.Errorf("first line = %q, want exact %q (no trailing spaces)", lines[0], "alpha_plain")
		}
	})

	t.Run("respects NO_COLOR", func(t *testing.T) {
		t.Setenv("NO_COLOR", "1")
		var stdout, stderr bytes.Buffer
		cmd := &ListCmd{Status: "all"}
		if err := cmd.runWith(context.Background(), spy, &stdout, &stderr, true, now); err != nil {
			t.Fatalf("runWith: %v", err)
		}
		out := stdout.String()
		if strings.Contains(out, "\x1b[") {
			t.Fatalf("NO_COLOR=1 must suppress ANSI escapes, got:\n%q", out)
		}
		if !strings.Contains(out, "expires in 4h (2026-06-14 12:00 UTC)") {
			t.Errorf("missing relative expiry:\n%s", out)
		}
	})
}

func TestListCmd_LongAndStatusFilters(t *testing.T) {
	now := time.Date(2026, 6, 14, 8, 0, 0, 0, time.UTC)
	b := newMemBackend(t)
	seedListFixture(t, b, now)
	spy := &noSecretReadBackend{memBackend: b, t: t}

	t.Run("--long displays header and metadata columns without ANSI when NO_COLOR=1", func(t *testing.T) {
		t.Setenv("NO_COLOR", "1")
		var stdout, stderr bytes.Buffer
		cmd := &ListCmd{Long: true, Status: "all"}
		if err := cmd.runWith(context.Background(), spy, &stdout, &stderr, true, now); err != nil {
			t.Fatalf("runWith: %v", err)
		}
		out := stdout.String()
		lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
		if len(lines) != 7 {
			t.Fatalf("expected header + 6 rows = 7 lines, got %d:\n%s", len(lines), out)
		}
		if !strings.HasPrefix(lines[0], "NAME") || !strings.Contains(lines[0], "STATUS") || !strings.Contains(lines[0], "CREATED") {
			t.Errorf("unexpected header: %q", lines[0])
		}
		if !strings.Contains(out, "2026-06-14 06:00 UTC") {
			t.Errorf("missing CreatedAt timestamp:\n%s", out)
		}
		if !strings.Contains(out, "revoked 2026-06-14 07:00 UTC") {
			t.Errorf("missing RevokedAt detail:\n%s", out)
		}
	})

	t.Run("--long with ANSI keeps column alignment identical", func(t *testing.T) {
		t.Setenv("NO_COLOR", "")
		t.Setenv("TERM", "xterm-256color")
		var stdoutColor, stdoutPlain, stderr bytes.Buffer
		if err := (&ListCmd{Long: true, Status: "all"}).runWith(context.Background(), spy, &stdoutColor, &stderr, true, now); err != nil {
			t.Fatalf("color runWith: %v", err)
		}
		t.Setenv("NO_COLOR", "1")
		if err := (&ListCmd{Long: true, Status: "all"}).runWith(context.Background(), spy, &stdoutPlain, &stderr, true, now); err != nil {
			t.Fatalf("plain runWith: %v", err)
		}
		if stripTestANSI(stdoutColor.String()) != stdoutPlain.String() {
			t.Fatalf("ANSI codes shifted column alignment!\nstripped color:\n%s\nplain:\n%s",
				stripTestANSI(stdoutColor.String()), stdoutPlain.String())
		}
	})

	t.Run("--status filters", func(t *testing.T) {
		cases := []struct {
			status string
			want   []string
		}{
			{"active", []string{"alpha_plain", "beta_ttl"}},
			{"expired", []string{"gamma_expired"}},
			{"revoked", []string{"delta_revoked"}},
			{"pending", []string{"epsilon_pending"}},
		}
		for _, tc := range cases {
			var stdout, stderr bytes.Buffer
			cmd := &ListCmd{JSON: true, Status: tc.status}
			if err := cmd.runWith(context.Background(), spy, &stdout, &stderr, false, now); err != nil {
				t.Fatalf("status=%s: %v", tc.status, err)
			}
			var items []listJSONEntry
			if err := json.Unmarshal(stdout.Bytes(), &items); err != nil {
				t.Fatalf("status=%s: unmarshal: %v", tc.status, err)
			}
			if len(items) != len(tc.want) {
				t.Fatalf("status=%s: got %d items (%+v), want %v", tc.status, len(items), items, tc.want)
			}
			for i, w := range tc.want {
				if items[i].Name != w {
					t.Errorf("status=%s: item[%d].Name = %q, want %q", tc.status, i, items[i].Name, w)
				}
			}
		}
	})
}

func TestListCmd_JSONAndEmptyState(t *testing.T) {
	now := time.Date(2026, 6, 14, 8, 0, 0, 0, time.UTC)

	t.Run("--json outputs empty array (not null) when empty", func(t *testing.T) {
		b := newMemBackend(t)
		var stdout, stderr bytes.Buffer
		if err := (&ListCmd{JSON: true, Status: "all"}).runWith(context.Background(), b, &stdout, &stderr, true, now); err != nil {
			t.Fatalf("runWith: %v", err)
		}
		if strings.TrimSpace(stdout.String()) != "[]" {
			t.Fatalf("got %q, want []", stdout.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("unexpected stderr in --json mode: %q", stderr.String())
		}
	})

	t.Run("TTY empty state prints helpful stderr hint", func(t *testing.T) {
		b := newMemBackend(t)
		var stdout, stderr bytes.Buffer
		if err := (&ListCmd{Status: "all"}).runWith(context.Background(), b, &stdout, &stderr, true, now); err != nil {
			t.Fatalf("runWith: %v", err)
		}
		if stdout.Len() != 0 {
			t.Fatalf("expected empty stdout, got %q", stdout.String())
		}
		if !strings.Contains(stderr.String(), "opq set") {
			t.Fatalf("expected helpful empty-state hint on stderr, got %q", stderr.String())
		}
	})

	t.Run("TTY filtered empty state prints filter hint", func(t *testing.T) {
		b := newMemBackend(t)
		mustSet(t, b, "only_active", "v")
		var stdout, stderr bytes.Buffer
		if err := (&ListCmd{Status: "revoked"}).runWith(context.Background(), b, &stdout, &stderr, true, now); err != nil {
			t.Fatalf("runWith: %v", err)
		}
		if stdout.Len() != 0 {
			t.Fatalf("expected empty stdout, got %q", stdout.String())
		}
		if !strings.Contains(stderr.String(), `no secrets with status "revoked"`) {
			t.Fatalf("unexpected stderr hint: %q", stderr.String())
		}
	})
}

func TestListCmd_KongFlags(t *testing.T) {
	var cli CLI
	p, err := kong.New(&cli)
	if err != nil {
		t.Fatalf("kong.New: %v", err)
	}
	if _, err := p.Parse([]string{"list", "-l", "--json", "--status", "expired"}); err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if !cli.List.Long || !cli.List.JSON || cli.List.Status != "expired" {
		t.Fatalf("unexpected ListCmd: %+v", cli.List)
	}
	if _, err := p.Parse([]string{"list", "--status", "bogus"}); err == nil {
		t.Fatal("expected error for invalid --status")
	}
}

func TestUIFormatDurationAndSanitize(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{0, "0s"},
		{500 * time.Millisecond, "<1s"},
		{45 * time.Second, "45s"},
		{12 * time.Minute, "12m"},
		{59*time.Minute + 50*time.Second, "1h"},
		{4 * time.Hour, "4h"},
		{3*time.Hour + 59*time.Minute + 59*time.Second, "4h"},
		{4*time.Hour + 15*time.Minute, "4h15m"},
		{23*time.Hour + 59*time.Minute + 50*time.Second, "1d"},
		{2*24*time.Hour + 6*time.Hour, "2d6h"},
		{7 * 24 * time.Hour, "7d"},
		{30*24*time.Hour + 5*time.Hour, "30d"},
	}
	for _, tc := range cases {
		if got := uiFormatDuration(tc.d); got != tc.want {
			t.Errorf("uiFormatDuration(%v) = %q, want %q", tc.d, got, tc.want)
		}
	}

	// Sanitizer must neutralize escape sequences and control bytes.
	if got := uiSanitizeCell("a\x1b[31mb\tc\nd\x1fe"); strings.ContainsAny(got, "\x1b\t\n\x1f") {
		t.Fatalf("uiSanitizeCell left control bytes: %q", got)
	}
}

// stripTestANSI strips SGR ANSI sequences (\x1b[...m) for alignment assertions.
func stripTestANSI(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] == '\x1b' && i+1 < len(s) && s[i+1] == '[' {
			j := i + 2
			for j < len(s) && s[j] != 'm' {
				j++
			}
			if j < len(s) {
				i = j + 1
				continue
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}
