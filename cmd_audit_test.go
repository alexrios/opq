package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alecthomas/kong"
)

func marshalAuditLine(t *testing.T, ev AuditEvent) string {
	t.Helper()
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal AuditEvent: %v", err)
	}
	return string(b)
}

func TestAuditCmd_No200CapAndAllAcrossRotatedLog(t *testing.T) {
	tmp := withAuditTmpDir(t)
	auditDir := filepath.Join(tmp, "opq")
	if err := os.MkdirAll(auditDir, 0o700); err != nil {
		t.Fatal(err)
	}
	baseTS := time.Date(2026, 6, 14, 10, 0, 0, 0, time.UTC)

	// Write 150 entries to rotated log (.1) and 150 entries to active log (total 300).
	var rotBuf, actBuf strings.Builder
	for i := 0; i < 150; i++ {
		rotBuf.WriteString(marshalAuditLine(t, AuditEvent{
			Timestamp:  baseTS.Add(time.Duration(i) * time.Second),
			Action:     ActionExecInject,
			SecretName: fmt.Sprintf("sec_%03d", i),
			Caller:     "cli",
		}) + "\n")
	}
	for i := 150; i < 300; i++ {
		actBuf.WriteString(marshalAuditLine(t, AuditEvent{
			Timestamp:  baseTS.Add(time.Duration(i) * time.Second),
			Action:     ActionExecInject,
			SecretName: fmt.Sprintf("sec_%03d", i),
			Caller:     "cli",
		}) + "\n")
	}
	if err := os.WriteFile(filepath.Join(auditDir, "audit.log.1"), []byte(rotBuf.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(auditDir, "audit.log"), []byte(actBuf.String()), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("-n 250 returns all 250 entries (no 200 cap)", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		cmd := &AuditCmd{Tail: 250}
		if err := cmd.runWith(tailAudit, &stdout, &stderr, false); err != nil {
			t.Fatalf("runWith: %v", err)
		}
		lines := strings.Split(strings.TrimSuffix(stdout.String(), "\n"), "\n")
		if len(lines) != 250 {
			t.Fatalf("got %d lines, want 250", len(lines))
		}
		if !strings.Contains(lines[0], "sec_050") || !strings.Contains(lines[249], "sec_299") {
			t.Fatalf("unexpected slice bounds: first=%s last=%s", lines[0], lines[249])
		}
	})

	t.Run("--all returns all 300 entries across active and rotated logs", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		cmd := &AuditCmd{Tail: 20, All: true}
		if err := cmd.runWith(tailAudit, &stdout, &stderr, false); err != nil {
			t.Fatalf("runWith: %v", err)
		}
		lines := strings.Split(strings.TrimSuffix(stdout.String(), "\n"), "\n")
		if len(lines) != 300 {
			t.Fatalf("got %d lines, want 300", len(lines))
		}
		if !strings.Contains(lines[0], "sec_000") || !strings.Contains(lines[299], "sec_299") {
			t.Fatalf("unexpected bounds: first=%s last=%s", lines[0], lines[299])
		}
	})
}

func TestAuditCmd_FiltersAppliedBeforeTail(t *testing.T) {
	baseTS := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	var allLines []string
	// Emit 25 denied events early, followed by 50 normal cli list events at the tail.
	for i := 0; i < 25; i++ {
		allLines = append(allLines, marshalAuditLine(t, AuditEvent{
			Timestamp:  baseTS.Add(time.Duration(i) * time.Second),
			Action:     ActionDenied,
			SecretName: fmt.Sprintf("denied_%02d", i),
			Caller:     "mcp",
			Message:    "not_found",
		}))
	}
	// Multi-secret mcp_run entry to test SecretNames matching.
	allLines = append(allLines, marshalAuditLine(t, AuditEvent{
		Timestamp:   baseTS.Add(30 * time.Second),
		Action:      ActionMCPRun,
		SecretNames: []string{"openai_key", "stripe_key"},
		Caller:      "mcp",
		Message:     "timed_out=false",
	}))
	for i := 0; i < 50; i++ {
		allLines = append(allLines, marshalAuditLine(t, AuditEvent{
			Timestamp:  baseTS.Add(time.Duration(100+i) * time.Second),
			Action:     ActionList,
			SecretName: "stripe_key",
			Caller:     "cli",
		}))
	}

	fakeRead := func(n int) ([]string, error) {
		if n <= 0 || n >= len(allLines) {
			return append([]string(nil), allLines...), nil
		}
		return append([]string(nil), allLines[len(allLines)-n:]...), nil
	}

	t.Run("-n 20 --action denied returns the last 20 denied entries despite 50 newer non-denied entries", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		cmd := &AuditCmd{Tail: 20, Action: ActionDenied}
		if err := cmd.runWith(fakeRead, &stdout, &stderr, false); err != nil {
			t.Fatalf("runWith: %v", err)
		}
		lines := strings.Split(strings.TrimSuffix(stdout.String(), "\n"), "\n")
		if len(lines) != 20 {
			t.Fatalf("got %d lines, want 20", len(lines))
		}
		if !strings.Contains(lines[0], "denied_05") || !strings.Contains(lines[19], "denied_24") {
			t.Fatalf("unexpected range: first=%s last=%s", lines[0], lines[19])
		}
	})

	t.Run("--secret matches both SecretName and SecretNames", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		cmd := &AuditCmd{All: true, Secret: "stripe_key"}
		if err := cmd.runWith(fakeRead, &stdout, &stderr, false); err != nil {
			t.Fatalf("runWith: %v", err)
		}
		lines := strings.Split(strings.TrimSuffix(stdout.String(), "\n"), "\n")
		if len(lines) != 51 {
			t.Fatalf("got %d lines, want 51 (1 mcp_run + 50 cli list)", len(lines))
		}
		if !strings.Contains(lines[0], `"action":"mcp_run"`) {
			t.Fatalf("expected mcp_run entry matching SecretNames first, got %s", lines[0])
		}
	})

	t.Run("--caller mcp combined with --secret", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		cmd := &AuditCmd{All: true, Caller: "mcp", Secret: "stripe_key"}
		if err := cmd.runWith(fakeRead, &stdout, &stderr, false); err != nil {
			t.Fatalf("runWith: %v", err)
		}
		lines := strings.Split(strings.TrimSuffix(stdout.String(), "\n"), "\n")
		if len(lines) != 1 || !strings.Contains(lines[0], `"action":"mcp_run"`) {
			t.Fatalf("expected 1 mcp_run line, got %v", lines)
		}
	})
}

func TestAuditCmd_TTYTableColorNoColorAndJSONOverride(t *testing.T) {
	baseTS := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	sample := []string{
		marshalAuditLine(t, AuditEvent{
			Timestamp:  baseTS,
			Action:     ActionSet,
			SecretName: "api_key",
			Caller:     "cli",
			Message:    "expires_at=2026-06-15T12:00:00Z",
		}),
		marshalAuditLine(t, AuditEvent{
			Timestamp:  baseTS.Add(time.Second),
			Action:     ActionDenied,
			SecretName: "api_key",
			Caller:     "mcp",
			Message:    "secret_expired",
		}),
		marshalAuditLine(t, AuditEvent{
			Timestamp: baseTS.Add(2 * time.Second),
			Action:    ActionRedactionDisabled,
			Caller:    "cli",
			Message:   "sh (+1 args)",
		}),
		marshalAuditLine(t, AuditEvent{
			Timestamp:   baseTS.Add(3 * time.Second),
			Action:      ActionNetworkAllowed,
			SecretNames: []string{"api_key", "other"},
			Caller:      "mcp",
			Message:     "sandbox=net-allowed",
		}),
	}
	fakeRead := func(int) ([]string, error) { return sample, nil }

	t.Run("TTY renders aligned table with ANSI emphasis on sensitive actions", func(t *testing.T) {
		t.Setenv("NO_COLOR", "")
		t.Setenv("TERM", "xterm-256color")
		var stdoutColor, stdoutPlain, stderr bytes.Buffer
		if err := (&AuditCmd{Tail: 20}).runWith(fakeRead, &stdoutColor, &stderr, true); err != nil {
			t.Fatalf("runWith color: %v", err)
		}
		out := stdoutColor.String()
		for _, hdr := range []string{"TIME", "CALLER", "ACTION", "SECRET", "DETAIL"} {
			if !strings.Contains(out, hdr) {
				t.Errorf("missing header %q:\n%s", hdr, out)
			}
		}
		if !strings.Contains(out, "\x1b[31mdenied\x1b[0m") {
			t.Errorf("expected red highlight on denied:\n%q", out)
		}
		if !strings.Contains(out, "\x1b[1;31mredaction_disabled\x1b[0m") {
			t.Errorf("expected bold-red highlight on redaction_disabled:\n%q", out)
		}
		if !strings.Contains(out, "\x1b[33mnetwork_allowed\x1b[0m") {
			t.Errorf("expected yellow highlight on network_allowed:\n%q", out)
		}
		if !strings.Contains(out, "api_key,other") {
			t.Errorf("expected joined SecretNames:\n%s", out)
		}

		// With NO_COLOR=1, ANSI escapes disappear and columns stay identically aligned.
		t.Setenv("NO_COLOR", "1")
		if err := (&AuditCmd{Tail: 20}).runWith(fakeRead, &stdoutPlain, &stderr, true); err != nil {
			t.Fatalf("runWith plain: %v", err)
		}
		if strings.Contains(stdoutPlain.String(), "\x1b[") {
			t.Fatalf("NO_COLOR=1 emitted ANSI escapes:\n%q", stdoutPlain.String())
		}
		if stripTestANSI(stdoutColor.String()) != stdoutPlain.String() {
			t.Fatalf("ANSI codes broke column alignment!\nstripped:\n%s\nplain:\n%s",
				stripTestANSI(stdoutColor.String()), stdoutPlain.String())
		}
	})

	t.Run("--json forces raw JSONL even on TTY", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		if err := (&AuditCmd{Tail: 20, JSON: true}).runWith(fakeRead, &stdout, &stderr, true); err != nil {
			t.Fatalf("runWith: %v", err)
		}
		want := strings.Join(sample, "\n") + "\n"
		if stdout.String() != want {
			t.Fatalf("--json output mismatch:\ngot:\n%s\nwant:\n%s", stdout.String(), want)
		}
	})

	t.Run("TTY empty audit prints stderr hint", func(t *testing.T) {
		emptyRead := func(int) ([]string, error) { return nil, nil }
		var stdout, stderr bytes.Buffer
		if err := (&AuditCmd{Tail: 20}).runWith(emptyRead, &stdout, &stderr, true); err != nil {
			t.Fatalf("runWith: %v", err)
		}
		if stdout.Len() != 0 {
			t.Fatalf("expected empty stdout, got %q", stdout.String())
		}
		if !strings.Contains(stderr.String(), "no audit entries") {
			t.Fatalf("expected empty hint on stderr, got %q", stderr.String())
		}

		stderr.Reset()
		if err := (&AuditCmd{Tail: 20, Action: ActionDenied}).runWith(emptyRead, &stdout, &stderr, true); err != nil {
			t.Fatalf("runWith filtered empty: %v", err)
		}
		if !strings.Contains(stderr.String(), "no matching audit entries") {
			t.Fatalf("expected filtered empty hint on stderr, got %q", stderr.String())
		}
	})
}

func TestAuditCmd_KongFlags(t *testing.T) {
	// Default (omitted --caller) must parse cleanly.
	var cli CLI
	p, err := kong.New(&cli)
	if err != nil {
		t.Fatalf("kong.New: %v", err)
	}
	if _, err := p.Parse([]string{"audit"}); err != nil {
		t.Fatalf("Parse default audit failed: %v", err)
	}
	if cli.Audit.Tail != 20 || cli.Audit.Caller != "" || cli.Audit.All || cli.Audit.JSON {
		t.Fatalf("unexpected defaults: %+v", cli.Audit)
	}

	var cli2 CLI
	p2, _ := kong.New(&cli2)
	if _, err := p2.Parse([]string{"audit", "-n", "500", "--all", "--json", "--caller", "mcp", "--action", "denied", "--secret", "foo"}); err != nil {
		t.Fatalf("Parse full flags failed: %v", err)
	}
	if cli2.Audit.Tail != 500 || !cli2.Audit.All || !cli2.Audit.JSON || cli2.Audit.Caller != "mcp" || cli2.Audit.Action != "denied" || cli2.Audit.Secret != "foo" {
		t.Fatalf("unexpected parsed AuditCmd: %+v", cli2.Audit)
	}

	var cli3 CLI
	p3, _ := kong.New(&cli3)
	if _, err := p3.Parse([]string{"audit", "--caller", "invalid"}); err == nil {
		t.Fatal("expected error for invalid --caller")
	}
}
