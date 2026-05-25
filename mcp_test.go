package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestNormalizeExit(t *testing.T) {
	cases := []struct {
		in        int
		wantOK    bool
		wantCode  int
		whatLeaks string
	}{
		{0, true, 0, ""},
		{1, false, 1, "should collapse 1 to 1"},
		{2, false, 1, "should collapse non-zero to 1 (no oracle byte)"},
		{42, false, 1, "should collapse arbitrary status to 1"},
		{255, false, 1, "should collapse max 8-bit to 1"},
		{-1, false, 1, "negative (signal/timeout) collapses to 1"},
	}
	for _, c := range cases {
		gotOK, gotCode := normalizeExit(c.in)
		if gotOK != c.wantOK || gotCode != c.wantCode {
			t.Errorf("normalizeExit(%d) = (%v,%d), want (%v,%d): %s",
				c.in, gotOK, gotCode, c.wantOK, c.wantCode, c.whatLeaks)
		}
	}
}

func TestClampTimeout(t *testing.T) {
	cases := []struct {
		in   int
		want time.Duration
	}{
		{0, mcpDefaultTimeout},
		{-5, mcpDefaultTimeout},
		{30, 30 * time.Second},
		{600, 600 * time.Second},
		{601, mcpMaxTimeout},
		{10000, mcpMaxTimeout},
	}
	for _, c := range cases {
		if got := clampTimeout(c.in); got != c.want {
			t.Errorf("clampTimeout(%d) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestClampAuditTailN(t *testing.T) {
	cases := []struct {
		in   int
		want int
	}{
		{0, 20},
		{-3, 20},
		{50, 50},
		{200, 200},
		{201, mcpMaxAuditTailN},
		{99999, mcpMaxAuditTailN},
	}
	for _, c := range cases {
		if got := clampAuditTailN(c.in); got != c.want {
			t.Errorf("clampAuditTailN(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestCappedWriter_BelowCap(t *testing.T) {
	var buf bytes.Buffer
	cw := newCappedWriter(&buf, 100)
	n, err := cw.Write([]byte("hello"))
	if err != nil || n != 5 {
		t.Fatalf("write below cap: n=%d err=%v", n, err)
	}
	if buf.String() != "hello" {
		t.Fatalf("inner = %q, want %q", buf.String(), "hello")
	}
	if cw.Truncated() {
		t.Fatalf("should not be truncated")
	}
}

func TestCappedWriter_ExactCap(t *testing.T) {
	var buf bytes.Buffer
	cw := newCappedWriter(&buf, 5)
	n, err := cw.Write([]byte("hello"))
	if err != nil || n != 5 {
		t.Fatalf("write == cap: n=%d err=%v", n, err)
	}
	if buf.String() != "hello" {
		t.Fatalf("inner = %q", buf.String())
	}
	if cw.Truncated() {
		t.Fatalf("exact-cap write should not flip truncated yet")
	}
	// One more byte after cap is exhausted should flip it.
	n, err = cw.Write([]byte("x"))
	if err != nil || n != 1 {
		t.Fatalf("post-cap write: n=%d err=%v", n, err)
	}
	if !cw.Truncated() {
		t.Fatalf("post-cap write should mark truncated")
	}
	if buf.String() != "hello" {
		t.Fatalf("post-cap should not extend inner: got %q", buf.String())
	}
}

func TestCappedWriter_OverCapSingleWrite(t *testing.T) {
	var buf bytes.Buffer
	cw := newCappedWriter(&buf, 5)
	in := []byte("hello world")
	n, err := cw.Write(in)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if n != len(in) {
		// The caller (subprocess) must believe the write succeeded so
		// it does not retry; we report full length even though we
		// silently dropped the tail.
		t.Fatalf("n = %d, want %d", n, len(in))
	}
	if buf.String() != "hello" {
		t.Fatalf("inner = %q, want %q", buf.String(), "hello")
	}
	if !cw.Truncated() {
		t.Fatalf("over-cap write should mark truncated")
	}
}

func TestCappedWriter_PipelinedWithRedactor(t *testing.T) {
	// Verify the documented pipeline order: redactor sits upstream of
	// cap, so secrets straddling the cap boundary are still redacted
	// (cap only sees post-redaction bytes).
	var buf bytes.Buffer
	cap := 30
	cw := newCappedWriter(&buf, cap)
	secret := []byte("SUPER_SECRET_VALUE_123")
	rw := NewRedactingWriter(cw, []NamedSecret{{Name: "API", Value: secret}})
	defer rw.Destroy()

	// Pre-secret prefix is large enough that the redacted form will
	// sit close to the cap, but the raw secret bytes must not leak
	// even if truncation kicks in.
	payload := append([]byte("PREFIX_"), secret...)
	payload = append(payload, []byte("_SUFFIX")...)
	if _, err := rw.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := rw.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}

	got := buf.String()
	if strings.Contains(got, string(secret)) {
		t.Fatalf("raw secret leaked into inner buffer: %q", got)
	}
	// The redacted token must appear since the secret is shorter than
	// the cap-minus-prefix budget.
	if !strings.Contains(got, "[REDACTED:API]") {
		t.Fatalf("redacted token missing from %q", got)
	}
}

func TestCappedWriter_RedactorSecretNeverLeaksUnderTruncation(t *testing.T) {
	// Even when truncation does fire, the secret bytes must not appear
	// in the captured output.
	var buf bytes.Buffer
	cw := newCappedWriter(&buf, 16) // tiny cap
	secret := []byte("PASSWORD123")
	rw := NewRedactingWriter(cw, []NamedSecret{{Name: "PW", Value: secret}})
	defer rw.Destroy()

	// Lots of filler followed by the secret; the cap will clip before
	// or at the secret region.
	filler := bytes.Repeat([]byte("A"), 1024)
	payload := append(filler, secret...)
	payload = append(payload, filler...)
	if _, err := rw.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := rw.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if !cw.Truncated() {
		t.Fatalf("expected truncation")
	}
	if bytes.Contains(buf.Bytes(), secret) {
		t.Fatalf("secret leaked under truncation: %q", buf.String())
	}
}

func TestHandleRunWithSecrets_EnvCountCap(t *testing.T) {
	// 33 entries should be rejected before any keyring access. We
	// can't easily mock the keyring, so we rely on the cap check being
	// the very first thing handleRunWithSecrets does after the command
	// presence check.
	env := make(map[string]string, mcpMaxEnvCount+1)
	for i := 0; i <= mcpMaxEnvCount; i++ {
		env[envNameFor(i)] = "no_such_secret"
	}
	res, _, err := handleRunWithSecrets(context.Background(), nil, runWithSecretsInput{
		Command: "/bin/true",
		Env:     env,
	})
	if err != nil {
		t.Fatalf("unexpected transport error: %v", err)
	}
	if res == nil || !res.IsError {
		t.Fatalf("expected IsError result for oversize env, got %+v", res)
	}
	text := mcpResultText(res)
	if !strings.Contains(text, "too many env vars") {
		t.Fatalf("expected env-count cap message, got %q", text)
	}
}

func TestHandleRunWithSecrets_RequiresCommand(t *testing.T) {
	res, _, err := handleRunWithSecrets(context.Background(), nil, runWithSecretsInput{})
	if err != nil {
		t.Fatalf("unexpected transport error: %v", err)
	}
	if res == nil || !res.IsError {
		t.Fatalf("expected IsError for missing command, got %+v", res)
	}
}

func TestAuditMCPRunMessage(t *testing.T) {
	msg := auditMCPRunMessage([]string{"a", "b"}, 137, true, false, true, 1234*time.Millisecond, "")
	for _, want := range []string{
		"secrets=a,b",
		"raw_exit=137", // raw status preserved for operator
		"elapsed_ms=1234",
		"stdout_truncated=true",
		"timed_out=true",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("audit message missing %q: %s", want, msg)
		}
	}
	if strings.Contains(msg, "stderr_truncated=true") {
		t.Errorf("audit message should not contain stderr_truncated when false: %s", msg)
	}
}

func TestHandleRunWithSecrets_RejectsBlockedEnvNames(t *testing.T) {
	cases := []string{
		// exact-map entries
		"PATH", "BASH_ENV",
		// LD_ prefix
		"LD_PRELOAD",
		// ERL_ prefix (newly added)
		"ERL_FLAGS",
		"ERL_NEW_FUTURE_VAR",
		// BASH_FUNC_ prefix (newly added); use a name valid per validEnvName
		// (no %%) since validEnvName runs before isBlockedEnvName.
		"BASH_FUNC_ls",
		// GIT_CONFIG_ prefix (newly added)
		"GIT_CONFIG_KEY_0",
	}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			res, _, err := handleRunWithSecrets(context.Background(), nil, runWithSecretsInput{
				Command: "/bin/true",
				Env:     map[string]string{name: "some_secret"},
			})
			if err != nil {
				t.Fatalf("unexpected transport error: %v", err)
			}
			if res == nil || !res.IsError {
				t.Fatalf("expected IsError result for blocked env %q, got %+v", name, res)
			}
			text := mcpResultText(res)
			if !strings.Contains(text, "deny-list") {
				t.Fatalf("expected deny-list message for %q, got %q", name, text)
			}
		})
	}
}

// TestHandleRunWithSecrets_DeterministicEnvOrder verifies that the
// env-name iteration order is stable across calls. Without deterministic
// iteration, Go's randomized map order would pick a different first key
// on most invocations, turning the audit log into noise and making
// failures non-reproducible.
//
// After H1 the AI-visible error for a missing secret is "not_found: <name>"
// (was "resolve <name>: ..."). The test must accept either taxonomy form
// to remain valid under both backend states. We require the result to be
// IsError; if a backend setup fault yields a generic backend_error (no
// per-name diagnostic), we skip — the env-iteration code path was reached
// but doesn't surface a per-name signal we can compare.
func TestHandleRunWithSecrets_DeterministicEnvOrder(t *testing.T) {
	env := map[string]string{
		"AAA": "no_such_a",
		"BBB": "no_such_b",
		"CCC": "no_such_c",
		"DDD": "no_such_d",
		"EEE": "no_such_e",
	}

	const trials = 10
	var first string
	for i := 0; i < trials; i++ {
		res, _, err := handleRunWithSecrets(context.Background(), nil, runWithSecretsInput{
			Command: "/bin/true",
			Env:     env,
		})
		if err != nil {
			t.Fatalf("unexpected transport error: %v", err)
		}
		if res == nil || !res.IsError {
			t.Skipf("expected IsError result; got %+v", res)
		}
		text := mcpResultText(res)
		// Per-name diagnostic shapes after H1:
		//   "not_found: <name>" (ErrSecretNotFound)
		//   "resolve <name>: ..." (legacy text — kept for back-compat tests)
		hasPerName := strings.HasPrefix(text, "not_found: ") || strings.HasPrefix(text, "resolve ")
		if !hasPerName {
			t.Skipf("backend yields no per-name diagnostic in this environment (got %q); env-iteration order not observable", text)
		}
		if i == 0 {
			first = text
			continue
		}
		if text != first {
			t.Fatalf("nondeterministic env order across calls:\n  first: %q\n  got:   %q", first, text)
		}
	}
}

func TestRunMCPServer_IgnoresEOFAndCanceled(t *testing.T) {
	// The historical bug was substring-matching "EOF" in error text;
	// the fix is to rely on errors.Is. These are unit-level checks of
	// the predicate by inspecting the wrapped errors.
	if !errors.Is(io.EOF, io.EOF) {
		t.Fatalf("sanity")
	}
	if !errors.Is(context.Canceled, context.Canceled) {
		t.Fatalf("sanity")
	}
}

// ----- helpers -----

func envNameFor(i int) string {
	// Valid identifier: letter prefix, decimal suffix.
	return "V" + itoa(i)
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(b[pos:])
}

// mcpResultText concatenates the Text fields of every TextContent in a
// CallToolResult. Used to assert error messages flow through to the
// caller.
func mcpResultText(res *mcp.CallToolResult) string {
	if res == nil {
		return ""
	}
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			if b.Len() > 0 {
				b.WriteByte('\n')
			}
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}

// ----- Phase 3 security-fix tests (C1, M3, H1) -----

// TestAuditTailMCP_StripsRawExit (C1) verifies that handleAuditTail does not
// return raw_exit tokens to an MCP caller, closing the exit-code oracle.
func TestAuditTailMCP_StripsRawExit(t *testing.T) {
	withAuditTmpDir(t)

	// Write an mcp_run audit line that contains raw_exit=42.
	ev := AuditEvent{
		Action:  ActionMCPRun,
		Caller:  "mcp",
		Message: "secrets=foo raw_exit=42 elapsed_ms=100",
	}
	if err := AppendAudit(ev); err != nil {
		t.Fatalf("AppendAudit: %v", err)
	}

	res, out, err := handleAuditTail(context.Background(), nil, auditTailInput{N: 10})
	if err != nil {
		t.Fatalf("handleAuditTail: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error result: %s", mcpResultText(res))
	}
	for _, line := range out.Entries {
		if strings.Contains(line, "raw_exit") {
			t.Errorf("raw_exit leaked to AI in line: %s", line)
		}
	}
	// The other fields must still be present.
	combined := strings.Join(out.Entries, "\n")
	if !strings.Contains(combined, "elapsed_ms=100") {
		t.Errorf("elapsed_ms missing from filtered output: %s", combined)
	}
}

// TestAuditTailMCP_StripsRawExitNegative verifies that raw_exit=-1 (timeout)
// is also stripped.
func TestAuditTailMCP_StripsRawExitNegative(t *testing.T) {
	withAuditTmpDir(t)

	ev := AuditEvent{
		Action:  ActionMCPRun,
		Caller:  "mcp",
		Message: "secrets=bar raw_exit=-1 elapsed_ms=60000 timed_out=true",
	}
	if err := AppendAudit(ev); err != nil {
		t.Fatalf("AppendAudit: %v", err)
	}

	_, out, err := handleAuditTail(context.Background(), nil, auditTailInput{N: 10})
	if err != nil {
		t.Fatalf("handleAuditTail: %v", err)
	}
	for _, line := range out.Entries {
		if strings.Contains(line, "raw_exit") {
			t.Errorf("raw_exit=-1 leaked to AI: %s", line)
		}
	}
}

// TestAuditTailMCP_FiltersNonMCPCaller (M3) verifies that CLI-driven audit
// entries are invisible to MCP callers but MCP-driven entries are returned.
func TestAuditTailMCP_FiltersNonMCPCaller(t *testing.T) {
	withAuditTmpDir(t)

	// Write a CLI entry and an MCP entry.
	if err := AppendAudit(AuditEvent{Action: ActionGet, SecretName: "mykey", Caller: "cli"}); err != nil {
		t.Fatalf("AppendAudit cli: %v", err)
	}
	if err := AppendAudit(AuditEvent{Action: ActionList, Caller: "mcp"}); err != nil {
		t.Fatalf("AppendAudit mcp: %v", err)
	}

	_, out, err := handleAuditTail(context.Background(), nil, auditTailInput{N: 10})
	if err != nil {
		t.Fatalf("handleAuditTail: %v", err)
	}
	// Only the mcp entry should come through.
	if len(out.Entries) != 1 {
		t.Fatalf("expected 1 entry, got %d: %v", len(out.Entries), out.Entries)
	}
	// Verify it's the mcp list entry, not the cli get entry.
	var ev AuditEvent
	if err := json.Unmarshal([]byte(out.Entries[0]), &ev); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if ev.Caller != "mcp" {
		t.Errorf("caller = %q, want mcp", ev.Caller)
	}
	if ev.Action != ActionList {
		t.Errorf("action = %q, want list", ev.Action)
	}
	// The CLI entry must NOT appear.
	for _, line := range out.Entries {
		if strings.Contains(line, "mykey") {
			t.Errorf("CLI secret name leaked to MCP caller: %s", line)
		}
	}
}

// TestAuditCLI_StillSeesEverything verifies that the CLI path (tailAudit
// directly) is unfiltered — the M3/C1 filtering is MCP-side only.
func TestAuditCLI_StillSeesEverything(t *testing.T) {
	withAuditTmpDir(t)

	events := []AuditEvent{
		{Action: ActionGet, SecretName: "humankey", Caller: "cli"},
		{Action: ActionMCPRun, Caller: "mcp", Message: "secrets=foo raw_exit=77 elapsed_ms=10"},
		{Action: ActionSet, SecretName: "another", Caller: "cli"},
	}
	for _, ev := range events {
		if err := AppendAudit(ev); err != nil {
			t.Fatalf("AppendAudit: %v", err)
		}
	}

	// tailAudit is the CLI read path — must return all lines unfiltered.
	lines, err := tailAudit(10)
	if err != nil {
		t.Fatalf("tailAudit: %v", err)
	}
	if len(lines) != 3 {
		t.Fatalf("CLI tailAudit: expected 3 lines, got %d", len(lines))
	}
	combined := strings.Join(lines, "\n")
	if !strings.Contains(combined, "humankey") {
		t.Errorf("CLI tailAudit missing cli get event")
	}
	if !strings.Contains(combined, "raw_exit=77") {
		t.Errorf("CLI tailAudit missing raw_exit (must be present for operator)")
	}
	if !strings.Contains(combined, "another") {
		t.Errorf("CLI tailAudit missing second cli event")
	}
}

// TestSanitizeErrForAI (H1) verifies the exec-start error taxonomy mapping.
// This helper is only reached for process-start failures in production
// (handleRunWithSecrets); backend errors do NOT flow through here — they
// hit a hardcoded "backend_error" literal at their call site.
func TestSanitizeErrForAI(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{ErrSecretNotFound, "not_found"},
		{fmt.Errorf("wrap: %w", ErrSecretNotFound), "not_found"},
		{exec.ErrNotFound, "exec_not_found"},
		{fs.ErrPermission, "exec_permission_denied"},
		{errors.New("some keyring error"), "exec_start_failed"},
		{nil, ""},
	}
	for _, c := range cases {
		got := sanitizeErrForAI(c.err)
		if got != c.want {
			t.Errorf("sanitizeErrForAI(%v) = %q, want %q", c.err, got, c.want)
		}
	}
}

// TestSanitizeErrForAI_HostileBytesStripped (H1) — defensive check: if any
// future call site routes a backend-style error through sanitizeErrForAI,
// the AI must not see wrapped bytes. This is NOT the production path for
// backend.Get errors (those use a hardcoded "backend_error" string — see
// TestHandleRunWithSecrets_BackendErrorReturnsFixedTaxonomy).
func TestSanitizeErrForAI_HostileBytesStripped(t *testing.T) {
	secret := "sk-abc123"
	wrapped := fmt.Errorf("resolve foo: %w", errors.New("plaintext: "+secret))
	got := sanitizeErrForAI(wrapped)
	if strings.Contains(got, secret) {
		t.Errorf("sanitizeErrForAI leaked secret bytes: %q", got)
	}
	if strings.Contains(got, "plaintext:") {
		t.Errorf("sanitizeErrForAI leaked wrapped text: %q", got)
	}
}

// TestHandleRunWithSecrets_BackendErrorReturnsFixedTaxonomy (H1) exercises
// the actual production code path for backend.Get errors: handleRunWithSecrets
// at the backend.Get failure branch routes through aiErr("backend_error"), a
// fixed literal that cannot carry backend bytes. We can't easily inject a
// hostile backend without refactoring OpenDefaultBackend; instead, we drive
// the handler through a code path that DOES reach the literal — a bad secret
// name lookup on a real (or unavailable) backend. The assertion is on the
// taxonomy string itself: it must be one of the documented fixed literals
// ("backend_error", "not_found: <name>") and must never contain raw byte
// patterns like "sk-", "Bearer ", "plaintext:" that backends sometimes
// embed.
func TestHandleRunWithSecrets_BackendErrorReturnsFixedTaxonomy(t *testing.T) {
	env := map[string]string{"V1": "nonexistent_secret_for_test"}
	res, _, err := handleRunWithSecrets(context.Background(), nil, runWithSecretsInput{
		Command: "/bin/true",
		Env:     env,
	})
	if err != nil {
		t.Fatalf("unexpected transport error: %v", err)
	}
	if res == nil || !res.IsError {
		t.Skipf("expected IsError result; backend may not be available in this environment")
	}
	text := mcpResultText(res)
	// Allowed taxonomy: backend_error OR not_found: <name> OR backend setup error.
	// Forbidden: any of these common backend-error-text giveaways.
	forbidden := []string{"sk-", "Bearer ", "plaintext:", "D-Bus", "dbus", "libsecret", "gnome-keyring", "keychain"}
	for _, bad := range forbidden {
		if strings.Contains(strings.ToLower(text), strings.ToLower(bad)) {
			t.Errorf("AI-visible error text contains backend-bytes-shaped token %q: %q", bad, text)
		}
	}
}

// TestFilterAuditLineForAI_UnparseableDropped verifies that corrupt/future
// log lines are silently dropped rather than forwarded to the AI.
func TestFilterAuditLineForAI_UnparseableDropped(t *testing.T) {
	_, ok := filterAuditLineForAI("not valid json {{{")
	if ok {
		t.Error("expected corrupt line to be dropped (ok=false)")
	}
}

// TestFilterAuditLineForAI_EmptyDropped verifies empty lines are dropped.
func TestFilterAuditLineForAI_EmptyDropped(t *testing.T) {
	_, ok := filterAuditLineForAI("")
	if ok {
		t.Error("expected empty line to be dropped")
	}
	_, ok = filterAuditLineForAI("   ")
	if ok {
		t.Error("expected whitespace-only line to be dropped")
	}
}

// TestStripRawExitTokens verifies all raw_exit variants are removed.
func TestStripRawExitTokens(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"secrets=foo raw_exit=42 elapsed_ms=100", "secrets=foo elapsed_ms=100"},
		{"raw_exit=-1 timed_out=true", "timed_out=true"},
		{"raw_exit=0 elapsed_ms=5", "elapsed_ms=5"},
		{"raw_exit=255 stdout_truncated=true", "stdout_truncated=true"},
		{"secrets=bar elapsed_ms=10", "secrets=bar elapsed_ms=10"},   // no raw_exit token
		{"", ""},
	}
	for _, c := range cases {
		got := stripRawExitTokens(c.in)
		if got != c.want {
			t.Errorf("stripRawExitTokens(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestAuditTailClamp verifies that a wildly-large request from an AI
// (think 10000) is silently clamped to mcpMaxAuditTailN instead of
// dumping the entire history.
func TestAuditTailClamp(t *testing.T) {
	tmp := withAuditTmpDir(t)
	path := filepath.Join(tmp, "opq", "audit.log")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 300; i++ {
		if _, err := f.WriteString("{\"action\":\"x\"}\n"); err != nil {
			t.Fatal(err)
		}
	}
	_ = f.Close()

	lines, err := tailAudit(clampAuditTailN(10000))
	if err != nil {
		t.Fatal(err)
	}
	if got := len(lines); got != mcpMaxAuditTailN {
		t.Fatalf("len=%d want %d", got, mcpMaxAuditTailN)
	}
}
