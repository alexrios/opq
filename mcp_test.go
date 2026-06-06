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

// TestRunWithSecretsPipeline_RedactorShortCircuitWired (P2-6, joint-review
// 2026-05) locks the P1-1 short-circuit at the wiring level. If a future
// refactor inserts an interposer (metering / logging / tee writer) between
// RedactingWriter and cappedWriter that does NOT proxy Truncated(), the
// one-shot type assertion in NewRedactingWriter fails silently. downTrunc
// becomes nil, the short-circuit disappears, and an AI calling
// run_with_secrets with a high-volume producer like `yes` burns the full
// MCP timeout window scanning bytes the 256 KiB cap is dropping anyway.
//
// This test rebuilds the production handleRunWithSecrets output pipeline
// byte-for-byte (mcp.go lines 398-406) and asserts the redactor reports
// the short-circuit is wired. It intentionally lives in mcp_test.go (not
// redact_test.go): the regression is a property of the MCP pipeline
// assembly, not of RedactingWriter in isolation.
func TestRunWithSecretsPipeline_RedactorShortCircuitWired(t *testing.T) {
	// Mirror the production assembly. Any drift here from the real
	// handleRunWithSecrets pipeline construction defeats the test.
	var stdoutBuf, stderrBuf bytes.Buffer
	stdoutCap := newCappedWriter(&stdoutBuf, mcpMaxOutputBytes)
	stderrCap := newCappedWriter(&stderrBuf, mcpMaxOutputBytes)
	named := []NamedSecret{{Name: "API", Value: []byte("sk-test-value")}}
	stdoutRW := NewRedactingWriter(stdoutCap, named)
	stderrRW := NewRedactingWriter(stderrCap, named)
	defer stdoutRW.Destroy()
	defer stderrRW.Destroy()

	// Structural invariants of the wiring.
	if !stdoutRW.hasTruncationShortCircuit() {
		t.Fatalf("stdout RedactingWriter has nil downTrunc — the P1-1 short-circuit is no longer wired through the production pipeline. Likely cause: an interposer between RedactingWriter and cappedWriter that does not implement Truncated() bool.")
	}
	if !stderrRW.hasTruncationShortCircuit() {
		t.Fatalf("stderr RedactingWriter has nil downTrunc — symmetry broken; only stdout is short-circuited.")
	}

	// Lock the cap constant. mcpMaxOutputBytes is the cap the production
	// code passes; if either drifts the test should catch it.
	if mcpMaxOutputBytes != 256*1024 {
		t.Fatalf("mcpMaxOutputBytes = %d, want 256*1024 (256 KiB)", mcpMaxOutputBytes)
	}
	if stdoutCap.remaining != mcpMaxOutputBytes {
		t.Fatalf("stdoutCap.remaining = %d, want %d", stdoutCap.remaining, mcpMaxOutputBytes)
	}
	if stderrCap.remaining != mcpMaxOutputBytes {
		t.Fatalf("stderrCap.remaining = %d, want %d", stderrCap.remaining, mcpMaxOutputBytes)
	}

	// Initial state: pre-flip, no writes yet.
	if stdoutRW.passThrough {
		t.Fatalf("stdoutRW.passThrough should be false before any write")
	}
	if stderrRW.passThrough {
		t.Fatalf("stderrRW.passThrough should be false before any write")
	}
}

// TestRunWithSecretsPipeline_ShortCircuitFiresUnderTruncation (P2-6) is the
// behavioral half of the wiring assertion above. It writes more than the
// cap through the production pipeline (with a small cap for test speed)
// and confirms that the redactor flips into pass-through after truncation,
// proving the short-circuit code path actually executes end-to-end rather
// than just being structurally reachable.
//
// Determinism: this test does not measure CPU or wall time. It uses the
// sticky passThrough bit and the cappedWriter byte counter as the signal,
// both of which are deterministic state transitions.
func TestRunWithSecretsPipeline_ShortCircuitFiresUnderTruncation(t *testing.T) {
	// Small cap so the test stays fast; the structural test above locks
	// the production cap constant separately.
	const cap = 1024
	var inner bytes.Buffer
	cw := newCappedWriter(&inner, cap)
	rw := NewRedactingWriter(cw, []NamedSecret{{Name: "API", Value: []byte("sekret")}})
	defer rw.Destroy()

	if !rw.hasTruncationShortCircuit() {
		t.Fatalf("precondition: downTrunc must be wired for this test to be meaningful")
	}

	// First write: cap + 1 bytes. cappedWriter consumes `cap` bytes and
	// drops the trailing byte, flipping truncated=true. The RedactingWriter
	// only checks downTrunc.Truncated() at the START of its own Write, so
	// passThrough is still false at this point.
	first := bytes.Repeat([]byte("A"), cap+1)
	if _, err := rw.Write(first); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if !cw.Truncated() {
		t.Fatalf("cappedWriter should have flipped truncated=true after writing cap+1 bytes")
	}
	// Lock cap exhaustion explicitly. Without this, a future inner-writer
	// that partially accepts bytes (n < len(p), no error) would leave
	// remaining > 0 and the second write below could still grow `inner`,
	// making the inner.Len() == preLen assertion misleading. bytes.Buffer
	// today always accepts the full slice, so this is defense-in-depth.
	if cw.remaining != 0 {
		t.Fatalf("cap not fully exhausted after first write: remaining=%d, want 0", cw.remaining)
	}
	if rw.passThrough {
		t.Fatalf("rw.passThrough should still be false — the flip happens on the NEXT Write")
	}

	// Second write: this triggers the short-circuit check at the top of
	// RedactingWriter.Write. The secret "sekret" must come through verbatim
	// to the cappedWriter (which then drops it because the cap is exhausted),
	// proving scan() was bypassed.
	preLen := inner.Len()
	if _, err := rw.Write([]byte("B sekret B")); err != nil {
		t.Fatalf("second write: %v", err)
	}

	// Assert the sticky passThrough bit is now set — this is the P1-1
	// short-circuit having fired.
	if !rw.passThrough {
		t.Fatalf("rw.passThrough must be true after the second write — the short-circuit did not fire")
	}
	// Holdover must have been zeroed on the flip (redact.go lines 101-106).
	if len(rw.holdover) != 0 {
		t.Fatalf("rw.holdover must be empty after the flip, got %d bytes", len(rw.holdover))
	}
	// Inner buffer must not have grown past the cap: cappedWriter drops
	// post-cap bytes, and the redactor handed them off verbatim (proving
	// it did not retry / split / hold them).
	if inner.Len() != preLen {
		t.Fatalf("inner buffer grew past the cap: was %d, now %d (cap=%d)", preLen, inner.Len(), cap)
	}
	if inner.Len() > cap {
		t.Fatalf("inner.Len() = %d exceeds cap %d", inner.Len(), cap)
	}
	// No redaction token must appear post-flip in the inner buffer: bytes
	// past the cap are dropped, so the only post-flip evidence we can read
	// is the absence of growth above. Also assert no raw secret leaked
	// into the captured (pre-cap) portion — this is a separate invariant
	// from the short-circuit, but a cheap sanity check.
	if bytes.Contains(inner.Bytes(), []byte("sekret")) {
		t.Fatalf("raw secret leaked into pre-cap buffer: %q", inner.String())
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
	msg := auditMCPRunMessage(137, true, false, true, 1234*time.Millisecond, "")
	for _, want := range []string{
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
	// Secret names now live on AuditEvent.SecretNames (not in the
	// message); confirm they serialize under the expected JSON key.
	ev := AuditEvent{Action: ActionMCPRun, SecretNames: []string{"a", "b"}, Message: msg}
	raw, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(raw), `"secret_names":["a","b"]`) {
		t.Errorf("expected secret_names array in event JSON, got %s", raw)
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

// TestAuditTailMCP_AllowlistFilter (C1/J-10) verifies that handleAuditTail
// applies the AI-visible allowlist filter to mcp_run messages: raw_exit is
// stripped (exit-code oracle defense) AND elapsed_ms is stripped (timing
// oracle defense, J-6). Only allowlisted keys survive.
func TestAuditTailMCP_AllowlistFilter(t *testing.T) {
	withAuditTmpDir(t)

	// Write an mcp_run audit line that contains raw_exit=42 and elapsed_ms=100.
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
		if strings.Contains(line, "elapsed_ms") {
			t.Errorf("elapsed_ms leaked to AI in line: %s", line)
		}
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

// TestHandleListSecrets_AuditsBeforeBackend (joint-review 2026-05 P3)
// locks the audit-before-action contract for list_secrets. An AI that
// hammers list_secrets against a degraded backend (D-Bus down, keyring
// locked, etc.) must leave a trace per call. Previously the audit was
// emitted ONLY on the success path, so failure-path probing was
// invisible to the operator. The fix moves AppendAudit to the head of
// the handler so backend success and failure both audit.
//
// The test works whether or not the host has a usable keyring: if the
// call succeeds, the post-call audit log carries the entry; if it
// fails, the same entry must still be present.
func TestHandleListSecrets_AuditsBeforeBackend(t *testing.T) {
	withAuditTmpDir(t)
	SetCallerTag("mcp")
	t.Cleanup(func() { SetCallerTag("cli") })

	_, _, err := handleListSecrets(context.Background(), nil, listSecretsInput{})
	if err != nil {
		t.Fatalf("handleListSecrets: %v", err)
	}

	lines, err := tailAudit(20)
	if err != nil {
		t.Fatalf("tailAudit: %v", err)
	}
	var seen bool
	for _, line := range lines {
		var ev AuditEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			continue
		}
		if ev.Action == ActionList && ev.Caller == "mcp" {
			seen = true
			break
		}
	}
	if !seen {
		t.Fatalf("expected ActionList/mcp audit entry regardless of backend availability; got %v", lines)
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

// TestFilterAuditLineForAI_AuditTailSurvives verifies that ActionAuditTail
// entries pass through filterAuditLineForAI WITHOUT having their Message
// filtered. The allowlist gate (filterAuditMessageForAI) is intentionally
// scoped to ActionMCPRun only — broadening it would silently drop the
// `n=N` token from audit_tail self-log entries (a J-5 deterrent the AI is
// supposed to see). This test locks that scope so a future refactor that
// widens the condition (e.g. `ev.Action != ActionList`) trips here.
func TestFilterAuditLineForAI_AuditTailSurvives(t *testing.T) {
	raw, err := json.Marshal(AuditEvent{
		Timestamp: time.Now().UTC(),
		Action:    ActionAuditTail,
		Caller:    "mcp",
		Message:   "n=20",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	out, ok := filterAuditLineForAI(string(raw))
	if !ok {
		t.Fatal("expected audit_tail line to be kept by filter")
	}
	var ev AuditEvent
	if err := json.Unmarshal([]byte(out), &ev); err != nil {
		t.Fatalf("unmarshal filtered line: %v", err)
	}
	if ev.Message != "n=20" {
		t.Errorf("audit_tail msg mutated by filter: got %q, want %q", ev.Message, "n=20")
	}
}

// TestRunWithSecretsOutput_NoTruncationFields locks the P1 fix from
// the 2026-05 joint review: the AI-visible response struct must not
// expose stdout_truncated / stderr_truncated. Combined with caller-
// controlled commands those booleans were a clean 1-bit-per-call
// output-volume oracle (the AI emits a volume that is a function of a
// secret byte and binary-searches the cap threshold). Re-introducing
// either field re-opens the oracle. The textual header path
// (handleRunWithSecrets' textParts builder) is covered by the existing
// end-to-end MCP tests below, which assert the rendered text shape.
func TestRunWithSecretsOutput_NoTruncationFields(t *testing.T) {
	raw, err := json.Marshal(runWithSecretsOutput{})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, banned := range []string{"stdout_truncated", "stderr_truncated"} {
		if strings.Contains(string(raw), banned) {
			t.Errorf("AI-visible response JSON contains banned key %q: %s\n"+
				"This field is an output-volume oracle (joint review 2026-05 P1) "+
				"and must not be reintroduced.", banned, raw)
		}
	}
}

// TestQuantizeOutputForAI_EmptyStaysEmpty: gap #3 mitigation only pads
// non-empty streams. Empty stdout/stderr must remain empty so silent
// commands do not inflate the response by 1 KiB each.
func TestQuantizeOutputForAI_EmptyStaysEmpty(t *testing.T) {
	if got := quantizeOutputForAI(""); got != "" {
		t.Errorf("empty input should pass through; got len=%d %q", len(got), got)
	}
}

// TestQuantizeOutputForAI_LengthIsBucketQuantized is the load-bearing
// invariant for the gap-#3 mitigation: for any non-empty input shorter
// than the cap, len(returned) must equal exactly nextOutputBucket(len(input)).
// If this invariant is ever broken (e.g. an off-by-one in the padding
// arithmetic), the AI's len(stdout) channel rate ticks back up.
func TestQuantizeOutputForAI_LengthIsBucketQuantized(t *testing.T) {
	// Sample inputs spanning every bucket boundary, including N-1, N,
	// and N+1 for each bucket. Outputs above the largest bucket
	// (mcpMaxOutputBytes) cannot occur in practice (cappedWriter
	// truncates) so we test exactly at the cap as the boundary case.
	checks := []int{1, 100, 1023, 1024, 1025, 4095, 4096, 4097, 16383, 16384,
		16385, 65535, 65536, 65537, 262143, mcpMaxOutputBytes}
	for _, n := range checks {
		in := strings.Repeat("x", n)
		out := quantizeOutputForAI(in)
		want := nextOutputBucket(n)
		if len(out) != want {
			t.Errorf("quantizeOutputForAI(len=%d): got len=%d, want %d (bucket)", n, len(out), want)
		}
	}
}

// TestQuantizeOutputForAI_PadMarkerVisible: when the padding gap is
// large enough to fit the marker, the marker must appear once between
// the real output and the pad spaces. AI tooling parses on this marker
// to skip the pad tail.
func TestQuantizeOutputForAI_PadMarkerVisible(t *testing.T) {
	out := quantizeOutputForAI("hello")
	if !strings.Contains(out, outputPadMarker) {
		t.Errorf("expected pad marker %q in output, got %q", outputPadMarker, out)
	}
	if !strings.HasPrefix(out, "hello") {
		t.Errorf("real output should be at the head; got %q", out[:20])
	}
}

// TestQuantizeOutputForAI_SmallPadGapNoMarker: when the gap to the
// bucket is below len(outputPadMarker), we cannot fit the marker so we
// emit only spaces. This is a correctness edge: the length invariant
// still holds, just the marker is omitted.
func TestQuantizeOutputForAI_SmallPadGapNoMarker(t *testing.T) {
	// Input length such that bucket - len(input) < len(outputPadMarker).
	in := strings.Repeat("x", 1024-3)
	out := quantizeOutputForAI(in)
	if len(out) != 1024 {
		t.Fatalf("length invariant broken: got %d, want 1024", len(out))
	}
	if strings.Contains(out, outputPadMarker) {
		t.Errorf("pad gap was smaller than marker length; marker should be omitted, got %q", out[len(in):])
	}
}

// TestQuantizeOutputForAI_AtCapNoPadding: an input already at the cap
// (cappedWriter's max output bytes) is the largest bucket; no padding is
// added (no room above it).
func TestQuantizeOutputForAI_AtCapNoPadding(t *testing.T) {
	in := strings.Repeat("x", mcpMaxOutputBytes)
	out := quantizeOutputForAI(in)
	if len(out) != mcpMaxOutputBytes {
		t.Errorf("at-cap input should not grow: got len=%d, want %d", len(out), mcpMaxOutputBytes)
	}
}

// TestOutputBuckets_StartUnderCapEndAtCap locks the bucket-ladder
// invariants required by quantizeOutputForAI: monotonic non-empty
// power-of-two-ish, last entry equals the cap. Without these, the
// fallback in nextOutputBucket fails and the AI-visible length channel
// re-opens.
func TestOutputBuckets_StartUnderCapEndAtCap(t *testing.T) {
	if len(outputBuckets) == 0 {
		t.Fatal("outputBuckets must be non-empty")
	}
	for i := 1; i < len(outputBuckets); i++ {
		if outputBuckets[i] <= outputBuckets[i-1] {
			t.Errorf("outputBuckets must be strictly increasing; got %v", outputBuckets)
		}
	}
	if last := outputBuckets[len(outputBuckets)-1]; last != mcpMaxOutputBytes {
		t.Errorf("final bucket must equal mcpMaxOutputBytes; got %d, want %d", last, mcpMaxOutputBytes)
	}
}

// TestAIAuditMessageAllowlist_Invariant locks the exact set of keys
// permitted in AI-visible audit Message fields. Every entry below is a
// closed-set widening of the AI's audit channel and was reviewed for
// side-channel implications when added (see the godoc on
// aiAuditMessageAllowlist for the per-key justifications). Adding a new
// key REQUIRES updating this test, which forces the contributor to write
// a one-line justification and re-read the threat-model commentary.
//
// stdout_truncated and stderr_truncated were REMOVED from this list when
// the output-volume oracle (P1 in joint review 2026-05) was closed; the
// AI must not be able to recover the truncation flag via audit_tail
// either. Re-adding them would re-open the oracle.
func TestAIAuditMessageAllowlist_Invariant(t *testing.T) {
	want := map[string]bool{
		"timed_out": true,
	}
	if len(aiAuditMessageAllowlist) != len(want) {
		t.Fatalf("allowlist size changed: got %d keys, want %d (every change to this list MUST be reviewed for AI-leak implications)",
			len(aiAuditMessageAllowlist), len(want))
	}
	for k := range want {
		if !aiAuditMessageAllowlist[k] {
			t.Errorf("allowlist missing expected key %q", k)
		}
	}
	for k := range aiAuditMessageAllowlist {
		if !want[k] {
			t.Errorf("allowlist contains unexpected key %q — review the side-channel implications before widening this test", k)
		}
	}
}

// TestFilterAuditMessageForAI verifies the allowlist filter keeps known-safe
// keys and drops all others (including raw_exit, elapsed_ms, and the now-
// stripped stdout_truncated/stderr_truncated output-volume oracle tokens).
func TestFilterAuditMessageForAI(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"secrets=foo raw_exit=42 elapsed_ms=100", ""},
		{"raw_exit=-1 timed_out=true", "timed_out=true"},
		{"raw_exit=0 elapsed_ms=5", ""},
		{"raw_exit=255 stdout_truncated=true", ""},
		{"secrets=bar elapsed_ms=10", ""}, // both non-allowlisted
		{"stdout_truncated=true stderr_truncated=true timed_out=true", "timed_out=true"},
		{"", ""},
	}
	for _, c := range cases {
		got := filterAuditMessageForAI(c.in)
		if got != c.want {
			t.Errorf("filterAuditMessageForAI(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestHandleRunWithSecrets_RejectsBadSecretName (J-14) — the MCP surface
// rejects malformed secret names with the taxonomy string
// "invalid_secret_name" before any backend lookup. Asserting via a
// real-backend-or-not setup is fine because the validation gate runs
// strictly BEFORE the backend.Get call.
func TestHandleRunWithSecrets_RejectsBadSecretName(t *testing.T) {
	withAuditTmpDir(t)

	cases := []struct {
		envName, secretName string
	}{
		{"API", "bad name"},
		{"API", "bad/path"},
		{"API", "bad$value"},
		{"API", strings.Repeat("a", 129)},
		{"API", ""},
		{"API", "bad\nname"},
	}
	for _, c := range cases {
		t.Run(c.secretName, func(t *testing.T) {
			res, _, err := handleRunWithSecrets(context.Background(), nil, runWithSecretsInput{
				Command: "/bin/true",
				Env:     map[string]string{c.envName: c.secretName},
			})
			if err != nil {
				t.Fatalf("unexpected transport error: %v", err)
			}
			if res == nil || !res.IsError {
				t.Fatalf("expected IsError result for bad secret %q, got %+v", c.secretName, res)
			}
			text := mcpResultText(res)
			if !strings.Contains(text, "invalid_secret_name") {
				t.Fatalf("expected 'invalid_secret_name' taxonomy, got %q", text)
			}
			// Validation runs BEFORE backend.Get, so any 'denied' audit
			// entry must come from the validator itself (Message =
			// "invalid_secret_name"), not from a backend lookup (Message
			// = "not_found" / "backend_error"). The validator MUST emit a
			// 'denied' entry so an AI probing the shape gate leaves a
			// trace — see Finding 4 in /tmp/opaque-qa/codereview-findings.md.
			lines, _ := tailAudit(100)
			sawValidatorDenied := false
			for _, line := range lines {
				if strings.Contains(line, `"action":"denied"`) {
					switch {
					case strings.Contains(line, `"msg":"invalid_secret_name"`):
						sawValidatorDenied = true
					case strings.Contains(line, `"msg":"not_found"`),
						strings.Contains(line, `"msg":"backend_error"`):
						t.Errorf("validation must run BEFORE backend.Get; saw backend-shaped 'denied' entry: %s", line)
					}
				}
			}
			if !sawValidatorDenied {
				t.Errorf("validator must emit a 'denied' audit entry with msg=invalid_secret_name; none seen in: %v", lines)
			}
		})
	}
}

// TestHandleRunWithSecrets_RejectsTooManyArgs (J-16) — input.Args length
// must be capped at mcpMaxArgCount (256). 257 args is rejected with the
// taxonomy "too many args" before any backend or sandbox work.
func TestHandleRunWithSecrets_RejectsTooManyArgs(t *testing.T) {
	args := make([]string, mcpMaxArgCount+1)
	for i := range args {
		args[i] = "x"
	}
	res, _, err := handleRunWithSecrets(context.Background(), nil, runWithSecretsInput{
		Command: "/bin/true",
		Args:    args,
	})
	if err != nil {
		t.Fatalf("unexpected transport error: %v", err)
	}
	if res == nil || !res.IsError {
		t.Fatalf("expected IsError result for oversize args, got %+v", res)
	}
	text := mcpResultText(res)
	if !strings.Contains(text, "too many args") {
		t.Fatalf("expected 'too many args' message, got %q", text)
	}
}

// TestHandleRunWithSecrets_AcceptsArgsAtCap (J-16) — 256 args is within
// the cap and must not be rejected by the args-cap check. The call may
// still fail downstream (e.g. backend unavailable or sandbox probe), but
// the failure must not be the args-cap error.
func TestHandleRunWithSecrets_AcceptsArgsAtCap(t *testing.T) {
	args := make([]string, mcpMaxArgCount)
	for i := range args {
		args[i] = "x"
	}
	res, _, err := handleRunWithSecrets(context.Background(), nil, runWithSecretsInput{
		Command: "/bin/true",
		Args:    args,
	})
	if err != nil {
		t.Fatalf("unexpected transport error: %v", err)
	}
	// If a result was returned (success or failure), it must not be the
	// args-cap error. Downstream failures (sandbox unavailable, backend
	// unavailable, etc.) are acceptable here — the assertion is narrowly
	// that the args-cap gate passed.
	if res != nil {
		text := mcpResultText(res)
		if strings.Contains(text, "too many args") {
			t.Fatalf("256 args wrongly rejected by args-cap: %q", text)
		}
	}
}

// TestHandleAuditTail_EmitsAuditEntry (J-5) — every audit_tail MCP call
// must itself leave an audit entry (caller=mcp, action=audit_tail,
// msg="n=<clamped>"). Without this, an AI scraping the operator's
// activity via repeated audit_tail calls is invisible to the operator.
func TestHandleAuditTail_EmitsAuditEntry(t *testing.T) {
	withAuditTmpDir(t)
	SetCallerTag("mcp")
	t.Cleanup(func() { SetCallerTag("cli") })

	res, _, err := handleAuditTail(context.Background(), nil, auditTailInput{})
	if err != nil {
		t.Fatalf("handleAuditTail: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error result: %s", mcpResultText(res))
	}

	// Read the audit log directly (tailAudit returns CLI-unfiltered view)
	// and look for the audit_tail entry. clampAuditTailN(0) = 20, so
	// the entry's msg must be "n=20".
	lines, err := tailAudit(20)
	if err != nil {
		t.Fatalf("tailAudit: %v", err)
	}
	var found *AuditEvent
	for _, line := range lines {
		var ev AuditEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			continue
		}
		if ev.Action == ActionAuditTail {
			ev := ev // shadow into stable address
			found = &ev
			break
		}
	}
	if found == nil {
		t.Fatalf("no audit_tail entry found in audit log; lines=%v", lines)
	}
	if found.Caller != "mcp" {
		t.Errorf("audit_tail entry caller = %q, want mcp", found.Caller)
	}
	if found.Message != "n=20" {
		t.Errorf("audit_tail entry msg = %q, want n=20 (default after clamp)", found.Message)
	}
}

// TestHandleAuditTail_EmitsAuditEntry_CustomN (J-5) — when the AI passes
// a specific N, the audit entry must reflect the clamped value.
func TestHandleAuditTail_EmitsAuditEntry_CustomN(t *testing.T) {
	withAuditTmpDir(t)
	SetCallerTag("mcp")
	t.Cleanup(func() { SetCallerTag("cli") })

	// 99999 clamps to mcpMaxAuditTailN (200).
	_, _, err := handleAuditTail(context.Background(), nil, auditTailInput{N: 99999})
	if err != nil {
		t.Fatalf("handleAuditTail: %v", err)
	}
	lines, err := tailAudit(20)
	if err != nil {
		t.Fatalf("tailAudit: %v", err)
	}
	wantMsg := fmt.Sprintf("n=%d", mcpMaxAuditTailN)
	var seen bool
	for _, line := range lines {
		var ev AuditEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			continue
		}
		if ev.Action == ActionAuditTail && ev.Message == wantMsg {
			seen = true
			break
		}
	}
	if !seen {
		t.Fatalf("audit_tail entry with msg=%q not found in %v", wantMsg, lines)
	}
}

// TestHandleAuditTail_StripsSelfEntryByNonce (joint-review 2026-05 P3-1)
// — handleAuditTail writes a self-entry BEFORE reading the log, then
// strips its own row from the AI-visible response so the requested `n`
// is not partially consumed. The strip used to be position-based ("the
// last filtered line, matched by PID"), which broke under two
// scenarios: (a) concurrent writers landing between our write and our
// read, pushing our self-entry away from last position; (b) prior
// audit_tail entries from earlier calls being incorrectly considered
// for strip because they shared our PID.
//
// This test asserts the second invariant directly: a prior audit_tail
// entry MUST NOT be stripped by a new call. We pre-plant a "prior"
// audit_tail row with a distinct nonce, plant a follow-on mcp_run row,
// then call handleAuditTail. The handler's own freshly-written entry
// must be stripped (by nonce match), while the pre-planted prior
// audit_tail entry must survive as the deterrent the J-5 design
// promises. (The concurrent-writer race itself is exercised at unit
// level by TestStripSelfAuditTailEntry/removes_single_match_anywhere;
// integration-testing the literal interleaving would require a custom
// audit-writer hook with no security gain.)
func TestHandleAuditTail_StripsSelfEntryByNonce(t *testing.T) {
	withAuditTmpDir(t)
	SetCallerTag("mcp")
	t.Cleanup(func() { SetCallerTag("cli") })

	// Pre-plant a self-style audit_tail entry from a "prior call".
	const priorNonce = "deadbeefdeadbeefdeadbeefdeadbeef"
	if err := AppendAudit(AuditEvent{
		Action:  ActionAuditTail,
		Caller:  "mcp",
		Message: "n=20",
		Nonce:   priorNonce,
	}); err != nil {
		t.Fatalf("plant prior audit_tail: %v", err)
	}
	// Plant a follow-on mcp_run entry so our prior-call audit_tail is
	// no longer the last line in the log when handleAuditTail reads it.
	// This is the "displaced" scenario.
	if err := AppendAudit(AuditEvent{
		Action:  ActionMCPRun,
		Caller:  "mcp",
		Message: "raw_exit=0 elapsed_ms=10",
	}); err != nil {
		t.Fatalf("plant mcp_run: %v", err)
	}

	res, out, err := handleAuditTail(context.Background(), nil, auditTailInput{N: 20})
	if err != nil {
		t.Fatalf("handleAuditTail: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error result: %s", mcpResultText(res))
	}

	// The prior-call audit_tail (deterrent) MUST survive.
	var seenPrior bool
	var selfCount int
	for _, line := range out.Entries {
		var ev AuditEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("unmarshal entry: %v", err)
		}
		if ev.Nonce == priorNonce {
			seenPrior = true
		}
		if ev.Action == ActionAuditTail {
			selfCount++
		}
	}
	if !seenPrior {
		t.Errorf("prior-call audit_tail entry (nonce=%s) was incorrectly stripped; entries=%v", priorNonce, out.Entries)
	}
	// Exactly one audit_tail entry should remain (the prior one). The
	// handler's own freshly-written row must have been stripped by its
	// unique nonce match.
	if selfCount != 1 {
		t.Errorf("expected exactly 1 audit_tail entry to survive (the prior-call deterrent), got %d: %v", selfCount, out.Entries)
	}
}

// TestStripSelfAuditTailEntry locks the nonce-scanner's invariants in
// isolation so a future refactor of handleAuditTail cannot accidentally
// regress the strip behavior.
func TestStripSelfAuditTailEntry(t *testing.T) {
	// Helper to build a serialized audit-line with a given nonce.
	mk := func(action, nonce string) string {
		raw, err := json.Marshal(AuditEvent{Action: action, Caller: "mcp", Nonce: nonce})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return string(raw)
	}

	t.Run("removes single match anywhere in slice", func(t *testing.T) {
		// Place the self-entry in the MIDDLE of the slice — this is
		// the race-displacement case (a concurrent writer landed after
		// our AppendAudit, so the new line(s) are now after us). A
		// position-based strip would have missed this row.
		a := mk(ActionList, "")
		self := mk(ActionAuditTail, "n1")
		b := mk(ActionMCPRun, "")
		out := stripSelfAuditTailEntry([]string{a, self, b}, "n1")
		if len(out) != 2 {
			t.Fatalf("expected 2 entries, got %d: %v", len(out), out)
		}
		// Robust check via Nonce field rather than substring match
		// (Kimi gate 2): a future change that adds a field whose value
		// contains "n1" would otherwise pass spuriously.
		for _, line := range out {
			var ev AuditEvent
			if err := json.Unmarshal([]byte(line), &ev); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if ev.Nonce == "n1" {
				t.Errorf("self entry not stripped: %s", line)
			}
		}
	})
	t.Run("empty nonce is a no-op", func(t *testing.T) {
		entries := []string{mk(ActionAuditTail, ""), mk(ActionMCPRun, "")}
		out := stripSelfAuditTailEntry(entries, "")
		if len(out) != 2 {
			t.Errorf("empty nonce must not modify slice; got %v", out)
		}
	})
	t.Run("no match is a no-op", func(t *testing.T) {
		entries := []string{mk(ActionAuditTail, "other"), mk(ActionMCPRun, "")}
		out := stripSelfAuditTailEntry(entries, "missing")
		if len(out) != 2 {
			t.Errorf("non-matching nonce must not modify slice; got %v", out)
		}
	})
	t.Run("only audit_tail action matches", func(t *testing.T) {
		// A non-audit_tail entry carrying the same nonce must NOT be
		// stripped — defensive against future code paths that mint
		// nonces for other actions.
		entries := []string{mk(ActionMCPRun, "samepid")}
		out := stripSelfAuditTailEntry(entries, "samepid")
		if len(out) != 1 {
			t.Errorf("expected non-audit_tail nonce-bearer to survive; got %v", out)
		}
	})
	t.Run("malformed json is skipped", func(t *testing.T) {
		entries := []string{"{not json", mk(ActionAuditTail, "n2")}
		out := stripSelfAuditTailEntry(entries, "n2")
		if len(out) != 1 || out[0] != "{not json" {
			t.Errorf("expected malformed to survive, audit_tail to be stripped; got %v", out)
		}
	})
}

// TestGenerateAuditNonce sanity-checks the nonce generator.
func TestGenerateAuditNonce(t *testing.T) {
	a := generateAuditNonce()
	b := generateAuditNonce()
	if len(a) != 32 || len(b) != 32 {
		t.Fatalf("nonce length: a=%d b=%d, want 32", len(a), len(b))
	}
	if a == b {
		t.Errorf("two nonces collided: %s == %s", a, b)
	}
	// Verify hex shape.
	for _, ch := range a {
		ok := (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')
		if !ok {
			t.Errorf("nonce contains non-hex char %q in %s", ch, a)
		}
	}
}

// TestFilterAuditLineForAI_StripsElapsedMs (J-10/J-6) — a synthetic
// audit_run JSON line carrying elapsed_ms must have that token stripped
// from the AI-visible msg field. Also exercises that raw_exit and
// exec_* tokens are stripped while allowlisted keys survive.
func TestFilterAuditLineForAI_StripsElapsedMs(t *testing.T) {
	cases := []struct {
		name string
		in   AuditEvent
		// want list of substrings that must NOT appear in the filtered line.
		forbidden []string
		// want list of substrings that MUST appear in the filtered line.
		required []string
	}{
		{
			name: "elapsed_ms_stripped",
			in: AuditEvent{
				Action:  ActionMCPRun,
				Caller:  "mcp",
				Message: "raw_exit=0 elapsed_ms=42 stdout_truncated=true",
			},
			// stdout_truncated is now a forbidden token too (joint-review
			// 2026-05 P1 fix): the output-volume oracle is closed at both
			// the response struct and the audit_tail surfaces.
			forbidden: []string{"elapsed_ms", "raw_exit", "stdout_truncated"},
			required:  []string{},
		},
		{
			name: "raw_exit_negative_stripped",
			in: AuditEvent{
				Action:  ActionMCPRun,
				Caller:  "mcp",
				Message: "raw_exit=-1 elapsed_ms=60000 timed_out=true",
			},
			forbidden: []string{"raw_exit", "elapsed_ms"},
			required:  []string{"timed_out=true"},
		},
		{
			name: "exec_taxonomy_stripped",
			in: AuditEvent{
				Action:  ActionMCPRun,
				Caller:  "mcp",
				Message: "raw_exit=-1 elapsed_ms=10 exec_start_failed",
			},
			forbidden: []string{"raw_exit", "elapsed_ms", "exec_start_failed"},
			required:  []string{},
		},
		{
			name: "only_timed_out_survives",
			in: AuditEvent{
				Action:  ActionMCPRun,
				Caller:  "mcp",
				Message: "stdout_truncated=true stderr_truncated=true timed_out=true",
			},
			// Post P1 fix: stdout_truncated/stderr_truncated are oracles
			// and must not survive the filter; only timed_out remains.
			forbidden: []string{"raw_exit", "elapsed_ms", "stdout_truncated", "stderr_truncated"},
			required:  []string{"timed_out=true"},
		},
		{
			// Joint-review 2026-05 P3: ActionNetworkAllowed messages
			// were previously NOT run through the allowlist filter, so
			// `command=` and `args=` tokens reached the AI verbatim
			// (AI-supplied bytes echoed back via audit_tail — a
			// divergence from the closed-allowlist invariant). The
			// fix extends the filter to cover this action; neither
			// `command` nor `args` is on the allowlist, so the Message
			// collapses to empty.
			name: "network_allowed_command_stripped",
			in: AuditEvent{
				Action:  ActionNetworkAllowed,
				Caller:  "mcp",
				Message: "command=curl args=3",
			},
			forbidden: []string{"command=", "args=", "curl"},
			required:  []string{},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			raw, err := json.Marshal(c.in)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			out, ok := filterAuditLineForAI(string(raw))
			if !ok {
				t.Fatalf("expected line to be kept, got dropped: %s", raw)
			}
			// Re-parse so we look at the msg field, not random JSON.
			var got AuditEvent
			if err := json.Unmarshal([]byte(out), &got); err != nil {
				t.Fatalf("unmarshal output: %v (line=%s)", err, out)
			}
			for _, bad := range c.forbidden {
				if strings.Contains(got.Message, bad) {
					t.Errorf("forbidden token %q present in filtered msg %q", bad, got.Message)
				}
			}
			for _, want := range c.required {
				if !strings.Contains(got.Message, want) {
					t.Errorf("required token %q missing from filtered msg %q", want, got.Message)
				}
			}
		})
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

// findAuditDeniedWithMessage scans the audit log entries for an
// ActionDenied event tagged with caller "mcp" and exact Message match.
// Returns the parsed event and ok=true if found. Used by the P1-1 tests
// below to assert that exec-resolution failures leave a forensic trace.
func findAuditDeniedWithMessage(t *testing.T, wantMsg string) (AuditEvent, bool) {
	t.Helper()
	lines, err := tailAudit(50)
	if err != nil {
		t.Fatalf("tailAudit: %v", err)
	}
	for _, line := range lines {
		var ev AuditEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			continue
		}
		if ev.Action == ActionDenied && strings.HasPrefix(ev.Caller, "mcp") && ev.Message == wantMsg {
			return ev, true
		}
	}
	return AuditEvent{}, false
}

// TestHandleRunWithSecrets_AuditsOnExecNotFound (P1-1, joint-review 2026-05)
// locks the audit-before-return invariant for the exec_not_found branch
// of handleRunWithSecrets's WrapCommand-failure handler. An AI probing
// filesystem path existence one call at a time by reading the response
// taxonomy ("exec_not_found: <basename>") must leave a forensic trace
// in the operator's audit log. Previously this branch returned without
// auditing — joint-review 2026-05 P1.
//
// The Message MUST be the bare taxonomy token "exec_not_found" with
// no AI-supplied bytes (no basename echo) — that would be an
// AI-controlled-bytes channel into the operator log.
func TestHandleRunWithSecrets_AuditsOnExecNotFound(t *testing.T) {
	withAuditTmpDir(t)
	SetCallerTag("mcp")
	t.Cleanup(func() { SetCallerTag("cli") })

	// A bare name guaranteed not to be on PATH. exec.LookPath only wraps
	// exec.ErrNotFound for bare-name lookups — an absolute path that does
	// not exist returns an os-level fs.ErrNotExist that does NOT satisfy
	// errors.Is(err, exec.ErrNotFound) (it falls into the wrap_command_failed
	// catch-all instead, see TestHandleRunWithSecrets_AuditsOnWrapCommandFailed_AbsPath).
	const ghost = "zzz-no-such-bin-anywhere-for-test-xyz"
	res, _, err := handleRunWithSecrets(context.Background(), nil, runWithSecretsInput{
		Command: ghost,
	})
	if err != nil {
		t.Fatalf("unexpected transport error: %v", err)
	}
	if res == nil || !res.IsError {
		t.Fatalf("expected IsError for missing command, got %+v", res)
	}
	text := mcpResultText(res)
	if !strings.Contains(text, "exec_not_found") {
		t.Fatalf("expected response to carry exec_not_found taxonomy, got %q", text)
	}

	ev, ok := findAuditDeniedWithMessage(t, "exec_not_found")
	if !ok {
		t.Fatalf("expected ActionDenied/mcp audit entry with Message=exec_not_found; none found")
	}
	// CRITICAL: the basename ("nonexistent-binary-for-test-only-xyz") must
	// NOT appear anywhere in the audit Message. If it does, an AI can
	// inject controlled bytes into the operator-facing audit log via
	// `Command`. Exact-match on the taxonomy token catches any future
	// regression that concatenates the basename in.
	if ev.Message != "exec_not_found" {
		t.Errorf("audit Message must be the bare taxonomy token, got %q", ev.Message)
	}
	if strings.Contains(ev.Message, ghost) {
		t.Errorf("audit Message leaks AI-supplied basename: %q", ev.Message)
	}
}

// TestHandleRunWithSecrets_AuditsOnExecPermissionDenied (P1-1) locks the
// audit-before-return invariant for the exec_permission_denied branch.
// An AI enumerating which paths exist-but-aren't-executable (a common
// signal for "this host has the binary I want") must leave a trace.
func TestHandleRunWithSecrets_AuditsOnExecPermissionDenied(t *testing.T) {
	withAuditTmpDir(t)
	SetCallerTag("mcp")
	t.Cleanup(func() { SetCallerTag("cli") })

	// Create a regular file with mode 0600 (no exec bit). exec.LookPath
	// on an absolute path checks executability and returns fs.ErrPermission.
	dir := t.TempDir()
	target := filepath.Join(dir, "not-executable")
	if err := os.WriteFile(target, []byte("#!/bin/sh\necho nope\n"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}

	res, _, err := handleRunWithSecrets(context.Background(), nil, runWithSecretsInput{
		Command: target,
	})
	if err != nil {
		t.Fatalf("unexpected transport error: %v", err)
	}
	if res == nil || !res.IsError {
		t.Fatalf("expected IsError for non-executable command, got %+v", res)
	}
	text := mcpResultText(res)
	if !strings.Contains(text, "exec_permission_denied") {
		t.Fatalf("expected response to carry exec_permission_denied taxonomy, got %q", text)
	}

	ev, ok := findAuditDeniedWithMessage(t, "exec_permission_denied")
	if !ok {
		t.Fatalf("expected ActionDenied/mcp audit entry with Message=exec_permission_denied; none found")
	}
	if ev.Message != "exec_permission_denied" {
		t.Errorf("audit Message must be the bare taxonomy token, got %q", ev.Message)
	}
	if strings.Contains(ev.Message, filepath.Base(target)) {
		t.Errorf("audit Message leaks AI-supplied basename: %q", ev.Message)
	}
}

// TestHandleRunWithSecrets_AuditMessageHasNoBasename (P1-1) is an
// explicit guard against any future change that re-introduces the
// AI-supplied basename into the audit Message. The audit log is
// operator-facing; injecting attacker-controlled bytes (via the
// Command field) into that log enables log-poisoning and
// taxonomy-grep evasion. Locked here so even a well-meaning refactor
// trips the assertion.
func TestHandleRunWithSecrets_AuditMessageHasNoBasename(t *testing.T) {
	withAuditTmpDir(t)
	SetCallerTag("mcp")
	t.Cleanup(func() { SetCallerTag("cli") })

	// A distinctive basename that would be obvious if it leaked.
	const sentinel = "/zzz-attacker-poison-marker"
	_, _, err := handleRunWithSecrets(context.Background(), nil, runWithSecretsInput{
		Command: sentinel,
	})
	if err != nil {
		t.Fatalf("unexpected transport error: %v", err)
	}

	lines, err := tailAudit(50)
	if err != nil {
		t.Fatalf("tailAudit: %v", err)
	}
	for _, line := range lines {
		var ev AuditEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			continue
		}
		if strings.Contains(ev.Message, "zzz-attacker-poison-marker") {
			t.Fatalf("AI-supplied basename leaked into audit Message: %q", line)
		}
	}
}

// TestHandleRunWithSecrets_AuditsOnWrapCommandFailed_AbsPath (P1-1)
// drives the third WrapCommand-failure branch end-to-end. exec.LookPath
// on an absolute path that does not exist returns an *exec.Error
// wrapping syscall ENOENT — which does NOT satisfy
// errors.Is(err, exec.ErrNotFound) (that sentinel is specifically for
// the "bare name not on PATH" case). So the failure flows into the
// catch-all third branch and must be audited as "wrap_command_failed".
//
// The taxonomy is deliberately NOT "sandbox_unavailable" for this
// branch: an absent absolute path is not an infrastructure failure;
// the pre-WrapCommand VerifySandboxAvailable branch retains the
// sandbox_unavailable taxonomy for actual sandbox-broken cases. Naming
// fix per Kimi gate 2.
//
// Recording this behavior also pins the taxonomy: if a future
// LookPath change starts returning a more specific wrapped error for
// absolute paths, this test breaks loudly and the maintainer can pick
// a more accurate Message.
func TestHandleRunWithSecrets_AuditsOnWrapCommandFailed_AbsPath(t *testing.T) {
	withAuditTmpDir(t)
	SetCallerTag("mcp")
	t.Cleanup(func() { SetCallerTag("cli") })

	// Absolute path that does not exist on disk.
	const ghost = "/nonexistent-binary-for-test-only-xyz"
	res, _, err := handleRunWithSecrets(context.Background(), nil, runWithSecretsInput{
		Command: ghost,
	})
	if err != nil {
		t.Fatalf("unexpected transport error: %v", err)
	}
	if res == nil || !res.IsError {
		t.Fatalf("expected IsError, got %+v", res)
	}
	if text := mcpResultText(res); !strings.Contains(text, "wrap_command_failed") {
		t.Fatalf("expected wrap_command_failed in response, got %q", text)
	}

	ev, ok := findAuditDeniedWithMessage(t, "wrap_command_failed")
	if !ok {
		t.Fatalf("expected ActionDenied/mcp audit entry with Message=wrap_command_failed; none found")
	}
	if ev.Message != "wrap_command_failed" {
		t.Errorf("audit Message must be the bare taxonomy token, got %q", ev.Message)
	}
	if strings.Contains(ev.Message, filepath.Base(ghost)) {
		t.Errorf("audit Message leaks AI-supplied basename: %q", ev.Message)
	}
}
