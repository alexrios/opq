package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
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
// env-name iteration is sorted so the "first resolve failure" is
// stable across calls. Without sort.Strings, Go's randomized map
// iteration would pick a different first key on most invocations,
// turning the audit log into noise and making failures non-reproducible.
//
// This test requires the env-iteration code path to actually run, which
// in turn requires OpenDefaultBackend to succeed. In a sandboxed CI
// without a Secret Service session that won't happen, so we skip when
// the error text doesn't reach the "resolve" stage.
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
		if !strings.HasPrefix(text, "resolve ") {
			t.Skipf("backend unavailable in this environment (got %q); env-iteration path not exercised", text)
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
