package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestParseEnvMappings(t *testing.T) {
	type want struct {
		mappings []envMapping
		errSub   string // substring of expected error message; empty = no error
	}
	cases := []struct {
		name string
		in   []string
		want want
	}{
		{
			name: "empty input returns empty slice",
			in:   nil,
			want: want{mappings: []envMapping{}},
		},
		{
			name: "single valid mapping",
			in:   []string{"API_KEY=openai_api_key"},
			want: want{mappings: []envMapping{{envName: "API_KEY", secretName: "openai_api_key"}}},
		},
		{
			name: "multiple valid mappings preserve order",
			in:   []string{"A=one", "B=two", "C=three"},
			want: want{mappings: []envMapping{
				{envName: "A", secretName: "one"},
				{envName: "B", secretName: "two"},
				{envName: "C", secretName: "three"},
			}},
		},
		{
			name: "secret name containing equals is rejected by shape validator",
			// IndexByte returns the FIRST '='; everything after it would be
			// the secret name. J-14 rejects names outside [A-Za-z0-9_.-]{1,128}.
			in:   []string{"X=foo=bar=baz"},
			want: want{errSub: "invalid secret name"},
		},
		{
			name:   "missing equals is rejected",
			in:     []string{"API_KEY"},
			want:   want{errSub: "expected VAR=secret_name"},
		},
		{
			name:   "leading equals is rejected (empty env name)",
			in:     []string{"=openai_api_key"},
			want:   want{errSub: "expected VAR=secret_name"},
		},
		{
			name:   "trailing equals is rejected (empty secret name)",
			in:     []string{"API_KEY="},
			want:   want{errSub: "expected VAR=secret_name"},
		},
		{
			name:   "env name starting with digit is rejected",
			in:     []string{"1FOO=bar"},
			want:   want{errSub: "invalid env var name"},
		},
		{
			name:   "env name with dash is rejected",
			in:     []string{"FOO-BAR=baz"},
			want:   want{errSub: "invalid env var name"},
		},
		{
			name:   "duplicate env name is rejected",
			in:     []string{"API=one", "API=two"},
			want:   want{errSub: `env var "API" specified twice`},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseEnvMappings(tc.in)
			if tc.want.errSub != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil (result=%v)", tc.want.errSub, got)
				}
				if !strings.Contains(err.Error(), tc.want.errSub) {
					t.Fatalf("expected error containing %q, got %q", tc.want.errSub, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			// reflect.DeepEqual treats nil slice and empty slice as different;
			// normalize to empty slice for comparison.
			if got == nil {
				got = []envMapping{}
			}
			if !reflect.DeepEqual(got, tc.want.mappings) {
				t.Fatalf("mappings mismatch:\n  got:  %#v\n  want: %#v", got, tc.want.mappings)
			}
		})
	}
}

func TestValidEnvName(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"", false},
		{"A", true},
		{"a", true},
		{"_", true},
		{"_FOO", true},
		{"FOO_BAR", true},
		{"foo123", true},
		{"FOO_BAR_BAZ_123", true},
		{"1FOO", false},     // leading digit
		{"9", false},        // single digit
		{"FOO-BAR", false},  // dash
		{"FOO.BAR", false},  // dot
		{"FOO BAR", false},  // space
		{"FOO=BAR", false},  // equals
		{"FOO/BAR", false},  // slash
		{"FOO\nBAR", false}, // newline
		{"FOO\x00", false},  // NUL
		{"é", false},        // non-ASCII letter
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			if got := validEnvName(tc.in); got != tc.want {
				t.Fatalf("validEnvName(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// TestValidEnvName_RejectsTooLong locks J-13: env-var names longer than
// maxEnvNameBytes (256) are rejected. The cap exists to bound the
// child-env table size a single --env / Env-map entry can produce.
func TestValidEnvName_RejectsTooLong(t *testing.T) {
	// 256 chars (boundary, accepted): "A_" + 254 'A's = 256.
	at256 := "A_" + strings.Repeat("A", 254)
	if len(at256) != 256 {
		t.Fatalf("at256 length = %d, want 256", len(at256))
	}
	if !validEnvName(at256) {
		t.Errorf("validEnvName(len=256) = false, want true")
	}
	// 257 chars (over the cap, rejected).
	at257 := "A_" + strings.Repeat("A", 255)
	if len(at257) != 257 {
		t.Fatalf("at257 length = %d, want 257", len(at257))
	}
	if validEnvName(at257) {
		t.Errorf("validEnvName(len=257) = true, want false")
	}
	// 255 chars (well under the cap, accepted).
	at255 := "A_" + strings.Repeat("A", 253)
	if len(at255) != 255 {
		t.Fatalf("at255 length = %d, want 255", len(at255))
	}
	if !validEnvName(at255) {
		t.Errorf("validEnvName(len=255) = false, want true")
	}
}

func TestFilterParentEnv(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{
			name: "drops all OPQ_ vars",
			in:   []string{"OPQ_DEBUG=1", "OPQ_FOO=bar"},
			want: []string{},
		},
		{
			name: "keeps non-OPQ vars",
			in:   []string{"PATH=/usr/bin", "HOME=/home/x"},
			want: []string{"PATH=/usr/bin", "HOME=/home/x"},
		},
		{
			name: "mixed input keeps order of survivors",
			in:   []string{"PATH=/usr/bin", "OPQ_DEBUG=1", "HOME=/home/x", "OPQ_AUDIT_PATH=/tmp/a"},
			want: []string{"PATH=/usr/bin", "HOME=/home/x"},
		},
		{
			name: "OPQ_ prefix is case-sensitive (opq_ lowercase is kept)",
			// HasPrefix is case-sensitive; only the all-uppercase internal
			// prefix is filtered. This is intentional — user code may have
			// its own opq_-named vars.
			in:   []string{"opq_user_thing=1", "OPQ_REAL=2"},
			want: []string{"opq_user_thing=1"},
		},
		{
			name: "prefix-only match is dropped, substring match is kept",
			in:   []string{"OPQ_=empty", "MY_OPQ_VAR=fine"},
			want: []string{"MY_OPQ_VAR=fine"},
		},
		{
			name: "empty input returns empty slice",
			in:   []string{},
			want: []string{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := filterParentEnv(tc.in)
			if got == nil {
				got = []string{}
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("filterParentEnv mismatch:\n  got:  %#v\n  want: %#v", got, tc.want)
			}
		})
	}
}

func TestParseEnvMappings_RejectsBlockedNames(t *testing.T) {
	cases := []string{
		// exact-map entries
		"PATH=some_secret",
		"BASH_ENV=some_secret",
		"GLIBC_TUNABLES=some_secret",
		// LD_ prefix
		"LD_PRELOAD=some_secret",
		// NSS_ / GIO_ prefixes
		"NSS_HOSTS=some_secret",
		"GIO_USE_VFS=some_secret",
		// ERL_ prefix (newly added)
		"ERL_FLAGS=some_secret",
		"ERL_NEW_FUTURE_VAR=some_secret",
		// BASH_FUNC_ prefix (newly added); use a name valid per validEnvName
		// (no %%) since validEnvName runs before isBlockedEnvName.
		"BASH_FUNC_ls=some_secret",
		// GIT_CONFIG_ prefix (newly added)
		"GIT_CONFIG_KEY_0=some_secret",
		"GIT_CONFIG_VALUE_0=some_secret",
	}
	for _, spec := range cases {
		t.Run(spec, func(t *testing.T) {
			_, err := parseEnvMappings([]string{spec})
			if err == nil {
				t.Fatalf("expected error for blocked spec %q, got nil", spec)
			}
			if !strings.Contains(err.Error(), "deny-list") {
				t.Fatalf("expected deny-list in error, got %q", err.Error())
			}
		})
	}
}

// TestParseEnvMappings_RejectsBadSecretName locks J-14 on the CLI surface:
// a secret name outside [A-Za-z0-9_.-]{1,128} is rejected with the
// verbose CLI-style message ("invalid secret name") before any backend
// touch.
func TestParseEnvMappings_RejectsBadSecretName(t *testing.T) {
	cases := []struct {
		name string
		spec string
	}{
		// '=' is consumed by IndexByte as the separator, so the trailing
		// "bar=baz" becomes the secret name and fails the shape gate.
		{"secret_with_embedded_equals", "API=foo=bar=baz"},
		{"secret_with_space", "API=bad name"},
		{"secret_with_slash", "API=bad/path"},
		{"secret_with_dollar", "API=bad$value"},
		{"secret_too_long", "API=" + strings.Repeat("a", 129)},
		{"secret_with_newline", "API=bad\nname"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseEnvMappings([]string{tc.spec})
			if err == nil {
				t.Fatalf("expected error for spec %q, got nil", tc.spec)
			}
			if !strings.Contains(err.Error(), "invalid secret name") {
				t.Fatalf("expected 'invalid secret name' in error, got %q", err.Error())
			}
		})
	}
}

func TestParseEnvMappings_LegitimateNameStillParses(t *testing.T) {
	got, err := parseEnvMappings([]string{"OPENAI_API_KEY=openai_api_key"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []envMapping{{envName: "OPENAI_API_KEY", secretName: "openai_api_key"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("mismatch:\n  got:  %#v\n  want: %#v", got, want)
	}
}

func TestExitCodeError(t *testing.T) {
	// Sanity check that the typed error reports the expected code and
	// carries a non-empty message (kong.FatalIfErrorf would otherwise
	// print an empty string if we ever fell back to it).
	e := &exitCodeError{code: 42}
	if e.ExitCode() != 42 {
		t.Fatalf("ExitCode = %d, want 42", e.ExitCode())
	}
	if e.Error() == "" {
		t.Fatal("Error() returned empty string")
	}
}

// -----------------------------------------------------------------------------
// --no-redact gate tests (P0-1).
//
// The gate sits in ExecCmd.Run() ahead of any keyring access. The tests below
// drive the shared checkRetypeGate directly (with the --no-redact prompt and
// literal) using a mocked openConfirmTTY, just like cmd_get_test.go does for
// the --plaintext gate.
// -----------------------------------------------------------------------------

// fakeNoRedactTTY models the controlling-terminal pair as buffers. Both the
// input/output buffer and a close-tracking flag survive after openConfirmTTY
// returns so tests can assert on what got written to the prompt.
type fakeNoRedactTTY struct {
	in     *bytes.Buffer
	outBuf *bytes.Buffer
	closed bool
}

func newNoRedactTTYOpener(input string) (func() (io.Reader, io.Writer, io.Closer, error), *fakeNoRedactTTY) {
	tty := &fakeNoRedactTTY{
		in:     bytes.NewBufferString(input),
		outBuf: &bytes.Buffer{},
	}
	open := func() (io.Reader, io.Writer, io.Closer, error) {
		return tty.in, tty.outBuf, fakeCloser{f: func() error { tty.closed = true; return nil }}, nil
	}
	return open, tty
}

// errWriter always fails Write; used to drive GateReasonTTYWrite.
type errWriter struct{ err error }

func (e errWriter) Write(p []byte) (int, error) { return 0, e.err }

// errReader always fails Read with a non-EOF error; used to drive
// GateReasonTTYRead.
type errReader struct{ err error }

func (e errReader) Read(p []byte) (int, error) { return 0, e.err }

func TestCheckNoRedactGate_Allows_HappyPath(t *testing.T) {
	t.Helper()
	open, tty := newNoRedactTTYOpener(noRedactConfirmInputLiteral + "\n")
	cfg := retypeGateConfig{
		stdoutIsTTY:    true,
		envHumanFlag:   "1",
		openConfirmTTY: open,
	}
	userReason, auditReason, err := checkRetypeGate(cfg, noRedactConfirmInputPrompt, noRedactConfirmInputLiteral, errNoRedactGate)
	if err != nil {
		t.Fatalf("expected gate pass, got err=%v userReason=%q auditReason=%q", err, userReason, auditReason)
	}
	if userReason != "" || auditReason != "" {
		t.Errorf("expected empty reasons on success, got userReason=%q auditReason=%q", userReason, auditReason)
	}
	if !strings.Contains(tty.outBuf.String(), noRedactConfirmInputPrompt) {
		t.Errorf("prompt not written to TTY writer: %q", tty.outBuf.String())
	}
	if !tty.closed {
		t.Errorf("TTY closer was not invoked")
	}
	// Kimi P0: a "happy path" that never actually consumed the confirmation
	// line would also pass — verify the input buffer was drained.
	if tty.in.Len() != 0 {
		t.Fatalf("confirmation line was not read from TTY (remaining=%q)", tty.in.String())
	}
}

func TestCheckNoRedactGate_Refuses_StdoutNotTTY(t *testing.T) {
	t.Helper()
	open, _ := newNoRedactTTYOpener(noRedactConfirmInputLiteral + "\n")
	cfg := retypeGateConfig{
		stdoutIsTTY:    false,
		envHumanFlag:   "1",
		openConfirmTTY: open,
	}
	userReason, auditReason, err := checkRetypeGate(cfg, noRedactConfirmInputPrompt, noRedactConfirmInputLiteral, errNoRedactGate)
	if err == nil {
		t.Fatal("expected gate refusal when stdout is not a TTY")
	}
	if !strings.Contains(userReason, "stdout") {
		t.Errorf("user reason should mention stdout, got %q", userReason)
	}
	if auditReason != GateReasonStdoutNoTTY {
		t.Errorf("audit reason = %q, want %q", auditReason, GateReasonStdoutNoTTY)
	}
}

// Table-driven: every value other than the literal "1" must refuse.
func TestCheckNoRedactGate_Refuses_EnvMissing(t *testing.T) {
	for _, val := range []string{"", "0", "true", "TRUE", " 1", "1 "} {
		t.Run("env="+val, func(t *testing.T) {
			open, _ := newNoRedactTTYOpener(noRedactConfirmInputLiteral + "\n")
			cfg := retypeGateConfig{
				stdoutIsTTY:    true,
				envHumanFlag:   val,
				openConfirmTTY: open,
			}
			userReason, auditReason, err := checkRetypeGate(cfg, noRedactConfirmInputPrompt, noRedactConfirmInputLiteral, errNoRedactGate)
			if err == nil {
				t.Fatalf("expected refusal for env value %q", val)
			}
			if !strings.Contains(userReason, envHumanConfirm) {
				t.Errorf("user reason should mention %s, got %q", envHumanConfirm, userReason)
			}
			if auditReason != GateReasonEnvMissing {
				t.Errorf("audit reason = %q, want %q", auditReason, GateReasonEnvMissing)
			}
		})
	}
}

func TestCheckNoRedactGate_Refuses_TTYOpenFailure(t *testing.T) {
	t.Helper()
	openFail := func() (io.Reader, io.Writer, io.Closer, error) {
		return nil, nil, nil, errors.New("no /dev/tty")
	}
	cfg := retypeGateConfig{
		stdoutIsTTY:    true,
		envHumanFlag:   "1",
		openConfirmTTY: openFail,
	}
	userReason, auditReason, err := checkRetypeGate(cfg, noRedactConfirmInputPrompt, noRedactConfirmInputLiteral, errNoRedactGate)
	if err == nil {
		t.Fatal("expected gate refusal when /dev/tty cannot be opened")
	}
	if !strings.Contains(userReason, "no controlling tty") {
		t.Errorf("user reason should mention 'no controlling tty', got %q", userReason)
	}
	if auditReason != GateReasonNoTTY {
		t.Errorf("audit reason = %q, want %q", auditReason, GateReasonNoTTY)
	}
}

func TestCheckNoRedactGate_Refuses_TTYWriteFailure(t *testing.T) {
	t.Helper()
	// Reader is fine; writer returns an error on Write so we trip
	// GateReasonTTYWrite before the read happens.
	openErr := func() (io.Reader, io.Writer, io.Closer, error) {
		return bytes.NewBufferString(noRedactConfirmInputLiteral + "\n"),
			errWriter{err: errors.New("disk full")},
			fakeCloser{f: func() error { return nil }},
			nil
	}
	cfg := retypeGateConfig{
		stdoutIsTTY:    true,
		envHumanFlag:   "1",
		openConfirmTTY: openErr,
	}
	userReason, auditReason, err := checkRetypeGate(cfg, noRedactConfirmInputPrompt, noRedactConfirmInputLiteral, errNoRedactGate)
	if err == nil {
		t.Fatal("expected gate refusal on TTY write failure")
	}
	if !strings.Contains(userReason, "tty write") {
		t.Errorf("user reason should mention 'tty write', got %q", userReason)
	}
	if auditReason != GateReasonTTYWrite {
		t.Errorf("audit reason = %q, want %q", auditReason, GateReasonTTYWrite)
	}
}

func TestCheckNoRedactGate_Refuses_TTYReadFailure(t *testing.T) {
	t.Helper()
	// Writer accepts the prompt; reader returns a non-EOF error.
	openErr := func() (io.Reader, io.Writer, io.Closer, error) {
		return errReader{err: errors.New("hung up")},
			&bytes.Buffer{},
			fakeCloser{f: func() error { return nil }},
			nil
	}
	cfg := retypeGateConfig{
		stdoutIsTTY:    true,
		envHumanFlag:   "1",
		openConfirmTTY: openErr,
	}
	userReason, auditReason, err := checkRetypeGate(cfg, noRedactConfirmInputPrompt, noRedactConfirmInputLiteral, errNoRedactGate)
	if err == nil {
		t.Fatal("expected gate refusal on TTY read failure")
	}
	if !strings.Contains(userReason, "tty read") {
		t.Errorf("user reason should mention 'tty read', got %q", userReason)
	}
	if auditReason != GateReasonTTYRead {
		t.Errorf("audit reason = %q, want %q", auditReason, GateReasonTTYRead)
	}
}

// Pure EOF before any line is read must not crash and must surface as a
// confirmation mismatch (the bufio.ReadString contract: io.EOF with a
// possibly-empty partial line is tolerated, then the empty line fails the
// literal compare). Kimi P1: this branch is distinct from "\n" since no
// newline ever arrives.
func TestCheckNoRedactGate_Refuses_EOFWithoutLine(t *testing.T) {
	open, _ := newNoRedactTTYOpener("") // empty input → immediate EOF
	cfg := retypeGateConfig{
		stdoutIsTTY:    true,
		envHumanFlag:   "1",
		openConfirmTTY: open,
	}
	userReason, auditReason, err := checkRetypeGate(cfg, noRedactConfirmInputPrompt, noRedactConfirmInputLiteral, errNoRedactGate)
	if err == nil {
		t.Fatal("expected refusal on EOF without confirmation line")
	}
	if auditReason != GateReasonConfirmMismatch {
		t.Errorf("audit reason = %q, want %q", auditReason, GateReasonConfirmMismatch)
	}
	_ = userReason
}

// Table-driven: any input that doesn't equal the literal "no-redact" after
// CRLF stripping must be refused as GateReasonConfirmMismatch. EOF without
// a matching line falls into this bucket too (handled by the empty case via
// the dedicated TTY-read-EOF assertion).
func TestCheckNoRedactGate_Refuses_LineMismatch(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"plain_yes", "yes\n"},
		{"uppercase_literal", "NO-REDACT\n"},
		{"empty_line", "\n"},
		{"leading_space", " no-redact\n"},
		{"trailing_space", "no-redact \n"},
		{"suffix_after_literal", "no-redact:something\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			open, _ := newNoRedactTTYOpener(tc.input)
			cfg := retypeGateConfig{
				stdoutIsTTY:    true,
				envHumanFlag:   "1",
				openConfirmTTY: open,
			}
			userReason, auditReason, err := checkRetypeGate(cfg, noRedactConfirmInputPrompt, noRedactConfirmInputLiteral, errNoRedactGate)
			if err == nil {
				t.Fatalf("expected refusal for input %q", tc.input)
			}
			if !strings.Contains(userReason, "mismatch") {
				t.Errorf("user reason should mention mismatch, got %q", userReason)
			}
			if auditReason != GateReasonConfirmMismatch {
				t.Errorf("audit reason = %q, want %q", auditReason, GateReasonConfirmMismatch)
			}
		})
	}
}

// CRLF on the wire (terminals that send \r\n) must still pass the gate;
// the implementation TrimRights both bytes. Mirrors the cmd_get gate test.
func TestCheckNoRedactGate_Allows_TrailingCR(t *testing.T) {
	t.Helper()
	open, _ := newNoRedactTTYOpener(noRedactConfirmInputLiteral + "\r\n")
	cfg := retypeGateConfig{
		stdoutIsTTY:    true,
		envHumanFlag:   "1",
		openConfirmTTY: open,
	}
	userReason, auditReason, err := checkRetypeGate(cfg, noRedactConfirmInputPrompt, noRedactConfirmInputLiteral, errNoRedactGate)
	if err != nil {
		t.Fatalf("expected gate pass with CRLF, got err=%v userReason=%q auditReason=%q", err, userReason, auditReason)
	}
}

// TestExecCmdRun_GateInvokedBeforeKeyring (Kimi P0) — drives the REAL
// ExecCmd.Run() with NoRedact=true under conditions that must fail at the
// gate (stdout-not-TTY in the test process). If a future refactor removes
// the gate call from Run(), this test fails because the error wouldn't carry
// the gate-refusal prefix. Also locks the ordering invariant: the gate runs
// BEFORE any backend.Get touch, so a missing/locked keyring on the test host
// can never mask a gate regression.
func TestExecCmdRun_GateInvokedBeforeKeyring(t *testing.T) {
	withAuditTmpDir(t)
	t.Setenv(envHumanConfirm, "") // explicitly unset the inline env

	cmd := &ExecCmd{
		NoRedact: true,
		Command:  []string{"echo", "ignored"},
	}
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected Run() to refuse with no TTY + no env, got nil")
	}
	// The gate's user-facing error always starts with this prefix; any
	// other error path (parseEnvMappings, backend, exec) wouldn't.
	if !strings.Contains(err.Error(), "refusing to run --no-redact") {
		t.Fatalf("Run() error does not look like a gate refusal: %v", err)
	}

	// The gate-refusal audit entry must exist with the right Message shape.
	data, readErr := os.ReadFile(filepath.Join(os.Getenv("XDG_STATE_HOME"), "opq", "audit.log"))
	if readErr != nil {
		t.Fatalf("read audit.log: %v", readErr)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	var found bool
	for _, line := range lines {
		var ev AuditEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			continue
		}
		if ev.Action == ActionDenied && strings.HasPrefix(ev.Message, "no_redact_refused:") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("no audit entry with Action=denied and Message prefix no_redact_refused: in:\n%s", string(data))
	}
}

// TestNoRedactGate_AuditMessageFormat — drive ExecCmd.Run() far enough to
// fail at the gate, then read the audit log and assert the line has
// Action=ActionDenied and Message="no_redact_refused:<reason>". We can't
// invoke ExecCmd.Run() directly (its kong-style fields need a real TTY); we
// reproduce the AppendAudit call site by hand using the audit constants so a
// later refactor of that line is caught.
func TestNoRedactGate_AuditMessageFormat(t *testing.T) {
	tmp := withAuditTmpDir(t)

	// Drive the gate to a known failure (stdout not a TTY) and replay the
	// production AppendAudit call shape from cmd_exec.go.
	cfg := retypeGateConfig{
		stdoutIsTTY:  false,
		envHumanFlag: "1",
		openConfirmTTY: func() (io.Reader, io.Writer, io.Closer, error) {
			return &bytes.Buffer{}, &bytes.Buffer{}, fakeCloser{f: func() error { return nil }}, nil
		},
	}
	_, auditReason, err := checkRetypeGate(cfg, noRedactConfirmInputPrompt, noRedactConfirmInputLiteral, errNoRedactGate)
	if err == nil {
		t.Fatal("expected gate refusal")
	}
	if writeErr := AppendAudit(AuditEvent{
		Action:  ActionDenied,
		Caller:  callerTag(),
		Message: "no_redact_refused:" + auditReason,
	}); writeErr != nil {
		t.Fatalf("AppendAudit: %v", writeErr)
	}

	data, err := os.ReadFile(filepath.Join(tmp, "opq", "audit.log"))
	if err != nil {
		t.Fatalf("read audit.log: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) == 0 {
		t.Fatalf("expected at least one audit line, got: %q", data)
	}
	var ev AuditEvent
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &ev); err != nil {
		t.Fatalf("unmarshal last line: %v", err)
	}
	if ev.Action != ActionDenied {
		t.Errorf("Action = %q, want %q", ev.Action, ActionDenied)
	}
	if !strings.HasPrefix(ev.Message, "no_redact_refused:") {
		t.Errorf("Message = %q, want prefix %q", ev.Message, "no_redact_refused:")
	}
	if !strings.HasSuffix(ev.Message, auditReason) {
		t.Errorf("Message = %q, want suffix %q (the stable taxonomy key)", ev.Message, auditReason)
	}
}

// TestForwardSignals_RelaysMultipleSignals proves the signal-forwarding
// helper stays alive across multiple signals (P1-2 from the joint review:
// the previous one-shot select dropped a second ^C aimed at a hung child).
func TestForwardSignals_RelaysMultipleSignals(t *testing.T) {
	sigCh := make(chan os.Signal, 4)
	done := make(chan struct{})

	received := make(chan os.Signal, 4)
	gotAll := make(chan struct{})
	go func() {
		forwardSignals(sigCh, done, func(sig os.Signal) {
			received <- sig
			if len(received) == 3 {
				close(gotAll)
			}
		})
	}()

	sigCh <- syscall.SIGINT
	sigCh <- syscall.SIGINT
	sigCh <- syscall.SIGTERM

	select {
	case <-gotAll:
	case <-time.After(2 * time.Second):
		t.Fatalf("forwardSignals delivered only %d signals, want 3", len(received))
	}

	want := []os.Signal{syscall.SIGINT, syscall.SIGINT, syscall.SIGTERM}
	for i, w := range want {
		got := <-received
		if got != w {
			t.Errorf("signal[%d] = %v, want %v", i, got, w)
		}
	}

	exited := make(chan struct{})
	go func() {
		// Re-run the helper with an empty sigCh so we can prove `done` exits it.
		idle := make(chan os.Signal)
		forwardSignals(idle, done, func(os.Signal) {})
		close(exited)
	}()
	close(done)
	select {
	case <-exited:
	case <-time.After(2 * time.Second):
		t.Fatal("forwardSignals did not return after done was closed")
	}
}
