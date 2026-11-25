package main

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

// fakeTTY models a controlling-terminal pair as buffers. The closer is a
// no-op since the buffers don't hold resources.
type fakeTTY struct {
	in     *bytes.Buffer
	outBuf *bytes.Buffer
	closed bool
}

func (f *fakeTTY) close() error { f.closed = true; return nil }

type fakeCloser struct{ f func() error }

func (c fakeCloser) Close() error { return c.f() }

func newFakeTTYOpener(input string) (func() (io.Reader, io.Writer, io.Closer, error), *fakeTTY) {
	tty := &fakeTTY{
		in:     bytes.NewBufferString(input),
		outBuf: &bytes.Buffer{},
	}
	open := func() (io.Reader, io.Writer, io.Closer, error) {
		return tty.in, tty.outBuf, fakeCloser{f: tty.close}, nil
	}
	return open, tty
}

func TestCheckInteractiveGate_AllowsHappyPath(t *testing.T) {
	open, tty := newFakeTTYOpener("api_key\n")
	cfg := retypeGateConfig{
		stdoutIsTTY:    true,
		envHumanFlag:   "1",
		openConfirmTTY: open,
	}
	userReason, auditReason, err := checkRetypeGate(cfg, confirmInputPrompt, "api_key", errInteractiveGate)
	if err != nil {
		t.Fatalf("expected gate pass, got err=%v userReason=%q auditReason=%q", err, userReason, auditReason)
	}
	if !strings.Contains(tty.outBuf.String(), confirmInputPrompt) {
		t.Errorf("prompt not written: %q", tty.outBuf.String())
	}
	if !tty.closed {
		t.Errorf("tty not closed")
	}
}

func TestCheckInteractiveGate_RefusesNonTTYStdout(t *testing.T) {
	open, _ := newFakeTTYOpener("api_key\n")
	cfg := retypeGateConfig{
		stdoutIsTTY:    false,
		envHumanFlag:   "1",
		openConfirmTTY: open,
	}
	userReason, auditReason, err := checkRetypeGate(cfg, confirmInputPrompt, "api_key", errInteractiveGate)
	if err == nil {
		t.Fatal("expected gate refusal")
	}
	if !strings.Contains(userReason, "stdout") {
		t.Errorf("user reason should mention stdout, got %q", userReason)
	}
	if auditReason != GateReasonStdoutNoTTY {
		t.Errorf("audit reason = %q, want %q", auditReason, GateReasonStdoutNoTTY)
	}
}

func TestCheckInteractiveGate_RefusesMissingEnvVar(t *testing.T) {
	open, _ := newFakeTTYOpener("api_key\n")
	cfg := retypeGateConfig{
		stdoutIsTTY:    true,
		envHumanFlag:   "",
		openConfirmTTY: open,
	}
	userReason, auditReason, err := checkRetypeGate(cfg, confirmInputPrompt, "api_key", errInteractiveGate)
	if err == nil {
		t.Fatal("expected gate refusal")
	}
	if !strings.Contains(userReason, envHumanConfirm) {
		t.Errorf("user reason should mention env var, got %q", userReason)
	}
	if auditReason != GateReasonEnvMissing {
		t.Errorf("audit reason = %q, want %q", auditReason, GateReasonEnvMissing)
	}
}

func TestCheckInteractiveGate_RefusesNonOneEnvVar(t *testing.T) {
	// Common typo / loose values must not satisfy the gate.
	for _, val := range []string{"true", "yes", "0", "TRUE", " 1"} {
		open, _ := newFakeTTYOpener("api_key\n")
		cfg := retypeGateConfig{
			stdoutIsTTY:    true,
			envHumanFlag:   val,
			openConfirmTTY: open,
		}
		_, _, err := checkRetypeGate(cfg, confirmInputPrompt, "api_key", errInteractiveGate)
		if err == nil {
			t.Errorf("expected refusal for env value %q", val)
		}
	}
}

func TestCheckInteractiveGate_RefusesWhenTTYUnavailable(t *testing.T) {
	openFail := func() (io.Reader, io.Writer, io.Closer, error) {
		return nil, nil, nil, errors.New("no /dev/tty")
	}
	cfg := retypeGateConfig{
		stdoutIsTTY:    true,
		envHumanFlag:   "1",
		openConfirmTTY: openFail,
	}
	userReason, auditReason, err := checkRetypeGate(cfg, confirmInputPrompt, "api_key", errInteractiveGate)
	if err == nil {
		t.Fatal("expected gate refusal")
	}
	if !strings.Contains(userReason, "no controlling tty") {
		t.Errorf("user reason should mention missing tty, got %q", userReason)
	}
	if auditReason != GateReasonNoTTY {
		t.Errorf("audit reason = %q, want %q", auditReason, GateReasonNoTTY)
	}
}

func TestCheckInteractiveGate_RefusesOnNameMismatch(t *testing.T) {
	open, _ := newFakeTTYOpener("wrong_name\n")
	cfg := retypeGateConfig{
		stdoutIsTTY:    true,
		envHumanFlag:   "1",
		openConfirmTTY: open,
	}
	userReason, auditReason, err := checkRetypeGate(cfg, confirmInputPrompt, "api_key", errInteractiveGate)
	if err == nil {
		t.Fatal("expected gate refusal")
	}
	if !strings.Contains(userReason, "mismatch") {
		t.Errorf("user reason should mention mismatch, got %q", userReason)
	}
	if auditReason != GateReasonConfirmMismatch {
		t.Errorf("audit reason = %q, want %q", auditReason, GateReasonConfirmMismatch)
	}
}

func TestCheckInteractiveGate_AcceptsCRLF(t *testing.T) {
	// Windows-style line endings should not break the comparison if the
	// user pasted a name from a terminal that supplies them.
	open, _ := newFakeTTYOpener("api_key\r\n")
	cfg := retypeGateConfig{
		stdoutIsTTY:    true,
		envHumanFlag:   "1",
		openConfirmTTY: open,
	}
	if userReason, auditReason, err := checkRetypeGate(cfg, confirmInputPrompt, "api_key", errInteractiveGate); err != nil {
		t.Fatalf("expected gate pass with CRLF, got err=%v userReason=%q auditReason=%q", err, userReason, auditReason)
	}
}

func TestCheckInteractiveGate_RefusesOnEOFBeforeNewline(t *testing.T) {
	// Empty TTY input (e.g. user hits Ctrl-D immediately) must not be
	// silently treated as a matching empty string when c.Name is empty
	// either; the gate should still refuse because an actual confirmed
	// release requires the user to type something non-empty equal to the
	// name. We test with a real secret name here.
	open, _ := newFakeTTYOpener("")
	cfg := retypeGateConfig{
		stdoutIsTTY:    true,
		envHumanFlag:   "1",
		openConfirmTTY: open,
	}
	_, _, err := checkRetypeGate(cfg, confirmInputPrompt, "api_key", errInteractiveGate)
	if err == nil {
		t.Fatal("expected refusal on empty TTY input")
	}
}

func TestGetCmd_MissingPlaintextIncludesExecAndExactHumanInvocation(t *testing.T) {
	err := (&GetCmd{Name: "stripe_secret_key", Plaintext: false}).Run()
	if err == nil {
		t.Fatal("expected refusal without --plaintext")
	}
	msg := err.Error()
	if !strings.Contains(msg, "opq exec") {
		t.Errorf("error should still recommend opq exec, got: %q", msg)
	}
	wantCmd := "OPQ_I_AM_HUMAN=1 opq get stripe_secret_key --plaintext"
	if !strings.Contains(msg, wantCmd) {
		t.Errorf("error should include exact human invocation %q, got: %q", wantCmd, msg)
	}
}

func TestGetCmd_MissingPlaintextSanitizesInvalidNameInHint(t *testing.T) {
	err := (&GetCmd{Name: "bad;name", Plaintext: false}).Run()
	if err == nil {
		t.Fatal("expected refusal without --plaintext")
	}
	if strings.Contains(err.Error(), "bad;name") {
		t.Errorf("invalid name should not be echoed into suggested command: %q", err.Error())
	}
	if !strings.Contains(err.Error(), "OPQ_I_AM_HUMAN=1 opq get <name> --plaintext") {
		t.Errorf("expected <name> placeholder in hint: %q", err.Error())
	}
}

func TestGetCmd_PlaintextGateRunsAndAuditsBeforeKeyring(t *testing.T) {
	withAuditTmpDir(t)
	t.Setenv(envHumanConfirm, "")
	err := (&GetCmd{Name: "api_key", Plaintext: true}).Run()
	if err == nil {
		t.Fatal("expected human gate refusal when stdout is not a TTY")
	}
	if !strings.Contains(err.Error(), "refusing to release plaintext secret") {
		t.Fatalf("unexpected error (gate may not have run before keyring): %v", err)
	}
	lines, tailErr := tailAudit(10)
	if tailErr != nil {
		t.Fatalf("tailAudit: %v", tailErr)
	}
	found := false
	for _, l := range lines {
		if strings.Contains(l, `"action":"denied"`) && strings.Contains(l, "get_plaintext_refused:") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected get_plaintext_refused audit entry before keyring access; got %v", lines)
	}
}
