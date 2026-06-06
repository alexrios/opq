package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
)

// retypeGateConfig holds the dependencies the human-confirmation gate uses,
// factored out so tests can drive the logic without touching real TTYs or env
// vars. Shared by `get --plaintext` and `exec --no-redact`, which gate
// identically by design (see CLAUDE.md: --no-redact is "gated identically to
// get --plaintext"). Unifying the two call sites here is what keeps them from
// drifting apart.
type retypeGateConfig struct {
	stdoutIsTTY  bool
	envHumanFlag string // value of OPQ_I_AM_HUMAN as read by caller
	// openConfirmTTY returns a reader/writer pair representing the controlling
	// terminal (/dev/tty in production), plus a closer the caller must invoke.
	// If the TTY cannot be opened, err is returned and the gate fails — humans
	// always have a /dev/tty even when stdin is redirected; AI runtimes that
	// redirect both ends do not.
	openConfirmTTY func() (io.Reader, io.Writer, io.Closer, error)
}

// checkRetypeGate runs the layered human-operator checks shared by
// `get --plaintext` and `exec --no-redact`: stdout must be a TTY,
// OPQ_I_AM_HUMAN=1 must be set inline, and the operator must retype `expected`
// on the controlling terminal. Success returns ("","",nil); any failure returns
// a verbose user reason, a stable audit key, and sentinel. The split keeps
// caller-influenced text (e.g. a /dev/tty errno) out of the AI-readable audit
// log (auditReason) while still giving the operator an actionable message.
//
// prompt is the copy written to the TTY; expected is the exact string the
// operator must type (the secret name for get, the literal "no-redact" for
// exec); sentinel is the error identity the calling command maps to its own
// audit/user message.
func checkRetypeGate(cfg retypeGateConfig, prompt, expected string, sentinel error) (userReason, auditReason string, err error) {
	if !cfg.stdoutIsTTY {
		return "stdout not a tty", GateReasonStdoutNoTTY, sentinel
	}
	if cfg.envHumanFlag != "1" {
		return "missing OPQ_I_AM_HUMAN=1", GateReasonEnvMissing, sentinel
	}
	r, w, closer, openErr := cfg.openConfirmTTY()
	if openErr != nil {
		return "no controlling tty: " + openErr.Error(), GateReasonNoTTY, sentinel
	}
	defer closer.Close()
	if _, werr := fmt.Fprintf(w, "%s", prompt); werr != nil {
		return "tty write: " + werr.Error(), GateReasonTTYWrite, sentinel
	}
	br := bufio.NewReader(r)
	line, rerr := br.ReadString('\n')
	if rerr != nil && rerr != io.EOF {
		return "tty read: " + rerr.Error(), GateReasonTTYRead, sentinel
	}
	got := strings.TrimRight(line, "\r\n")
	if got != expected {
		return "confirmation mismatch", GateReasonConfirmMismatch, sentinel
	}
	return "", "", nil
}

// openControllingTTY opens /dev/tty for read/write. It returns an error if the
// process has no controlling terminal (e.g. detached / daemonized / some CI
// runners). On systems without /dev/tty (Windows) this will fail — acceptable
// because opaque's production target is linux.
func openControllingTTY() (io.Reader, io.Writer, io.Closer, error) {
	f, err := os.OpenFile("/dev/tty", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		return nil, nil, nil, err
	}
	return f, f, f, nil
}
