package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"
)

// exitCodeError carries a child process exit code back to main() without
// calling os.Exit at the deep call site. Calling os.Exit here would skip
// all pending defers (memguard buffer Destroy, RedactingWriter Destroy,
// signal.Stop, and the top-level memguard.Purge), leaving secret pages
// reclaimed-but-not-zeroed on the way out. main() unwraps this error and
// calls os.Exit AFTER all defers have run.
type exitCodeError struct {
	code int
}

func (e *exitCodeError) Error() string {
	return fmt.Sprintf("child exited with code %d", e.code)
}

// ExitCode returns the exit code main() should propagate to the OS.
func (e *exitCodeError) ExitCode() int { return e.code }

type ExecCmd struct {
	Env      []string `name:"env" short:"e" help:"Inject a secret as an environment variable for the child. Format: VAR=secret_name. Repeatable."`
	NoRedact bool     `name:"no-redact" help:"DISABLE output redaction. HUMAN-ONLY: refuses unless stdout is a TTY AND OPQ_I_AM_HUMAN=1 is set inline AND you retype 'no-redact' on the controlling terminal. Logged loudly to the audit log."`
	Sandbox  string   `name:"sandbox" enum:"none,net,full" default:"none" help:"Subprocess sandbox profile: none (default, no isolation), net (block network), full (block network + tmpfs /home /tmp + minimal ro-binds)."`
	Command  []string `arg:"" passthrough:"" help:"Command and arguments to run. Use -- to separate from opq flags."`
}

// parseSandboxFlag maps the CLI/MCP string ("none"/"net"/"full") to
// a SandboxProfile. Empty string defaults to SandboxNone.
func parseSandboxFlag(s string) (SandboxProfile, error) {
	switch s {
	case "", "none":
		return SandboxNone, nil
	case "net":
		return SandboxNet, nil
	case "full":
		return SandboxFull, nil
	default:
		return SandboxNone, fmt.Errorf("unknown sandbox profile %q (want none|net|full)", s)
	}
}

// noRedactConfirmInputPrompt is the canonical prompt copy. Exported as a
// constant so tests don't have to mirror it.
const noRedactConfirmInputPrompt = "Type 'no-redact' to confirm release without redaction: "

// noRedactConfirmInputLiteral is the literal string the operator must type
// on the controlling terminal. A fixed literal (rather than the secret name)
// is used because --no-redact is not scoped to a single secret — the flag
// disables the redactor for every secret injected via --env in this run.
const noRedactConfirmInputLiteral = "no-redact"

// errNoRedactGate is returned when any of the layered --no-redact gates
// fail. Run() converts it into the user-facing error and audit message.
var errNoRedactGate = errors.New("no-redact release gate")

// noRedactGateConfig holds the dependencies that the gate uses, factored
// out so tests can drive the logic without touching real TTYs or env vars.
type noRedactGateConfig struct {
	stdoutIsTTY  bool
	envHumanFlag string // value of OPQ_I_AM_HUMAN as read by caller
	// openConfirmTTY returns a reader/writer pair representing the
	// controlling terminal (/dev/tty in production), plus a closer the
	// caller must invoke. If the TTY cannot be opened, err is returned and
	// the gate fails — humans always have a /dev/tty even when stdin is
	// redirected; AI runtimes that redirect both ends do not.
	openConfirmTTY func() (io.Reader, io.Writer, io.Closer, error)
}

// checkNoRedactGate runs the layered checks before --no-redact disables
// the RedactingWriter. The bypass it closes: an AI calls MCP run_with_secrets
// with `opq exec --no-redact --env X=key -- sh -c 'printf %s "$X"'`; the
// outer MCP RedactingWriter has no secrets registered for the inner exec's
// argv, so the resolved plaintext flows straight back to the AI.
func checkNoRedactGate(cfg noRedactGateConfig) (userReason, auditReason string, err error) {
	if !cfg.stdoutIsTTY {
		return "stdout not a tty", GateReasonStdoutNoTTY, errNoRedactGate
	}
	if cfg.envHumanFlag != "1" {
		return "missing OPQ_I_AM_HUMAN=1", GateReasonEnvMissing, errNoRedactGate
	}
	r, w, closer, openErr := cfg.openConfirmTTY()
	if openErr != nil {
		return "no controlling tty: " + openErr.Error(), GateReasonNoTTY, errNoRedactGate
	}
	defer closer.Close()
	if _, werr := fmt.Fprintf(w, "%s", noRedactConfirmInputPrompt); werr != nil {
		return "tty write: " + werr.Error(), GateReasonTTYWrite, errNoRedactGate
	}
	br := bufio.NewReader(r)
	line, rerr := br.ReadString('\n')
	if rerr != nil && rerr != io.EOF {
		return "tty read: " + rerr.Error(), GateReasonTTYRead, errNoRedactGate
	}
	got := strings.TrimRight(line, "\r\n")
	if got != noRedactConfirmInputLiteral {
		return "confirmation mismatch", GateReasonConfirmMismatch, errNoRedactGate
	}
	return "", "", nil
}

func (c *ExecCmd) Run() error {
	// kong's passthrough captures "--" literally as the first positional;
	// strip it so users can write the conventional `opq exec ... -- cmd`.
	if len(c.Command) > 0 && c.Command[0] == "--" {
		c.Command = c.Command[1:]
	}
	if len(c.Command) == 0 {
		return errors.New("missing command to run (example: opq exec --env OPENAI_API_KEY=openai_api_key -- curl https://api.openai.com)")
	}

	if c.NoRedact {
		cfg := noRedactGateConfig{
			stdoutIsTTY:    term.IsTerminal(int(os.Stdout.Fd())),
			envHumanFlag:   os.Getenv(envHumanConfirm),
			openConfirmTTY: openControllingTTY,
		}
		if userReason, auditReason, err := checkNoRedactGate(cfg); err != nil {
			_ = AppendAudit(AuditEvent{
				Action:  ActionDenied,
				Caller:  callerTag(),
				Message: "no_redact_refused:" + auditReason,
			})
			return fmt.Errorf("refusing to run --no-redact (%s). "+
				"This flag is gated to human operators: stdout must be a TTY, "+
				"%s=1 must be set inline on the command (do NOT export it), and you "+
				"must retype 'no-redact' on the controlling terminal", userReason, envHumanConfirm)
		}
	}

	envMappings, err := parseEnvMappings(c.Env)
	if err != nil {
		return err
	}

	profile, err := parseSandboxFlag(c.Sandbox)
	if err != nil {
		return err
	}
	if err := preflightExecutable(c.Command[0]); err != nil {
		return err
	}
	if profile != SandboxNone {
		if err := VerifySandboxAvailable(); err != nil {
			return fmt.Errorf("sandbox=%s requested but unavailable: %w", profile, err)
		}
	}
	execCmd, execArgs, err := WrapCommand(profile, c.Command[0], c.Command[1:])
	if err != nil {
		return fmt.Errorf("wrap command for sandbox: %w", err)
	}

	ctx := context.Background()
	backend, err := OpenDefaultBackend()
	if err != nil {
		return err
	}

	// Resolve all secrets up front so we fail before spawning anything.
	type resolved struct {
		envName string
		buf     *Buffer
	}
	resolvedSecrets := make([]resolved, 0, len(envMappings))
	cleanup := func() {
		for _, r := range resolvedSecrets {
			r.buf.Destroy()
		}
	}
	defer cleanup()

	now := time.Now().UTC()
	for _, m := range envMappings {
		buf, err := resolveSecret(ctx, backend, m.secretName, now)
		if err != nil {
			_ = AppendAudit(AuditEvent{Action: ActionDenied, SecretName: m.secretName, Caller: callerTag(), Message: sanitizePolicyErr(err)})
			return fmt.Errorf("resolve %s: %w", m.secretName, err)
		}
		resolvedSecrets = append(resolvedSecrets, resolved{envName: m.envName, buf: buf})
		_ = AppendAudit(AuditEvent{Action: ActionExecInject, SecretName: m.secretName, Caller: callerTag()})
	}

	if c.NoRedact {
		// Do NOT log the full argv: shell-style invocations can pass tokens
		// inline (e.g. `sh -c 'curl -H "Auth: sk-..."'`) and that would land
		// in the audit log in plaintext. Log only the binary basename plus
		// an arg-count so the loud `redaction_disabled` entry remains useful
		// for review without leaking caller-controlled values.
		_ = AppendAudit(AuditEvent{
			Action:  ActionRedactionDisabled,
			Caller:  callerTag(),
			Message: fmt.Sprintf("%s (+%d args)", filepath.Base(c.Command[0]), len(c.Command)-1),
		})
	}

	// Build child env: copy parent, drop our internal vars, append secrets.
	childEnv := filterParentEnv(os.Environ())
	for _, r := range resolvedSecrets {
		// We must construct one string per env var. The Go runtime copies
		// these into the exec's argv-equivalent. Keep the lifetime short:
		// all validation and command wrapping has succeeded, so build, hand
		// to exec.Cmd, then drop references as soon as Start copies them.
		childEnv = append(childEnv, r.envName+"="+string(r.buf.Bytes()))
	}

	cmd := exec.CommandContext(ctx, execCmd, execArgs...)
	cmd.Env = childEnv
	cmd.Stdin = os.Stdin

	var stdoutW, stderrW = os.Stdout, os.Stderr
	var stdoutRW, stderrRW *RedactingWriter
	if !c.NoRedact {
		named := make([]NamedSecret, 0, len(resolvedSecrets))
		for _, r := range resolvedSecrets {
			named = append(named, NamedSecret{Name: r.envName, Value: r.buf.Bytes()})
		}
		stdoutRW = NewRedactingWriter(os.Stdout, named)
		stderrRW = NewRedactingWriter(os.Stderr, named)
		cmd.Stdout = stdoutRW
		cmd.Stderr = stderrRW
		// Destroy after subprocess exits — done below.
		defer stdoutRW.Destroy()
		defer stderrRW.Destroy()
		_ = stdoutW // suppress unused if branch differs
		_ = stderrW
	} else {
		cmd.Stdout = stdoutW
		cmd.Stderr = stderrW
	}

	// Forward signals to the child so users can ^C cleanly.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigCh)

	if err := cmd.Start(); err != nil {
		clearEnvStrings(childEnv)
		childEnv = nil
		cmd.Env = nil
		return fmt.Errorf("start child: %w", err)
	}
	// childEnv contains strings holding the secret values. Go strings are
	// immutable, so we cannot wipe their backing bytes in place. Clear every
	// reference we control immediately after exec.Start copies the environment
	// into the child; the mlocked source lives in resolvedSecrets and is
	// Destroyed via defer above.
	clearEnvStrings(childEnv)
	childEnv = nil
	cmd.Env = nil

	// done lets the signal-forwarding goroutine exit once Wait returns,
	// instead of leaking blocked on sigCh. fwdDone joins the goroutine before
	// Run returns so the deferred signal.Stop cannot race the last forward.
	done := make(chan struct{})
	fwdDone := make(chan struct{})
	go func() {
		defer close(fwdDone)
		forwardSignals(sigCh, done, func(sig os.Signal) { _ = cmd.Process.Signal(sig) })
	}()

	waitErr := cmd.Wait()
	close(done)
	<-fwdDone
	if !c.NoRedact {
		_ = stdoutRW.Flush()
		_ = stderrRW.Flush()
	}

	if waitErr != nil {
		// Propagate the child's exit code through a typed error so all
		// defers (mlocked-buffer Destroy, redactor Destroy, signal.Stop,
		// top-level memguard.Purge in main) run before the process exits.
		var ee *exec.ExitError
		if errors.As(waitErr, &ee) {
			return &exitCodeError{code: ee.ExitCode()}
		}
		return waitErr
	}
	return nil
}

// forwardSignals relays every signal received on sigCh to signaller until
// done is closed. Looping (rather than returning after one signal) lets a
// second ^C reach a hung child after the first is dropped or ignored.
func forwardSignals(sigCh <-chan os.Signal, done <-chan struct{}, signaller func(os.Signal)) {
	for {
		select {
		case sig := <-sigCh:
			signaller(sig)
		case <-done:
			return
		}
	}
}

type envMapping struct {
	envName    string
	secretName string
}

func parseEnvMappings(specs []string) ([]envMapping, error) {
	out := make([]envMapping, 0, len(specs))
	seen := map[string]bool{}
	for _, s := range specs {
		eq := strings.IndexByte(s, '=')
		if eq <= 0 || eq == len(s)-1 {
			return nil, fmt.Errorf("invalid --env %q (expected VAR=secret_name)", s)
		}
		envName, secretName := s[:eq], s[eq+1:]
		if !validEnvName(envName) {
			return nil, fmt.Errorf("invalid env var name %q", envName)
		}
		if isBlockedEnvName(envName) {
			return nil, fmt.Errorf("env var %q is on the injected-env deny-list (PATH, LD_*, BASH_ENV, etc. — see env_policy.go); cannot be injected via --env", envName)
		}
		if !validSecretName(secretName) {
			return nil, fmt.Errorf("invalid secret name %q (must match [A-Za-z0-9_.-]{1,128})", secretName)
		}
		if seen[envName] {
			return nil, fmt.Errorf("env var %q specified twice", envName)
		}
		seen[envName] = true
		out = append(out, envMapping{envName: envName, secretName: secretName})
	}
	return out, nil
}

// maxEnvNameBytes caps the length of an injected env-var name. Real POSIX
// names are short (PATH, HOME, OPENAI_API_KEY, ...); the cap exists to bound
// the env-table size a single --env / Env-map entry can produce, not to
// enforce a strict POSIX rule.
const maxEnvNameBytes = 256

func validEnvName(s string) bool {
	if s == "" {
		return false
	}
	if len(s) > maxEnvNameBytes {
		return false
	}
	for i, r := range s {
		switch {
		case r == '_':
		case r >= 'A' && r <= 'Z':
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}

// filterParentEnv drops internal OPQ_* vars from the inherited env so
// they cannot leak into the subprocess.
func filterParentEnv(env []string) []string {
	out := make([]string, 0, len(env))
	for _, e := range env {
		if strings.HasPrefix(e, "OPQ_") {
			continue
		}
		out = append(out, e)
	}
	return out
}
