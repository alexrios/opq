// Package main — the run_with_secrets MCP tool.
//
// The AI's only way to *use* a secret: run a subprocess with secrets injected
// as env vars and get back redacted stdout/stderr. This is the low-trust
// building block whose three irreducible leak channels are documented in the
// mcp.go header. The handler resolves the sandbox profile, validates and
// resolves the requested secrets (TTL/revocation enforced via resolveSecret),
// wires the redactor→cap output pipeline, runs the child, and returns an
// oracle-minimized result (collapsed exit code, bucketed output lengths).
package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type runWithSecretsInput struct {
	Command        string            `json:"command" jsonschema:"executable to run (absolute path or name resolvable via PATH)"`
	Args           []string          `json:"args,omitempty" jsonschema:"arguments to pass to the command"`
	Env            map[string]string `json:"env" jsonschema:"mapping of ENV_VAR_NAME -> secret_name; the named secret's value will be set in the subprocess environment. Max 32 entries."`
	TimeoutSeconds int               `json:"timeout_seconds,omitempty" jsonschema:"per-call wall-clock timeout in seconds. Defaults to 60. Capped at 600."`
	AllowNetwork   bool              `json:"allow_network,omitempty" jsonschema:"if true, the subprocess runs WITHOUT a network sandbox and can reach external hosts; default false (network blocked)"`
	Isolation      string            `json:"isolation,omitempty" jsonschema:"filesystem isolation: 'net' (default; host FS passthrough) or 'full' (tmpfs /home, /tmp; minimal ro-binds)"`
}

// resolveMCPSandbox maps (AllowNetwork, Isolation) to a profile. Default is
// SandboxNet — the AI gets the secret but can't ship it off-box.
//
//	AllowNetwork=true  + Isolation=""|"net" -> SandboxNetAllowed (audit network_allowed)
//	AllowNetwork=true  + Isolation="full"   -> error (incompatible until v1.2)
//	AllowNetwork=false + Isolation=""|"net" -> SandboxNet (default)
//	AllowNetwork=false + Isolation="full"   -> SandboxFull
//
// allow_network keeps the FS sandbox (SandboxNetAllowed, not SandboxNone) and
// only lifts the netns; otherwise the AI could write the secret to a host path
// and read it back from a later sandboxed call.
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
		return SandboxNetAllowed, nil
	}
	if iso == "full" {
		return SandboxFull, nil
	}
	return SandboxNet, nil
}

// runWithSecretsOutput is the result handed to the AI. Several fields are
// normalized or omitted to deny oracles the AI could drive with a
// secret-conditional command (the raw values go to the operator audit only):
//   - ExitCode is collapsed to {0,1}; the raw 8-bit status is a 1-byte/call oracle.
//   - no stdout_truncated/stderr_truncated flags — each is a 1-bit volume oracle.
//   - Stdout/Stderr lengths are bucket-quantized by quantizeOutputForAI (gap #3);
//     the pad tail is marked [opq-pad] so tooling can strip it.
type runWithSecretsOutput struct {
	Succeeded bool   `json:"succeeded"`
	ExitCode  int    `json:"exit_code"`
	Stdout    string `json:"stdout"`
	Stderr    string `json:"stderr"`
	TimedOut  bool   `json:"timed_out"`
}

// normalizeExit collapses the raw exit code to {0,1} — the entire exit-code
// oracle defense. The raw status reaches the operator audit only.
func normalizeExit(raw int) (bool, int) {
	if raw == 0 {
		return true, 0
	}
	return false, 1
}

// clampTimeout falls back to the default for non-positive requests and silently
// caps at the ceiling (a too-large error isn't actionable by the AI).
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

// auditExecResolutionErr maps an exec-resolution failure (from
// preflightExecutable or WrapCommand, both of which run BEFORE any secret is
// resolved) to an audited, AI-safe CallToolResult. It writes the operator audit
// entry with a bare-token taxonomy Message and returns the response. Shared by
// the two pre-resolution call sites so their taxonomy can't drift.
//
// CRITICAL: the AI-supplied basename is NOT placed in the audit Message — that
// would be an AI-controlled-bytes channel into the operator's log
// (log-poisoning + grep-evasion). It IS echoed back to the AI in the
// not_found/permission cases because the AI supplied input.Command itself; the
// generic fallback carries no caller bytes. The third branch is named
// wrap_command_failed (not sandbox_unavailable) because its most common trigger
// is LookPath on a non-existent absolute path, which does not satisfy
// errors.Is(err, exec.ErrNotFound). See the matching invariant in CLAUDE.md.
func auditExecResolutionErr(err error, command string) *mcp.CallToolResult {
	switch {
	case errors.Is(err, exec.ErrNotFound):
		_ = AppendAudit(AuditEvent{Action: ActionDenied, Caller: callerTag(), Message: "exec_not_found"})
		return aiUserErr("exec_not_found: " + filepath.Base(command))
	case errors.Is(err, fs.ErrPermission):
		_ = AppendAudit(AuditEvent{Action: ActionDenied, Caller: callerTag(), Message: "exec_permission_denied"})
		return aiUserErr("exec_permission_denied: " + filepath.Base(command))
	default:
		_ = AppendAudit(AuditEvent{Action: ActionDenied, Caller: callerTag(), Message: "wrap_command_failed"})
		return aiErr("wrap_command_failed")
	}
}

func handleRunWithSecrets(ctx context.Context, _ *mcp.CallToolRequest, input runWithSecretsInput) (*mcp.CallToolResult, runWithSecretsOutput, error) {
	if input.Command == "" {
		// Our own validation message; safe to return verbatim.
		_ = AppendAudit(AuditEvent{Action: ActionDenied, Caller: callerTag(), Message: "invalid_input"})
		return aiUserErr("command is required"), runWithSecretsOutput{}, nil
	}
	if len(input.Env) > mcpMaxEnvCount {
		// Our own validation message; safe to return verbatim.
		_ = AppendAudit(AuditEvent{Action: ActionDenied, Caller: callerTag(), Message: "invalid_input"})
		return aiUserErr(fmt.Sprintf("too many env vars in one call (%d > %d)", len(input.Env), mcpMaxEnvCount)), runWithSecretsOutput{}, nil
	}
	if len(input.Args) > mcpMaxArgCount {
		// Our own validation message; safe to return verbatim.
		_ = AppendAudit(AuditEvent{Action: ActionDenied, Caller: callerTag(), Message: "invalid_input"})
		return aiUserErr(fmt.Sprintf("too many args in one call (%d > %d)", len(input.Args), mcpMaxArgCount)), runWithSecretsOutput{}, nil
	}

	profile, err := resolveMCPSandbox(input.AllowNetwork, input.Isolation)
	if err != nil {
		// Our own literals; safe to return verbatim.
		return aiUserErr(err.Error()), runWithSecretsOutput{}, nil
	}

	envMappings := make([]envMapping, 0, len(input.Env))
	// Sort env names so the "first failure" is stable across calls. Go's
	// map iteration is randomized; without the sort the audit log would
	// show a different first-rejected secret on every invocation, making
	// failures non-reproducible.
	envNames := make([]string, 0, len(input.Env))
	for k := range input.Env {
		envNames = append(envNames, k)
	}
	sort.Strings(envNames)
	for _, envName := range envNames {
		secretName := input.Env[envName]
		if !validEnvName(envName) {
			_ = AppendAudit(AuditEvent{Action: ActionDenied, Caller: callerTag(), Message: "invalid_env_name"})
			return aiUserErr(fmt.Sprintf("invalid env var name %q", envName)), runWithSecretsOutput{}, nil
		}
		if isBlockedEnvName(envName) {
			// Refuse to inject into a loader/interpreter var (PATH, LD_*,
			// BASH_ENV, ...) — that would be arbitrary code execution.
			_ = AppendAudit(AuditEvent{Action: ActionDenied, Caller: callerTag(), Message: "env_blocked"})
			return aiUserErr(fmt.Sprintf("env var %q is on the injected-env deny-list (PATH, LD_*, BASH_ENV, etc. — see env_policy.go)", envName)), runWithSecretsOutput{}, nil
		}
		if !validSecretName(secretName) {
			// Use a stable taxonomy and audit the validation failure.
			_ = AppendAudit(AuditEvent{Action: ActionDenied, Caller: callerTag(), Message: "invalid_secret_name"})
			return aiUserErr("invalid_secret_name"), runWithSecretsOutput{}, nil
		}
		envMappings = append(envMappings, envMapping{envName: envName, secretName: secretName})
	}

	if err := preflightExecutable(input.Command); err != nil {
		return auditExecResolutionErr(err, input.Command), runWithSecretsOutput{}, nil
	}
	if profile != SandboxNone {
		if err := VerifySandboxAvailable(); err != nil {
			// Sanitize: may carry the bwrap path or OS error.
			return aiErr("sandbox_unavailable"), runWithSecretsOutput{}, nil
		}
	}
	execCmd, execArgs, err := WrapCommand(profile, input.Command, input.Args)
	if err != nil {
		// Sanitize wrapper errors while preserving caller-fixable taxonomy.
		return auditExecResolutionErr(err, input.Command), runWithSecretsOutput{}, nil
	}

	backend, err := OpenDefaultBackend()
	if err != nil {
		// Sanitize: may carry keyring/D-Bus text.
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

	resolvedSecretNames := make([]string, 0, len(envMappings))
	for _, m := range envMappings {
		secretName := m.secretName
		// resolveSecret enforces TTL/revocation (read-only) before any value is
		// returned, so the AI can never inject a lapsed credential.
		buf, err := resolveSecret(ctx, backend, secretName, time.Now().UTC())
		if err != nil {
			// Operator audit keeps the precise reason; the AI gets one
			// state-free token. Distinguishing revoked/expired/not_found would
			// re-leak the tombstone existence filterVisibleSecretNames hides.
			_ = AppendAudit(AuditEvent{Action: ActionDenied, SecretName: secretName, Caller: callerTag(), Message: sanitizePolicyErr(err)})
			switch {
			case errors.Is(err, ErrSecretRevoked), errors.Is(err, ErrSecretExpired), errors.Is(err, ErrSecretNotFound):
				return aiErr("not_found: " + secretName), runWithSecretsOutput{}, nil
			}
			return aiErr("backend_error"), runWithSecretsOutput{}, nil
		}
		bufs = append(bufs, resolved{envName: m.envName, buf: buf})
		resolvedSecretNames = append(resolvedSecretNames, secretName)
	}

	childEnv := filterParentEnv(envFromMap()) // empty parent inheritance under MCP
	// MCP children inherit no env; give them a minimal PATH/HOME so common
	// tools don't fail on a missing one. Inert under SandboxFull.
	childEnv = append(childEnv, "PATH=/usr/bin:/usr/sbin:/bin:/sbin", "HOME=/tmp")
	for _, r := range bufs {
		childEnv = append(childEnv, r.envName+"="+string(r.buf.Bytes()))
	}

	// Pipeline: subprocess -> RedactingWriter -> cappedWriter -> buffer. The
	// redactor MUST sit upstream of the cap so the cap only ever clips
	// already-redacted bytes.
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

	if input.AllowNetwork {
		// Include SecretNames so operators can review network-approved use.
		_ = AppendAudit(AuditEvent{
			Action:      ActionNetworkAllowed,
			Caller:      callerTag(),
			SecretNames: resolvedSecretNames,
			Message:     fmt.Sprintf("command=%s args=%d", filepath.Base(input.Command), len(input.Args)),
		})
	}

	start := time.Now()
	cmd := exec.CommandContext(runCtx, execCmd, execArgs...)
	cmd.Env = childEnv
	cmd.Stdout = stdoutRW
	cmd.Stderr = stderrRW

	runErr := cmd.Start()
	clearEnvStrings(childEnv)
	childEnv = nil
	cmd.Env = nil
	if runErr == nil {
		runErr = cmd.Wait()
	}
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
				Action:      ActionMCPRun,
				Caller:      callerTag(),
				SecretNames: resolvedSecretNames,
				Message:     auditMCPRunMessage(-1, stdoutCap.Truncated(), stderrCap.Truncated(), false, elapsed, sanitizeExecStartErr(runErr)),
			})
			// Sanitize: runErr may carry binary paths / OS error text.
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

	// Truncation flags stay in the operator audit (below) but are not exposed
	// to the AI; quantizeOutputForAI buckets the stream lengths. See the
	// runWithSecretsOutput godoc for the side-channel reasoning.
	out := runWithSecretsOutput{
		Succeeded: succeeded,
		ExitCode:  normalizedExit,
		Stdout:    quantizeOutputForAI(stdoutBuf.String()),
		Stderr:    quantizeOutputForAI(stderrBuf.String()),
		TimedOut:  timedOut,
	}

	_ = AppendAudit(AuditEvent{
		Action:      ActionMCPRun,
		Caller:      callerTag(),
		SecretNames: resolvedSecretNames,
		Message:     auditMCPRunMessage(rawExit, stdoutCap.Truncated(), stderrCap.Truncated(), timedOut, elapsed, ""),
	})

	exitLabel := "success"
	if !succeeded {
		exitLabel = "failure"
	}
	textParts := []string{fmt.Sprintf("exit=%s", exitLabel)}
	if timedOut {
		textParts = append(textParts, "timed_out=true")
	}
	header := strings.Join(textParts, " ")
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("%s\n--- stdout ---\n%s\n--- stderr ---\n%s", header, out.Stdout, out.Stderr)}},
	}, out, nil
}

// auditMCPRunMessage formats the human-operator-facing summary written
// to the audit log after a run_with_secrets call. Includes the raw
// exit code (so operators retain debugging signal that the AI never
// sees), elapsed wall-clock, and any truncation/timeout flags. Secret
// names live in AuditEvent.SecretNames, not in this message.
func auditMCPRunMessage(rawExit int, stdoutTrunc, stderrTrunc, timedOut bool, elapsed time.Duration, extra string) string {
	parts := []string{
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
