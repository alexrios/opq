// Package main — MCP server surface.
//
// SECURITY MODEL — read before touching this file.
//
// The core invariant (no plaintext secret value ever crosses the AI boundary)
// holds here by omission: there is no get_secret_value tool. The absence IS the
// control. run_with_secrets lets the AI *use* a secret — it runs a subprocess
// with secrets injected as env vars and returns redacted stdout/stderr.
//
// Three channels in that flow cannot be closed by any byte-exact redactor; they
// are documented so nobody "fixes" them with a false sense of security:
//
//  1. SUBPROCESS EXFILTRATION. The AI picks the command, so it can move the
//     secret off-box (network, or a file it reads back via another tool). The
//     default sandbox blocks the network path; redaction only guards
//     *accidental* echo to stdout/stderr — it is not a sandbox.
//
//  2. ENCODING BYPASS. The redactor registers each secret's raw, base64
//     (std/URL, ±pad), and hex forms (see encodedSecretForms), so common
//     accidental re-encodings are caught. Exotic encodings (URL-percent,
//     base32, custom ciphers) are not — an adversary can always pick one.
//
//  3. OUTPUT-VOLUME SIDE CHANNEL. The AI controls output length, so the byte
//     count leaks secret bits. quantizeOutputForAI pads each stream to fixed
//     buckets, cutting the rate sharply but not to zero (bucket edges are
//     still binary-searchable).
//
// For high-risk use the intended model is a policy-enforcing wrapper that
// allowlists (command, args, secret) tuples; this file is a low-trust building
// block, not that proxy. The resource bounds below cap blast radius — they do
// not make run_with_secrets a sandbox.
package main

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os/exec"
	"path/filepath"
	"sort"
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
	mcpMaxArgCount    = 256
	mcpMaxAuditTailN  = 200
)

// newMCPServer wires the tools we expose to AI clients. Note that there is
// deliberately NO tool that returns a plaintext secret value — that's the
// whole point of this CLI. Tools exposed:
//
//	list_secrets         — names only.
//	run_with_secrets     — execute a subprocess with secrets injected as env
//	                       vars; stdout/stderr are redacted before return.
//	audit_tail           — recent audit-log entries (JSON lines).
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
			"(2) The redactor is byte-exact. Raw, common base64, and common hex forms are redacted; URL percent-encoding, base32, and arbitrary custom encodings are NOT covered.",
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
	// Audit BEFORE the backend call so an AI probing a degraded backend (D-Bus
	// down, keyring locked) by hammering list_secrets still leaves a trace even
	// when every call errors.
	_ = AppendAudit(AuditEvent{Action: ActionList, Caller: callerTag()})
	backend, err := OpenDefaultBackend()
	if err != nil {
		// Sanitize: backend errors may carry keyring/D-Bus text.
		return aiErr("backend_error"), listSecretsOutput{}, nil
	}
	names, err := backend.List(ctx)
	if err != nil {
		return aiErr("backend_error"), listSecretsOutput{}, nil
	}
	// backend.List returns raw keys including companion "meta/" items; the AI
	// must never see the scheme or a revoked secret's surviving tombstone.
	visible := filterVisibleSecretNames(names)
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: strings.Join(visible, "\n")}},
	}, listSecretsOutput{Names: visible}, nil
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

// clampAuditTailN caps the requested tail size so audit_tail can't become a
// wholesale-history enumeration channel.
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
		if errors.Is(err, exec.ErrNotFound) {
			_ = AppendAudit(AuditEvent{
				Action:  ActionDenied,
				Caller:  callerTag(),
				Message: "exec_not_found",
			})
			return aiUserErr("exec_not_found: " + filepath.Base(input.Command)), runWithSecretsOutput{}, nil
		}
		if errors.Is(err, fs.ErrPermission) {
			_ = AppendAudit(AuditEvent{
				Action:  ActionDenied,
				Caller:  callerTag(),
				Message: "exec_permission_denied",
			})
			return aiUserErr("exec_permission_denied: " + filepath.Base(input.Command)), runWithSecretsOutput{}, nil
		}
		_ = AppendAudit(AuditEvent{
			Action:  ActionDenied,
			Caller:  callerTag(),
			Message: "wrap_command_failed",
		})
		return aiErr("wrap_command_failed"), runWithSecretsOutput{}, nil
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
		if errors.Is(err, exec.ErrNotFound) {
			_ = AppendAudit(AuditEvent{
				Action:  ActionDenied,
				Caller:  callerTag(),
				Message: "exec_not_found",
			})
			return aiUserErr("exec_not_found: " + filepath.Base(input.Command)), runWithSecretsOutput{}, nil
		}
		if errors.Is(err, fs.ErrPermission) {
			_ = AppendAudit(AuditEvent{
				Action:  ActionDenied,
				Caller:  callerTag(),
				Message: "exec_permission_denied",
			})
			return aiUserErr("exec_permission_denied: " + filepath.Base(input.Command)), runWithSecretsOutput{}, nil
		}
		_ = AppendAudit(AuditEvent{
			Action:  ActionDenied,
			Caller:  callerTag(),
			Message: "wrap_command_failed",
		})
		return aiErr("wrap_command_failed"), runWithSecretsOutput{}, nil
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

// ----- output bucketing (gap #3 mitigation) -----

// outputBuckets is the closed set of stdout/stderr lengths the AI may
// observe in a run_with_secrets response. Every non-empty stream is
// padded up to the smallest bucket >= its real length. The cap value
// (mcpMaxOutputBytes) MUST be present as the final entry — outputs at
// the cap have already been truncated by cappedWriter and need no
// padding. Earlier buckets follow the geometric power-of-two ladder
// 1 KiB → 4 KiB → 16 KiB → 64 KiB so a small command's response is not
// inflated more than ~4x while the channel remains coarse-grained.
//
// Bits leaked per call (worst case, adversary controls the volume
// function): log2(len(outputBuckets)) bits per stream — today
// log2(5) ≈ 2.3 bits, down from ~17 bits (262144 distinct lengths).
// Recovering one 8-bit secret byte under this regime requires ~4 calls
// instead of 1; expanding the bucket set (more granularity) would
// invert that trade. Do not add intermediate buckets without justifying
// the per-call channel rate against the bandwidth cost.
//
// Empty (len==0) streams are NOT padded; an empty result is a coarse
// 1-bit signal (command emitted nothing) already implicit in the
// AI-controlled command and not worth the bandwidth cost of always
// emitting at least 1 KiB.
var outputBuckets = []int{1024, 4096, 16384, 65536, mcpMaxOutputBytes}

// outputPadMarker is the visible token appended once at the boundary
// between real output and padding. Tooling consuming the response can
// scan for this token and strip the trailing padding. The marker plus
// padding are bytes inside the JSON string value, so a naive
// byte-counter (`len(stdout)`) sees the bucket-quantized total — that
// is the whole point. The marker length is short enough that the
// smallest pad gap (4 bytes when n is 1020 and bucket is 1024) can
// fall below it; in that case we emit only space-padding without the
// marker. The marker bytes themselves are constant across calls and
// therefore not a channel.
const outputPadMarker = "\n[opq-pad]\n"

// nextOutputBucket returns the smallest bucket >= n, or n if n is
// already at or above the largest bucket (which equals mcpMaxOutputBytes).
func nextOutputBucket(n int) int {
	for _, b := range outputBuckets {
		if n <= b {
			return b
		}
	}
	return n
}

// quantizeOutputForAI pads s up to the next outputBuckets boundary so the
// AI-visible len(s) does not reveal fine-grained per-byte information
// about a subprocess output volume. Empty input is returned unchanged
// (see outputBuckets godoc for why). When the padding gap is large
// enough, an `[opq-pad]` marker is included once so AI tooling can
// recognize the suffix as padding; smaller gaps emit only spaces.
//
// Padding is byte-quantized to the bucket length: the returned string
// length is exactly bucket if s was non-empty. Tests verify this
// invariant — do not break it by adding "if pad <= 0 return s" style
// short-circuits past the initial empty check.
func quantizeOutputForAI(s string) string {
	if len(s) == 0 {
		return s
	}
	bucket := nextOutputBucket(len(s))
	pad := bucket - len(s)
	if pad <= 0 {
		return s
	}
	if pad >= len(outputPadMarker) {
		return s + outputPadMarker + strings.Repeat(" ", pad-len(outputPadMarker))
	}
	return s + strings.Repeat(" ", pad)
}

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

func newCappedWriter(inner io.Writer, limit int) *cappedWriter {
	return &cappedWriter{inner: inner, remaining: limit}
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
	// Record every audit_tail call BEFORE the read, so an AI scraping operator
	// activity is itself visible even if the read then fails. A per-call random
	// nonce tags our self-entry so the strip below finds it regardless of
	// position (a PID match broke under concurrent writers / PID reuse). If
	// crypto/rand fails the nonce is empty and the strip no-ops — the AI sees
	// one bookkeeping row, not a security violation; better than crashing.
	nonce := generateAuditNonce()
	_ = AppendAudit(AuditEvent{
		Action:  ActionAuditTail,
		Caller:  callerTag(),
		Message: fmt.Sprintf("n=%d", n),
		Nonce:   nonce,
	})
	lines, err := tailAudit(mcpMaxAuditTailN)
	if err != nil {
		return aiErr("internal_error"), auditTailOutput{}, nil
	}

	// Apply MCP-specific filters (M3 caller filter, C1 raw_exit strip).
	// The self-log entry we just appended (J-5) is included in `lines` and
	// passes the filter — strip it so the AI's requested-n window isn't
	// occupied by its own bookkeeping. The self-log entry's existence
	// remains visible to the operator via `opq audit` and to subsequent
	// AI calls (we strip OUR row only, identified by nonce; older
	// audit_tail entries from prior calls survive as the deterrent the
	// design promises).
	filtered := make([]string, 0, len(lines))
	for _, line := range lines {
		if out, ok := filterAuditLineForAI(line); ok {
			filtered = append(filtered, out)
		}
	}
	filtered = stripSelfAuditTailEntry(filtered, nonce)
	// Return at most the requested n entries (last n after filter).
	if len(filtered) > n {
		filtered = filtered[len(filtered)-n:]
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: strings.Join(filtered, "\n")}},
	}, auditTailOutput{Entries: filtered}, nil
}

// generateAuditNonce returns 32 hex chars (16 random bytes / 128 bits)
// suitable for tagging a single audit entry so the writer can identify
// it among later log lines. Returns the empty string on the (vanishingly
// rare) event that crypto/rand fails — callers must treat the empty
// nonce as "no strip possible" rather than crashing. 128 bits is
// overkill for the tiny collision domain (a few hundred entries in a
// tail window) but cheap and removes any need to think about birthday
// bounds.
func generateAuditNonce() string {
	var buf [16]byte
	if _, err := cryptorand.Read(buf[:]); err != nil {
		return ""
	}
	return hex.EncodeToString(buf[:])
}

// stripSelfAuditTailEntry scans the filtered audit lines and removes
// every ActionAuditTail entry whose Nonce matches the provided value.
// Returns the input unchanged if nonce is empty (graceful degradation
// path when crypto/rand fails) or no match is found.
//
// Why scan instead of strip-last (joint-review 2026-05 P3):
// handleAuditTail writes its self-entry BEFORE reading the log, but a
// concurrent AppendAudit (CLI process, another MCP handler, etc.) can
// land between our write and our read — our entry may then sit anywhere
// in the filtered window, not just at the end. A position-based strip
// either misses our entry (leak) or strips the wrong line (incorrect
// truncation of operator activity). Nonce-based matching is immune to
// reordering and to PID reuse (a previous process that wrote an
// audit_tail entry with the same PID is no longer our concern).
//
// Duplicate nonces would indicate a catastrophic RNG failure (128 bits
// of crypto/rand output colliding). We strip ALL matches rather than
// stop at the first — a defensive choice that costs nothing in the
// success path (zero duplicates) and avoids surfacing a duplicate-row
// puzzle to the AI in the failure path. Malformed JSON entries pass
// through unchanged.
func stripSelfAuditTailEntry(filtered []string, nonce string) []string {
	if nonce == "" {
		return filtered
	}
	out := make([]string, 0, len(filtered))
	for _, line := range filtered {
		var ev AuditEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			// Malformed lines pass through; the AI-visible filter would
			// already have dropped them upstream if they were invalid.
			out = append(out, line)
			continue
		}
		if ev.Action == ActionAuditTail && ev.Nonce == nonce {
			// Strip this entry.
			continue
		}
		out = append(out, line)
	}
	return out
}

// sanitizeErrForAI converts any error into a fixed-taxonomy string that is
// safe to surface to an MCP caller. The original error is preserved for the
// audit log; only the AI-visible CallToolResult uses the sanitized form.
//
// Call context: handleRunWithSecrets uses this only for process-start
// failures. Backend and sandbox errors are mapped at their own call sites.
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

// filterAuditLineForAI filters one raw audit line before it reaches an AI:
//   - caller filter: drop anything not caller="mcp", so CLI-driven entries
//     (get/set/delete, gate failures, operator-chosen sandbox profiles) stay
//     invisible. The prefix match is future-proof for session IDs ("mcp:abc").
//   - message allowlist: for key=value-shaped Messages, strip every token not
//     on aiAuditMessageAllowlist (raw_exit, elapsed_ms, ... are oracles).
//
// Returns ("", false) to drop the line entirely.
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

	// Only MCP-originated (caller="mcp") entries are visible to the AI.
	if !strings.HasPrefix(ev.Caller, "mcp") {
		return "", false
	}

	// The allowlist gate must cover EVERY action whose Message uses the
	// key=value shape: ActionMCPRun, ActionNetworkAllowed, and ActionSet
	// (expires_at). ActionSet is CLI-only today and dropped by the caller
	// filter above, but is listed so a future MCP set path can't leak it.
	// Bare-token actions (ActionDenied: env_blocked, ...) deliberately bypass
	// the gate — the allowlist would drop their whole payload.
	switch ev.Action {
	case ActionMCPRun, ActionNetworkAllowed, ActionSet:
		if ev.Message != "" {
			ev.Message = filterAuditMessageForAI(ev.Message)
		}
	}

	out, err := json.Marshal(ev)
	if err != nil {
		// Should never happen with a valid AuditEvent, but be safe.
		return "", false
	}
	return string(out), true
}

// aiAuditMessageAllowlist is the closed set of `key=value` tokens that may
// appear in an AI-visible audit-log Message. Every other token is dropped.
// Bare (no '=') tokens are also dropped. Adding a key here is a deliberate
// audit-channel widening — every entry below has been reviewed for AI-leak
// implications.
//
//	timed_out — 1-bit oracle, already exposed in the run_with_secrets
//	            result (TimedOut), so allowlisting it in the audit stream
//	            does not enlarge the AI's information surface.
//
// Explicitly NOT on the list (and therefore stripped):
//
//	raw_exit          — 8-bit exit-code oracle; normalizeExit withholds it.
//	elapsed_ms        — wall-clock timing oracle; never exposed in the
//	                    run_with_secrets result, must not leak via audit.
//	stdout_truncated  — output-volume oracle; removed from the response
//	                    struct (see gap #3 in the file header). The AI
//	                    must not be able to recover the flag via audit_tail.
//	stderr_truncated  — same.
//	exec_*            — operator-facing diagnostic detail; not for AI.
//
// Future contributors: do NOT add a key here without writing a one-line
// justification of why the AI seeing it does not enable a side-channel.
var aiAuditMessageAllowlist = map[string]bool{
	"timed_out": true,
}

// filterAuditMessageForAI rebuilds an audit Message containing only tokens
// whose key is on the aiAuditMessageAllowlist. The empty string is returned
// if no tokens survive — that is a valid audit-line state (the `msg` field
// is `omitempty` JSON).
//
// Invariant: every allowlisted token's value MUST NOT contain a literal
// space. The function splits on ' ' to identify tokens, so a space inside a
// value would split it and silently drop the trailing portion. Today every
// producer (auditMCPRunMessage) emits boolean-shaped values; if a future
// allowlist entry needs spaces in its value, switch the format to a
// space-free encoding (e.g. URL encoding) before adding the key.
func filterAuditMessageForAI(msg string) string {
	if msg == "" {
		return ""
	}
	tokens := strings.Split(msg, " ")
	// Allocate a fresh slice instead of aliasing tokens[:0]. The forward-
	// scan loop happens to be safe with aliasing because every append
	// position has already been read, but the invariant is non-local and
	// would silently break if the loop is ever rewritten as a backward
	// scan or rearranged to read positions after writes.
	out := make([]string, 0, len(tokens))
	for _, tok := range tokens {
		key, _, ok := strings.Cut(tok, "=")
		if !ok {
			// Bare token with no '='; drop (cannot be on allowlist).
			continue
		}
		if !aiAuditMessageAllowlist[key] {
			continue
		}
		out = append(out, tok)
	}
	return strings.Join(out, " ")
}
