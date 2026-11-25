// Package main: MCP server surface.
//
// SECURITY MODEL: read before touching any mcp*.go file.
//
// There is no get_secret_value tool. This prevents direct retrieval but does
// not prevent a malicious command from encoding a secret in its output.
// run_with_secrets lets the AI *use* a secret: it runs a subprocess
// with secrets injected as env vars and returns redacted stdout/stderr.
//
// Three channels in that flow cannot be closed by any byte-exact redactor; they
// are documented so nobody "fixes" them with a false sense of security:
//
//  1. SUBPROCESS EXFILTRATION. The AI picks the command, so it can move the
//     secret off-box (network, or a file it reads back via another tool). The
//     default sandbox blocks the network path; redaction only guards
//     *accidental* echo to stdout/stderr; it is not a sandbox.
//
//  2. ENCODING BYPASS. The redactor registers each secret's raw, base64
//     (std/URL, ±pad), and hex forms (see encodedSecretForms), so common
//     accidental re-encodings are caught. Exotic encodings (URL-percent,
//     base32, custom ciphers) are not; an adversary can always pick one.
//
//  3. OUTPUT-VOLUME SIDE CHANNEL. The AI controls output length, so the byte
//     count leaks secret bits. Padding is ineffective because a caller can
//     distinguish chosen output content from padding. Both content and length
//     remain channels; use approved operations for adversarial clients.
//
// For high-risk use the intended model is a policy-enforcing wrapper that
// allowlists (command, args, secret) tuples; this surface is a low-trust
// building block, not that proxy. The resource bounds below cap blast radius;
// they do not make run_with_secrets a sandbox.
//
// The surface is split across files by tool/concern (all package main):
//
//	mcp.go              this file: server wiring + resource bounds.
//	mcp_list.go         list_secrets tool.
//	mcp_run.go          run_with_secrets tool + sandbox/timeout/exit helpers.
//	mcp_output.go       output pipeline: cappedWriter.
//	mcp_audit_tail.go   audit_tail tool + self-entry nonce strip.
//	mcp_audit_filter.go AI-visible audit line/message filtering.
//	mcp_errors.go       aiErr/aiUserErr/sanitizeErrForAI.
package main

import (
	"context"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
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
	mcpMaxOutputBytes    = 256 * 1024
	mcpMaxEnvCount       = 32
	mcpMaxArgCount       = 256
	mcpMaxAuditTailN     = 200
	mcpMaxArgBytes       = 1 << 20
	mcpMaxConcurrentRuns = 4
)

var mcpRunSlots = make(chan struct{}, mcpMaxConcurrentRuns)

func boolPtr(b bool) *bool { return &b }

// newMCPServer wires the tools we expose to AI clients. Note that there is
// deliberately NO tool that returns a plaintext secret value; that's the
// whole point of this CLI. Tools exposed:
//
//	list_secrets         names only.
//	run_with_secrets     execute a subprocess with secrets injected as env
//	                     vars; stdout/stderr are redacted before return.
//	audit_tail           recent audit-log entries (JSON lines).
func newMCPServer(lifetime context.Context) (*mcp.Server, error) {
	srv := mcp.NewServer(&mcp.Implementation{
		Name:    "opq",
		Version: resolveVersion(),
	}, nil)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "list_secrets",
		Description: "List the names of secrets available in the user's keyring. Values are never returned.",
		Annotations: &mcp.ToolAnnotations{
			Title:           "List Secrets",
			ReadOnlyHint:    true,
			IdempotentHint:  true,
			DestructiveHint: boolPtr(false),
			OpenWorldHint:   boolPtr(false),
		},
	}, withServerLifetime(lifetime, handleListSecrets))

	mcp.AddTool(srv, &mcp.Tool{
		Name: "run_with_secrets",
		Description: strings.Join([]string{
			"Run a subprocess with named secrets injected as environment variables. Stdout and stderr are byte-redacted (raw, common base64, and common hex forms replaced with [REDACTED:VAR]) and capped at 256 KiB per stream.",
			"",
			"ENVIRONMENT: The child inherits no parent env vars and receives only PATH=/usr/bin:/usr/sbin:/bin:/sbin, HOME=/tmp, and the requested env secrets. Pass absolute paths for Homebrew or user-installed binaries (for example, /opt/homebrew/bin/jq).",
			"",
			"SANDBOX & NETWORK:",
			"- Default (allow_network=false, isolation=\"readonly\" or \"net\"): external networking is blocked (Linux namespaces or macOS Seatbelt) and the host filesystem is read-only. On Linux /tmp is an isolated empty tmpfs; on macOS all writes—including /tmp and /dev/null—are denied under the sandbox.",
			"- allow_network=true: permits external networking (recorded in the operator audit log as network_allowed) while keeping the read-only filesystem and protected-socket sandbox. Requires isolation=\"readonly\" (or \"net\"); cannot be combined with isolation=\"full\".",
			"- isolation=\"full\": blocks network and restricts host-file reads (minimal read-only system mounts with empty /home and /tmp on Linux; denies $HOME and temp reads via Seatbelt on macOS).",
			"",
			"SECURITY CAVEATS:",
			"(1) Even when sandboxed, the child shares the host kernel; loopback, kernel-keyring, and timing side channels are not blocked.",
			"(2) Redaction is byte-exact for raw, common base64, and common hex forms; URL percent-encoding, base32, and custom encodings are not covered.",
			"(3) Secret values are never returned by any tool, and detailed telemetry (raw exit codes, elapsed timing, output truncation, and expired/revoked policy states) lives in the operator audit log only—never in tool responses or audit_tail.",
			"Assume the operator treats any command you run as authorized use of every secret you request.",
		}, "\n"),
		InputSchema: runWithSecretsInputSchema(),
		Annotations: &mcp.ToolAnnotations{
			Title:           "Run Command with Secrets",
			ReadOnlyHint:    false,
			IdempotentHint:  false,
			DestructiveHint: boolPtr(true),
			OpenWorldHint:   boolPtr(true),
		},
	}, withServerLifetime(lifetime, handleRunWithSecrets))

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "audit_tail",
		Description: "Return the most recent opq audit-log entries as JSON-line strings (default 20, capped at 200 per call). Each call appends a self-audit entry to the operator log.",
		InputSchema: auditTailInputSchema(),
		Annotations: &mcp.ToolAnnotations{
			Title:           "Tail Audit Log",
			ReadOnlyHint:    true,
			IdempotentHint:  false,
			DestructiveHint: boolPtr(false),
			OpenWorldHint:   boolPtr(false),
		},
	}, withServerLifetime(lifetime, handleAuditTail))

	return srv, nil
}

// The SDK detaches request contexts from the Run context. Bind our handlers
// explicitly so graceful shutdown cancels active consuming commands too.
func withServerLifetime[In, Out any](lifetime context.Context, handler mcp.ToolHandlerFor[In, Out]) mcp.ToolHandlerFor[In, Out] {
	return func(ctx context.Context, req *mcp.CallToolRequest, input In) (*mcp.CallToolResult, Out, error) {
		ctx, cancel := context.WithCancel(ctx)
		stop := context.AfterFunc(lifetime, cancel)
		defer stop()
		defer cancel()
		if lifetime.Err() != nil {
			cancel()
		}
		return handler(ctx, req, input)
	}
}

func runMCPServer(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	srv, err := newMCPServer(ctx)
	if err != nil {
		return err
	}
	err = srv.Run(ctx, &disconnectTransport{Transport: &mcp.StdioTransport{}, cancel: cancel})
	// Closing stdin and context cancellation are normal end-of-session events.
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

// EOF must cancel handlers before the SDK waits for in-flight calls to finish.
// Otherwise a disconnected client can leave commands running until their timeout.
type disconnectTransport struct {
	mcp.Transport
	cancel context.CancelFunc
}

func (t *disconnectTransport) Connect(ctx context.Context) (mcp.Connection, error) {
	conn, err := t.Transport.Connect(ctx)
	if err != nil {
		t.cancel()
		return nil, err
	}
	return &disconnectConnection{Connection: conn, cancel: t.cancel}, nil
}

type disconnectConnection struct {
	mcp.Connection
	cancel context.CancelFunc
}

func (c *disconnectConnection) Read(ctx context.Context) (jsonrpc.Message, error) {
	msg, err := c.Connection.Read(ctx)
	if err != nil {
		c.cancel()
	}
	return msg, err
}

func (c *disconnectConnection) Write(ctx context.Context, msg jsonrpc.Message) error {
	err := c.Connection.Write(ctx, msg)
	if err != nil {
		c.cancel()
	}
	return err
}

func (c *disconnectConnection) Close() error {
	c.cancel()
	return c.Connection.Close()
}
