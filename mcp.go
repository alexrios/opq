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
	}, withServerLifetime(lifetime, handleListSecrets))

	mcp.AddTool(srv, &mcp.Tool{
		Name: "run_with_secrets",
		Description: strings.Join([]string{
			"Run a subprocess with named secrets injected as environment variables.",
			"Subprocess stdout/stderr is byte-redacted for the injected secrets and common base64/hex forms. Arbitrary output encodings and side channels remain visible; this is protection against accidental disclosure.",
			"NETWORK SANDBOX (DEFAULT): the subprocess uses the platform sandbox with NO external connectivity (Linux namespaces or macOS Seatbelt; DNS, TCP/UDP/IP egress, and outbound HTTP fail). Set `allow_network=true` ONLY when the command's purpose is to reach the network (e.g. an API call). When you opt in, the call is recorded in the operator's audit log as `network_allowed`.",
			"FILESYSTEM ISOLATION (opt-in): isolation=full gives Linux minimal read-only system mounts and empty /home and /tmp. macOS denies home/temp reads with a less hermetic Seatbelt profile. See the public sandbox reference for platform limits.",
			"SECURITY CAVEATS (read before relying on this tool):",
			"(1) Even with the network sandbox, the subprocess shares the kernel with the host. Loopback channels, kernel-keyring inheritance, and timing side-channels are NOT blocked.",
			"(2) The redactor is byte-exact. Raw, common base64, and common hex forms are redacted; URL percent-encoding, base32, and arbitrary custom encodings are NOT covered.",
			"(3) The output you receive does not reveal which secrets were resolved or their values; that information is in the operator's audit log only.",
			"Use this whenever you need a tool to consume an API key, token, or password, but assume the operator is treating any command you run as authorized use of every secret you ask for.",
		}, " "),
	}, withServerLifetime(lifetime, handleRunWithSecrets))

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "audit_tail",
		Description: "Return the most recent opaque audit-log entries as JSON-line strings. Capped at 200 entries per call.",
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
