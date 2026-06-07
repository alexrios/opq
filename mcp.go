// Package main — MCP server surface.
//
// SECURITY MODEL — read before touching any mcp*.go file.
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
// allowlists (command, args, secret) tuples; this surface is a low-trust
// building block, not that proxy. The resource bounds below cap blast radius —
// they do not make run_with_secrets a sandbox.
//
// The surface is split across files by tool/concern (all package main):
//
//	mcp.go              — this file: server wiring + resource bounds.
//	mcp_list.go         — list_secrets tool.
//	mcp_run.go          — run_with_secrets tool + sandbox/timeout/exit helpers.
//	mcp_output.go       — output pipeline: cappedWriter + bucket quantization.
//	mcp_audit_tail.go   — audit_tail tool + self-entry nonce strip.
//	mcp_audit_filter.go — AI-visible audit line/message filtering.
//	mcp_errors.go       — aiErr/aiUserErr/sanitizeErrForAI.
package main

import (
	"context"
	"errors"
	"io"
	"strings"
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
