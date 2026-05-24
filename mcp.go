package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
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
			"The plaintext value of each secret is NEVER returned to the caller; subprocess output is redacted before being returned.",
			"Use this whenever you need a tool to consume an API key, token, or password.",
		}, " "),
	}, handleRunWithSecrets)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "audit_tail",
		Description: "Return the most recent opaque audit-log entries as JSON-line strings.",
	}, handleAuditTail)

	return srv, nil
}

func runMCPServer(ctx context.Context, srv *mcp.Server) error {
	err := srv.Run(ctx, &mcp.StdioTransport{})
	// A stdio MCP server shuts down when its peer closes stdin. That is
	// a normal end-of-session, not a failure.
	if err == nil || errors.Is(err, io.EOF) || strings.Contains(err.Error(), "EOF") {
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
		return errResult(err), listSecretsOutput{}, nil
	}
	names, err := backend.List(ctx)
	if err != nil {
		return errResult(err), listSecretsOutput{}, nil
	}
	_ = AppendAudit(AuditEvent{Action: ActionList, Caller: callerTag()})
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: strings.Join(names, "\n")}},
	}, listSecretsOutput{Names: names}, nil
}

// ----- run_with_secrets -----

type runWithSecretsInput struct {
	Command string            `json:"command" jsonschema:"executable to run (absolute path or name resolvable via PATH)"`
	Args    []string          `json:"args,omitempty" jsonschema:"arguments to pass to the command"`
	Env     map[string]string `json:"env" jsonschema:"mapping of ENV_VAR_NAME -> secret_name; the named secret's value will be set in the subprocess environment"`
}

type runWithSecretsOutput struct {
	ExitCode int    `json:"exit_code"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
}

func handleRunWithSecrets(ctx context.Context, _ *mcp.CallToolRequest, input runWithSecretsInput) (*mcp.CallToolResult, runWithSecretsOutput, error) {
	if input.Command == "" {
		return errResult(errors.New("command is required")), runWithSecretsOutput{}, nil
	}

	backend, err := OpenDefaultBackend()
	if err != nil {
		return errResult(err), runWithSecretsOutput{}, nil
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

	for envName, secretName := range input.Env {
		if !validEnvName(envName) {
			return errResult(fmt.Errorf("invalid env var name %q", envName)), runWithSecretsOutput{}, nil
		}
		buf, err := backend.Get(ctx, secretName)
		if err != nil {
			_ = AppendAudit(AuditEvent{Action: ActionDenied, SecretName: secretName, Caller: callerTag(), Message: err.Error()})
			return errResult(fmt.Errorf("resolve %s: %w", secretName, err)), runWithSecretsOutput{}, nil
		}
		bufs = append(bufs, resolved{envName: envName, buf: buf})
		_ = AppendAudit(AuditEvent{Action: ActionMCPRun, SecretName: secretName, Caller: callerTag()})
	}

	childEnv := filterParentEnv(envFromMap()) // empty parent inheritance under MCP
	for _, r := range bufs {
		childEnv = append(childEnv, r.envName+"="+string(r.buf.Bytes()))
	}

	var stdoutBuf, stderrBuf bytes.Buffer
	named := make([]NamedSecret, 0, len(bufs))
	for _, r := range bufs {
		named = append(named, NamedSecret{Name: r.envName, Value: r.buf.Bytes()})
	}
	stdoutRW := NewRedactingWriter(&stdoutBuf, named)
	stderrRW := NewRedactingWriter(&stderrBuf, named)
	defer stdoutRW.Destroy()
	defer stderrRW.Destroy()

	cmd := exec.CommandContext(ctx, input.Command, input.Args...)
	cmd.Env = childEnv
	cmd.Stdout = stdoutRW
	cmd.Stderr = stderrRW

	exitCode := 0
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			exitCode = ee.ExitCode()
		} else {
			return errResult(err), runWithSecretsOutput{}, nil
		}
	}
	_ = stdoutRW.Flush()
	_ = stderrRW.Flush()

	out := runWithSecretsOutput{
		ExitCode: exitCode,
		Stdout:   stdoutBuf.String(),
		Stderr:   stderrBuf.String(),
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("exit=%d\n--- stdout ---\n%s\n--- stderr ---\n%s", out.ExitCode, out.Stdout, out.Stderr)}},
	}, out, nil
}

// envFromMap returns an empty slice for now. We intentionally do NOT
// inherit the MCP server's parent environment into subprocesses; the AI
// must declare every env var it wants, and only secret-backed values can
// be injected. If a future need to pass through specific vars arises,
// add an allowlist field to runWithSecretsInput.
func envFromMap() []string { return nil }

// ----- audit_tail -----

type auditTailInput struct {
	N int `json:"n,omitempty" jsonschema:"number of trailing entries; default 20"`
}

type auditTailOutput struct {
	Entries []string `json:"entries"`
}

func handleAuditTail(_ context.Context, _ *mcp.CallToolRequest, input auditTailInput) (*mcp.CallToolResult, auditTailOutput, error) {
	n := input.N
	if n <= 0 {
		n = 20
	}
	lines, err := tailAudit(n)
	if err != nil {
		return errResult(err), auditTailOutput{}, nil
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: strings.Join(lines, "\n")}},
	}, auditTailOutput{Entries: lines}, nil
}

func errResult(err error) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}},
	}
}
