// policy-proxy is an opt-in MCP deployment example, configured by an operator.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	maxOperationDescriptionBytes = 512
	maxStartupStderrBytes        = 4096
)

type config struct {
	Opq        string      `json:"opq"`
	Operations []operation `json:"operations"`
}

type operation struct {
	Name           string            `json:"name"`
	Description    string            `json:"description,omitempty"`
	Command        string            `json:"command"`
	Args           []string          `json:"args"`
	Env            map[string]string `json:"env"`
	TimeoutSeconds int               `json:"timeout_seconds"`
	AllowNetwork   bool              `json:"allow_network"`
	Isolation      string            `json:"isolation"`
}

type status struct {
	Succeeded bool `json:"succeeded"`
	TimedOut  bool `json:"timed_out"`
}

type toolCaller interface {
	CallTool(context.Context, *mcp.CallToolParams) (*mcp.CallToolResult, error)
}

var (
	operationName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,63}$`)
	envName       = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	secretName    = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)
)

func readConfig(r io.Reader) (config, error) {
	const maxConfigBytes = 1 << 20
	data, err := io.ReadAll(io.LimitReader(r, maxConfigBytes+1))
	if err != nil || len(data) > maxConfigBytes {
		return config{}, errors.New("cannot read configuration within size limit")
	}
	// encoding/json normally accepts duplicate keys; a policy must be unambiguous.
	if err := checkJSONValue(json.NewDecoder(bytes.NewReader(data))); err != nil {
		return config{}, errors.New("invalid or duplicate configuration fields")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var cfg config
	if err := dec.Decode(&cfg); err != nil {
		return config{}, errors.New("invalid configuration fields")
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return config{}, errors.New("configuration must contain exactly one object")
	}
	return cfg, validateConfig(cfg)
}

func checkJSONValue(dec *json.Decoder) error {
	token, err := dec.Token()
	if err != nil {
		return err
	}
	switch token {
	case json.Delim('{'):
		seen := map[string]bool{}
		for dec.More() {
			key, err := dec.Token()
			if err != nil {
				return err
			}
			name := strings.ToLower(key.(string))
			if seen[name] {
				return errors.New("duplicate key")
			}
			seen[name] = true
			if err := checkJSONValue(dec); err != nil {
				return err
			}
		}
		_, err = dec.Token()
	case json.Delim('['):
		for dec.More() {
			if err := checkJSONValue(dec); err != nil {
				return err
			}
		}
		_, err = dec.Token()
	}
	return err
}

func hasInvalidDescriptionChars(s string) bool {
	if !utf8.ValidString(s) {
		return true
	}
	for _, r := range s {
		if r == 0 || (unicode.IsControl(r) && r != '\t') {
			return true
		}
	}
	return false
}

func operationDescription(op operation) string {
	const contract = "Takes no arguments; returns status only."
	desc := strings.TrimSpace(op.Description)
	if desc == "" {
		return "Run this operator-approved fixed operation. " + contract
	}
	if !strings.HasSuffix(desc, ".") && !strings.HasSuffix(desc, "!") && !strings.HasSuffix(desc, "?") {
		desc += "."
	}
	return desc + " " + contract
}

func validateConfig(cfg config) error {
	if strings.ContainsRune(cfg.Opq, 0) {
		return errors.New("opq path contains NUL byte")
	}
	if !filepath.IsAbs(cfg.Opq) {
		return fmt.Errorf("opq must name an absolute executable path (got %q)", cfg.Opq)
	}
	if len(cfg.Operations) > 64 {
		return fmt.Errorf("too many approved operations (%d > max 64)", len(cfg.Operations))
	}
	seen := map[string]bool{}
	for i, op := range cfg.Operations {
		if !operationName.MatchString(op.Name) {
			return fmt.Errorf("operations[%d]: invalid operation name %q (must match ^[A-Za-z][A-Za-z0-9_-]{0,63}$)", i, op.Name)
		}
		if op.Name == "run_with_secrets" || op.Name == "list_secrets" || op.Name == "audit_tail" {
			return fmt.Errorf("operations[%d]: operation name %q is reserved", i, op.Name)
		}
		if seen[op.Name] {
			return fmt.Errorf("operations[%d]: duplicate operation name %q", i, op.Name)
		}
		seen[op.Name] = true
		if len(op.Description) > maxOperationDescriptionBytes {
			return fmt.Errorf("operation %q: description exceeds %d bytes (%d)", op.Name, maxOperationDescriptionBytes, len(op.Description))
		}
		if hasInvalidDescriptionChars(op.Description) {
			return fmt.Errorf("operation %q: description contains invalid control characters", op.Name)
		}
		if strings.ContainsRune(op.Command, 0) {
			return fmt.Errorf("operation %q: command contains NUL byte", op.Name)
		}
		if !filepath.IsAbs(op.Command) {
			return fmt.Errorf("operation %q: command must name an absolute executable path (got %q)", op.Name, op.Command)
		}
		if op.TimeoutSeconds < 1 || op.TimeoutSeconds > 600 {
			return fmt.Errorf("operation %q: timeout_seconds must be between 1 and 600 (got %d)", op.Name, op.TimeoutSeconds)
		}
		if len(op.Args) > 256 {
			return fmt.Errorf("operation %q: too many args (%d > max 256)", op.Name, len(op.Args))
		}
		if len(op.Env) > 32 {
			return fmt.Errorf("operation %q: too many env entries (%d > max 32)", op.Name, len(op.Env))
		}
		if op.Isolation != "net" && op.Isolation != "readonly" && op.Isolation != "full" {
			return fmt.Errorf("operation %q: unknown isolation %q (want readonly, net, or full)", op.Name, op.Isolation)
		}
		if op.AllowNetwork && op.Isolation == "full" {
			return fmt.Errorf("operation %q: allow_network=true cannot be combined with isolation=\"full\" (use \"readonly\" or \"net\")", op.Name)
		}
		for j, arg := range op.Args {
			if strings.ContainsRune(arg, 0) {
				return fmt.Errorf("operation %q: args[%d] contains NUL byte", op.Name, j)
			}
		}
		envNames := make([]string, 0, len(op.Env))
		for name := range op.Env {
			envNames = append(envNames, name)
		}
		sort.Strings(envNames)
		for _, name := range envNames {
			secret := op.Env[name]
			if !envName.MatchString(name) {
				return fmt.Errorf("operation %q: invalid env var name %q (must match ^[A-Za-z_][A-Za-z0-9_]*$)", op.Name, name)
			}
			if !secretName.MatchString(secret) {
				return fmt.Errorf("operation %q: env %q references invalid secret name %q (must match ^[A-Za-z0-9_.-]{1,128}$)", op.Name, name, secret)
			}
		}
	}
	return nil
}

func newProxy(lifetime context.Context, cfg config, upstream toolCaller) *mcp.Server {
	srv := mcp.NewServer(&mcp.Implementation{Name: "opq-policy-proxy", Version: "1"}, nil)
	// Reject excess calls rather than keeping an unbounded queue.
	slots := make(chan struct{}, 2)
	for _, op := range cfg.Operations {
		args := op.Args
		if args == nil {
			args = []string{}
		}
		env := op.Env
		if env == nil {
			env = map[string]string{}
		}
		mcp.AddTool(srv, &mcp.Tool{
			Name:        op.Name,
			Description: operationDescription(op),
			InputSchema: map[string]any{"type": "object", "properties": map[string]any{}, "additionalProperties": false},
		}, func(ctx context.Context, _ *mcp.CallToolRequest, input map[string]json.RawMessage) (*mcp.CallToolResult, status, error) {
			if len(input) != 0 {
				return nil, status{}, errors.New("operation takes no arguments")
			}
			select {
			case slots <- struct{}{}:
				defer func() { <-slots }()
			default:
				return nil, status{}, errors.New("operation capacity reached")
			}
			ctx, cancel := context.WithTimeout(ctx, time.Duration(op.TimeoutSeconds)*time.Second)
			stop := context.AfterFunc(lifetime, cancel)
			defer stop()
			defer cancel()
			if lifetime.Err() != nil {
				cancel()
			}
			if ctx.Err() != nil {
				return nil, status{TimedOut: errors.Is(ctx.Err(), context.DeadlineExceeded)}, nil
			}
			result, err := upstream.CallTool(ctx, &mcp.CallToolParams{
				Name: "run_with_secrets",
				Arguments: map[string]any{
					"command": op.Command, "args": args, "env": env,
					"timeout_seconds": op.TimeoutSeconds, "allow_network": op.AllowNetwork, "isolation": op.Isolation,
				},
			})
			if err != nil || result == nil || result.IsError || ctx.Err() != nil {
				return nil, status{TimedOut: errors.Is(ctx.Err(), context.DeadlineExceeded)}, nil
			}
			// Never return upstream Content, metadata, errors, or stdout/stderr.
			fields, _ := result.StructuredContent.(map[string]any)
			succeeded, successOK := fields["succeeded"].(bool)
			timedOut, timeoutOK := fields["timed_out"].(bool)
			if !successOK || !timeoutOK {
				return nil, status{}, nil
			}
			return nil, status{Succeeded: succeeded && !timedOut, TimedOut: timedOut}, nil
		})
	}
	return srv
}

// boundedStartupBuffer captures up to limit bytes of upstream stderr during
// initialization and discards all output once Stop is called. Captured bytes
// are used strictly for fixed-taxonomy failure classification and are never
// forwarded verbatim.
type boundedStartupBuffer struct {
	mu      sync.Mutex
	stopped bool
	limit   int
	buf     bytes.Buffer
}

func newBoundedStartupBuffer(limit int) *boundedStartupBuffer {
	return &boundedStartupBuffer{limit: limit}
}

func (b *boundedStartupBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.stopped {
		return len(p), nil
	}
	remaining := b.limit - b.buf.Len()
	if remaining > 0 {
		if len(p) > remaining {
			b.buf.Write(p[:remaining])
		} else {
			b.buf.Write(p)
		}
	}
	return len(p), nil
}

func (b *boundedStartupBuffer) Stop() {
	b.mu.Lock()
	b.stopped = true
	b.buf.Reset()
	b.mu.Unlock()
}

func (b *boundedStartupBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// classifyStartupError converts an upstream initialization error and bounded
// startup stderr capture into a fixed, sanitized operator hint. Raw upstream
// stderr, file paths, and library errors are never echoed because MCP hosts
// may surface proxy stderr to an agent.
func classifyStartupError(connectErr error, upstreamStderr string) error {
	switch {
	case errors.Is(connectErr, os.ErrNotExist), errors.Is(connectErr, exec.ErrNotFound):
		return errors.New("cannot connect to opq: configured opq binary not found (check policy 'opq' path)")
	case errors.Is(connectErr, os.ErrPermission), errors.Is(connectErr, fs.ErrPermission):
		return errors.New("cannot connect to opq: configured opq binary is not executable (check file permissions)")
	}
	lower := strings.ToLower(upstreamStderr)
	for _, marker := range []string{
		"subprocess sandbox",
		"bubblewrap",
		"bwrap",
		"sandbox-exec",
		"seatbelt",
		"unprivileged user namespaces",
		"sandbox unavailable",
	} {
		if strings.Contains(lower, marker) {
			return errors.New("cannot connect to opq: upstream subprocess sandbox unavailable (run 'opq doctor' to diagnose)")
		}
	}
	switch {
	case errors.Is(connectErr, context.DeadlineExceeded):
		return errors.New("cannot connect to opq: startup handshake timed out (run 'opq doctor' to diagnose)")
	case errors.Is(connectErr, context.Canceled):
		return errors.New("cannot connect to opq: startup canceled")
	default:
		return errors.New("cannot connect to opq: upstream MCP handshake failed (run 'opq doctor' to diagnose)")
	}
}

func run(ctx context.Context, path string) error {
	ctx, cancelLifetime := context.WithCancel(ctx)
	defer cancelLifetime()
	if !filepath.IsAbs(path) {
		return errors.New("--config must name an absolute operator-controlled file")
	}
	file, err := os.Open(path)
	if err != nil {
		return errors.New("cannot open operator configuration")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
		return errors.New("configuration must be a regular file without group or other write permission")
	}
	cfg, err := readConfig(file)
	if err != nil {
		return err
	}
	// The SDK owns shutdown: close upstream stdin, wait, then signal with a
	// bounded kill fallback. CommandContext's immediate SIGKILL could orphan
	// consuming subprocess groups before opq can cancel and reap them.
	cmd := exec.Command(cfg.Opq, "mcp")
	startupStderr := newBoundedStartupBuffer(maxStartupStderrBytes)
	cmd.Stderr = startupStderr
	cmd.WaitDelay = time.Second
	client := mcp.NewClient(&mcp.Implementation{Name: "opq-policy-proxy", Version: "1"}, nil)
	initCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	upstream, err := client.Connect(initCtx, &mcp.CommandTransport{Command: cmd, TerminateDuration: time.Second}, nil)
	cancel()
	if err != nil {
		if cmd.Process != nil && cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
		return classifyStartupError(err, startupStderr.String())
	}
	startupStderr.Stop()
	defer upstream.Close()
	if err := newProxy(ctx, cfg, upstream).Run(ctx, &disconnectTransport{Transport: &mcp.StdioTransport{}, cancel: cancelLifetime}); err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, context.Canceled) {
		return errors.New("proxy session failed")
	}
	return nil
}

// SDK request contexts outlive the server's Run context. Cancel the lifetime
// before EOF/error/Close reaches the SDK's wait for outstanding handlers.
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

func main() {
	path := flag.String("config", "", "absolute path to operator-controlled JSON policy")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "unexpected arguments")
		os.Exit(2)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, *path); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
