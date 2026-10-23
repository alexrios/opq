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
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type config struct {
	Opq        string      `json:"opq"`
	Operations []operation `json:"operations"`
}

type operation struct {
	Name           string            `json:"name"`
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

func validateConfig(cfg config) error {
	if !filepath.IsAbs(cfg.Opq) || strings.ContainsRune(cfg.Opq, 0) {
		return errors.New("opq must name an absolute executable path")
	}
	if len(cfg.Operations) > 64 {
		return errors.New("too many approved operations")
	}
	seen := map[string]bool{}
	for _, op := range cfg.Operations {
		if !operationName.MatchString(op.Name) || seen[op.Name] || op.Name == "run_with_secrets" || op.Name == "list_secrets" || op.Name == "audit_tail" {
			return errors.New("invalid, duplicate, or reserved operation name")
		}
		seen[op.Name] = true
		if !filepath.IsAbs(op.Command) || strings.ContainsRune(op.Command, 0) {
			return errors.New("operation command must name an absolute executable path")
		}
		if op.TimeoutSeconds < 1 || op.TimeoutSeconds > 600 || len(op.Args) > 256 || len(op.Env) > 32 {
			return errors.New("operation exceeds request limits")
		}
		if op.Isolation != "net" && op.Isolation != "full" || op.AllowNetwork && op.Isolation == "full" {
			return errors.New("invalid operation isolation or network combination")
		}
		for _, arg := range op.Args {
			if strings.ContainsRune(arg, 0) {
				return errors.New("operation argument contains NUL")
			}
		}
		for name, secret := range op.Env {
			if !envName.MatchString(name) || !secretName.MatchString(secret) {
				return errors.New("invalid environment mapping")
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
		mcp.AddTool(srv, &mcp.Tool{
			Name:        op.Name,
			Description: "Run this operator-approved fixed operation. Takes no arguments; returns status only.",
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
					"command": op.Command, "args": op.Args, "env": op.Env,
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
	cmd.Stderr = io.Discard
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
		return errors.New("cannot connect to opq")
	}
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
