package main

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const validConfig = `{"opq":"/operator/bin/opq","operations":[{"name":"probe","command":"/usr/bin/true","args":[],"env":{"API_TOKEN":"example_token"},"timeout_seconds":1,"allow_network":false,"isolation":"full"}]}`

func TestConfigValidation(t *testing.T) {
	cases := map[string]string{
		"unknown_root":            strings.Replace(validConfig, `"opq":`, `"unknown":true,"opq":`, 1),
		"unknown_operation":       strings.Replace(validConfig, `"name":`, `"unknown":true,"name":`, 1),
		"duplicate_root":          strings.Replace(validConfig, `"opq":`, `"opq":"/other","opq":`, 1),
		"duplicate_case_alias":    strings.Replace(validConfig, `"opq":`, `"OPQ":"/other","opq":`, 1),
		"duplicate_operation_key": strings.Replace(validConfig, `"name":`, `"name":"other","name":`, 1),
		"duplicate_env_key":       strings.Replace(validConfig, `"API_TOKEN":`, `"API_TOKEN":"other","API_TOKEN":`, 1),
		"relative_opq":            strings.Replace(validConfig, "/operator/bin/opq", "opq", 1),
		"relative_command":        strings.Replace(validConfig, "/usr/bin/true", "true", 1),
		"invalid_name":            strings.Replace(validConfig, `"probe"`, `"../probe"`, 1),
		"reserved_name":           strings.Replace(validConfig, `"probe"`, `"run_with_secrets"`, 1),
		"missing_timeout":         strings.Replace(validConfig, `"timeout_seconds":1`, `"timeout_seconds":0`, 1),
		"network_full":            strings.Replace(validConfig, `"allow_network":false`, `"allow_network":true`, 1),
		"unknown_isolation":       strings.Replace(validConfig, `"isolation":"full"`, `"isolation":"other"`, 1),
		"invalid_env":             strings.Replace(validConfig, "API_TOKEN", "BAD=ENV", 1),
		"invalid_secret":          strings.Replace(validConfig, "example_token", "meta/token", 1),
		"trailing_object":         validConfig + ` {}`,
		"null":                    "null",
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := readConfig(strings.NewReader(data)); err == nil {
				t.Fatal("invalid policy accepted")
			}
		})
	}
	cfg, err := readConfig(strings.NewReader(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Operations = append(cfg.Operations, cfg.Operations[0])
	if err := validateConfig(cfg); err == nil {
		t.Fatal("duplicate operation names accepted")
	}
	if _, err := readConfig(strings.NewReader(`{"opq":"/operator/bin/opq","operations":[]}`)); err != nil {
		t.Fatal(err)
	}
}

type fakeUpstream func(context.Context, *mcp.CallToolParams) (*mcp.CallToolResult, error)

func (f fakeUpstream) CallTool(ctx context.Context, p *mcp.CallToolParams) (*mcp.CallToolResult, error) {
	return f(ctx, p)
}

func connectProxy(t *testing.T, cfg config, upstream toolCaller) (*mcp.ClientSession, context.Context) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	a, b := mcp.NewInMemoryTransports()
	ss, err := newProxy(ctx, cfg, upstream).Connect(ctx, a, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ss.Close() })
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil).Connect(ctx, b, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs, ctx
}

func approvedConfig(t *testing.T) config {
	t.Helper()
	cfg, err := readConfig(strings.NewReader(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestProxyForwardsOnlyFixedOperationAndReturnsOnlyStatus(t *testing.T) {
	cfg := approvedConfig(t)
	var calls atomic.Int32
	upstream := fakeUpstream(func(_ context.Context, p *mcp.CallToolParams) (*mcp.CallToolResult, error) {
		calls.Add(1)
		want := map[string]any{"command": "/usr/bin/true", "args": []string{}, "env": map[string]string{"API_TOKEN": "example_token"}, "timeout_seconds": 1, "allow_network": false, "isolation": "full"}
		if p.Name != "run_with_secrets" || !reflect.DeepEqual(p.Arguments, want) {
			t.Errorf("forwarded request differs from fixed operator configuration")
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "synthetic-private-output"}}, StructuredContent: map[string]any{"succeeded": true, "timed_out": false, "stdout": "synthetic-private-output", "stderr": "synthetic-private-output", "exit_code": 255}}, nil
	})
	cs, ctx := connectProxy(t, cfg, upstream)
	listed, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed.Tools) != 1 || listed.Tools[0].Name != "probe" {
		t.Fatal("proxy exposed tools outside approved operations")
	}
	result, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "probe", Arguments: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "synthetic-private-output") || strings.Contains(string(data), "exit_code") {
		t.Fatal("private upstream fields escaped proxy")
	}
	fields, ok := result.StructuredContent.(map[string]any)
	if !ok || len(fields) != 2 || fields["succeeded"] != true || fields["timed_out"] != false {
		t.Fatal("unexpected typed status")
	}
	result, err = cs.CallTool(ctx, &mcp.CallToolParams{Name: "probe", Arguments: map[string]any{"command": "/bin/sh"}})
	if err == nil && !result.IsError {
		t.Fatal("caller-supplied command accepted")
	}
	_, err = cs.CallTool(ctx, &mcp.CallToolParams{Name: "run_with_secrets", Arguments: map[string]any{}})
	if err == nil {
		t.Fatal("arbitrary upstream tool exposed")
	}
	if calls.Load() != 1 {
		t.Fatal("rejected request reached upstream")
	}
}

func TestEmptyPolicyExposesNoTools(t *testing.T) {
	cs, ctx := connectProxy(t, config{Opq: "/operator/bin/opq"}, fakeUpstream(func(context.Context, *mcp.CallToolParams) (*mcp.CallToolResult, error) {
		t.Error("empty policy forwarded a request")
		return nil, nil
	}))
	result, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Tools) != 0 {
		t.Fatal("empty policy exposed tools")
	}
}

func TestProxyDropsUpstreamErrorsAndMalformedResults(t *testing.T) {
	for _, test := range []struct {
		name   string
		result *mcp.CallToolResult
		err    error
	}{
		{name: "error", err: errors.New("synthetic-private-error")},
		{name: "tool_error", result: &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "synthetic-private-error"}}}},
		{name: "malformed_status", result: &mcp.CallToolResult{StructuredContent: map[string]any{"succeeded": "synthetic-private-error"}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			cs, ctx := connectProxy(t, approvedConfig(t), fakeUpstream(func(context.Context, *mcp.CallToolParams) (*mcp.CallToolResult, error) { return test.result, test.err }))
			result, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "probe", Arguments: map[string]any{}})
			if err != nil {
				t.Fatal(err)
			}
			data, _ := json.Marshal(result)
			if strings.Contains(string(data), "synthetic-private-error") {
				t.Fatal("upstream error escaped proxy")
			}
			fields := result.StructuredContent.(map[string]any)
			if fields["succeeded"] != false {
				t.Fatal("upstream failure reported as success")
			}
		})
	}
}

func TestProxyBoundsConcurrentCalls(t *testing.T) {
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	defer close(release)
	cs, ctx := connectProxy(t, approvedConfig(t), fakeUpstream(func(ctx context.Context, _ *mcp.CallToolParams) (*mcp.CallToolResult, error) {
		entered <- struct{}{}
		select {
		case <-release:
			return &mcp.CallToolResult{StructuredContent: map[string]any{"succeeded": true, "timed_out": false}}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}))
	for range 2 {
		go func() { cs.CallTool(ctx, &mcp.CallToolParams{Name: "probe", Arguments: map[string]any{}}) }()
	}
	for range 2 {
		select {
		case <-entered:
		case <-ctx.Done():
			t.Fatal("approved calls did not start")
		}
	}
	result, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "probe", Arguments: map[string]any{}})
	if err == nil && !result.IsError {
		t.Fatal("proxy exceeded concurrent operation limit")
	}
}

func TestProxyAppliesOperatorTimeout(t *testing.T) {
	cs, ctx := connectProxy(t, approvedConfig(t), fakeUpstream(func(ctx context.Context, _ *mcp.CallToolParams) (*mcp.CallToolResult, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}))
	start := time.Now()
	result, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "probe", Arguments: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatal("operator deadline did not bound call")
	}
	fields := result.StructuredContent.(map[string]any)
	if fields["timed_out"] != true || fields["succeeded"] != false {
		t.Fatal("deadline not represented by typed failure status")
	}
}

func TestOperationDescriptionAndReadonlyIsolation(t *testing.T) {
	t.Run("default description preserved when omitted", func(t *testing.T) {
		cs, ctx := connectProxy(t, approvedConfig(t), fakeUpstream(func(context.Context, *mcp.CallToolParams) (*mcp.CallToolResult, error) {
			return &mcp.CallToolResult{StructuredContent: map[string]any{"succeeded": true, "timed_out": false}}, nil
		}))
		listed, err := cs.ListTools(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		want := "Run this operator-approved fixed operation. Takes no arguments; returns status only."
		if listed.Tools[0].Description != want {
			t.Fatalf("description = %q, want %q", listed.Tools[0].Description, want)
		}
	})

	t.Run("custom description and readonly isolation forwarded cleanly", func(t *testing.T) {
		raw := `{"opq":"/operator/bin/opq","operations":[{"name":"health_check","description":"Check upstream API health\t(prod)","command":"/usr/bin/true","timeout_seconds":5,"allow_network":true,"isolation":"readonly"}]}`
		cfg, err := readConfig(strings.NewReader(raw))
		if err != nil {
			t.Fatalf("readConfig: %v", err)
		}
		var gotArgs map[string]any
		cs, ctx := connectProxy(t, cfg, fakeUpstream(func(_ context.Context, p *mcp.CallToolParams) (*mcp.CallToolResult, error) {
			gotArgs, _ = p.Arguments.(map[string]any)
			return &mcp.CallToolResult{StructuredContent: map[string]any{"succeeded": true, "timed_out": false}}, nil
		}))
		listed, err := cs.ListTools(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		wantDesc := "Check upstream API health\t(prod). Takes no arguments; returns status only."
		if listed.Tools[0].Description != wantDesc {
			t.Fatalf("description = %q, want %q", listed.Tools[0].Description, wantDesc)
		}
		if _, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "health_check", Arguments: map[string]any{}}); err != nil {
			t.Fatal(err)
		}
		if gotArgs["isolation"] != "readonly" || gotArgs["allow_network"] != true {
			t.Fatalf("unexpected forwarded args: %#v", gotArgs)
		}
		if !reflect.DeepEqual(gotArgs["args"], []string{}) || !reflect.DeepEqual(gotArgs["env"], map[string]string{}) {
			t.Fatalf("omitted args/env should normalize to empty slice/map, got %#v", gotArgs)
		}
	})

	t.Run("exact 512 byte description accepted", func(t *testing.T) {
		cfg := approvedConfig(t)
		cfg.Operations[0].Description = strings.Repeat("a", maxOperationDescriptionBytes)
		if err := validateConfig(cfg); err != nil {
			t.Fatalf("512-byte description rejected: %v", err)
		}
	})

	t.Run("description rejects >512 bytes and control chars", func(t *testing.T) {
		badDescs := map[string]struct {
			desc    string
			wantSub string
		}{
			"too_long": {strings.Repeat("a", maxOperationDescriptionBytes+1), "exceeds 512 bytes"},
			"nul":      {"bad\x00desc", "control characters"},
			"newline":  {"line1\nline2", "control characters"},
			"cr":       {"line1\rline2", "control characters"},
			"escape":   {"ansi\x1b[31m", "control characters"},
			"del":      {"del\x7fchar", "control characters"},
		}
		for name, tc := range badDescs {
			t.Run(name, func(t *testing.T) {
				cfg := approvedConfig(t)
				cfg.Operations[0].Description = tc.desc
				err := validateConfig(cfg)
				if err == nil {
					t.Fatalf("expected error for %s", name)
				}
				if !strings.Contains(err.Error(), `operation "probe"`) || !strings.Contains(err.Error(), tc.wantSub) {
					t.Errorf("error = %q, want operation name and %q", err.Error(), tc.wantSub)
				}
			})
		}
	})
}

func TestValidateConfigPinpointErrors(t *testing.T) {
	base := func() config {
		return config{
			Opq: "/operator/bin/opq",
			Operations: []operation{{
				Name:           "probe",
				Command:        "/usr/bin/true",
				Args:           []string{},
				Env:            map[string]string{"API_TOKEN": "example_token"},
				TimeoutSeconds: 10,
				AllowNetwork:   false,
				Isolation:      "full",
			}},
		}
	}

	cases := []struct {
		name      string
		mutate    func(*config)
		wantParts []string
	}{
		{
			name:      "relative_opq",
			mutate:    func(c *config) { c.Opq = "opq" },
			wantParts: []string{"opq", "absolute executable path"},
		},
		{
			name: "too_many_operations",
			mutate: func(c *config) {
				c.Operations = make([]operation, 65)
			},
			wantParts: []string{"too many approved operations", "65", "64"},
		},
		{
			name:      "invalid_name",
			mutate:    func(c *config) { c.Operations[0].Name = "../bad" },
			wantParts: []string{"operations[0]", "invalid operation name", "../bad"},
		},
		{
			name:      "reserved_name",
			mutate:    func(c *config) { c.Operations[0].Name = "list_secrets" },
			wantParts: []string{"operations[0]", "list_secrets", "reserved"},
		},
		{
			name:      "duplicate_name",
			mutate:    func(c *config) { c.Operations = append(c.Operations, c.Operations[0]) },
			wantParts: []string{"operations[1]", "duplicate operation name", "probe"},
		},
		{
			name:      "relative_command",
			mutate:    func(c *config) { c.Operations[0].Command = "true" },
			wantParts: []string{`operation "probe"`, "command", "absolute executable path"},
		},
		{
			name:      "timeout_out_of_range",
			mutate:    func(c *config) { c.Operations[0].TimeoutSeconds = 601 },
			wantParts: []string{`operation "probe"`, "timeout_seconds", "1 and 600", "601"},
		},
		{
			name:      "too_many_args",
			mutate:    func(c *config) { c.Operations[0].Args = make([]string, 257) },
			wantParts: []string{`operation "probe"`, "too many args", "257", "256"},
		},
		{
			name: "too_many_env",
			mutate: func(c *config) {
				env := make(map[string]string, 33)
				for i := range 33 {
					env["V"+string(rune('A'+i%26))+string(rune('A'+i/26))] = "tok"
				}
				c.Operations[0].Env = env
			},
			wantParts: []string{`operation "probe"`, "too many env", "33", "32"},
		},
		{
			name:      "unknown_isolation",
			mutate:    func(c *config) { c.Operations[0].Isolation = "other" },
			wantParts: []string{`operation "probe"`, "unknown isolation", "other"},
		},
		{
			name:      "network_with_full",
			mutate:    func(c *config) { c.Operations[0].AllowNetwork = true; c.Operations[0].Isolation = "full" },
			wantParts: []string{`operation "probe"`, "allow_network=true", `isolation="full"`},
		},
		{
			name:      "arg_nul",
			mutate:    func(c *config) { c.Operations[0].Args = []string{"ok", "bad\x00arg"} },
			wantParts: []string{`operation "probe"`, "args[1]", "NUL"},
		},
		{
			name:      "invalid_env_name",
			mutate:    func(c *config) { c.Operations[0].Env = map[string]string{"BAD=NAME": "tok"} },
			wantParts: []string{`operation "probe"`, "invalid env var name", "BAD=NAME"},
		},
		{
			name:      "invalid_secret_name",
			mutate:    func(c *config) { c.Operations[0].Env = map[string]string{"TOK": "meta/secret"} },
			wantParts: []string{`operation "probe"`, `env "TOK"`, "invalid secret name", "meta/secret"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base()
			tc.mutate(&cfg)
			err := validateConfig(cfg)
			if err == nil {
				t.Fatalf("expected validation error for %s", tc.name)
			}
			msg := err.Error()
			for _, part := range tc.wantParts {
				if !strings.Contains(msg, part) {
					t.Errorf("error = %q, missing %q", msg, part)
				}
			}
		})
	}
}

func TestBoundedStartupBuffer(t *testing.T) {
	buf := newBoundedStartupBuffer(16)
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			n, err := buf.Write([]byte("0123456789abcdefghij"))
			if err != nil || n != 20 {
				t.Errorf("Write returned (%d, %v), want (20, nil)", n, err)
			}
		}()
	}
	wg.Wait()
	if got := len(buf.String()); got != 16 {
		t.Fatalf("buffered len = %d, want 16", got)
	}
	buf.Stop()
	if got := buf.String(); got != "" {
		t.Fatalf("Stop did not clear buffer: %q", got)
	}
	if n, err := buf.Write([]byte("post-stop")); err != nil || n != 9 {
		t.Fatalf("post-stop Write = (%d, %v), want (9, nil)", n, err)
	}
	if got := buf.String(); got != "" {
		t.Fatalf("post-stop write was captured: %q", got)
	}
}

func TestClassifyStartupError(t *testing.T) {
	const sentinel = "SYNTHETIC_PRIVATE_UPSTREAM_TOKEN_999"
	cases := []struct {
		name       string
		connectErr error
		stderr     string
		wantSub    string
	}{
		{
			name:       "binary_not_found",
			connectErr: &os.PathError{Op: "fork/exec", Path: "/secret/path/" + sentinel, Err: os.ErrNotExist},
			wantSub:    "configured opq binary not found",
		},
		{
			name:       "exec_err_not_found",
			connectErr: exec.ErrNotFound,
			wantSub:    "configured opq binary not found",
		},
		{
			name:       "permission_denied",
			connectErr: &os.PathError{Op: "fork/exec", Path: "/secret/path/" + sentinel, Err: fs.ErrPermission},
			wantSub:    "configured opq binary is not executable",
		},
		{
			name:       "sandbox_bwrap",
			connectErr: errors.New("eof"),
			stderr:     "opq: opq mcp requires a working subprocess sandbox: bubblewrap (bwrap) not found " + sentinel,
			wantSub:    "upstream subprocess sandbox unavailable (run 'opq doctor' to diagnose)",
		},
		{
			name:       "sandbox_seatbelt",
			connectErr: errors.New("eof"),
			stderr:     "sandbox-exec probe failed (Seatbelt disabled) " + sentinel,
			wantSub:    "upstream subprocess sandbox unavailable (run 'opq doctor' to diagnose)",
		},
		{
			name:       "timeout",
			connectErr: context.DeadlineExceeded,
			stderr:     sentinel,
			wantSub:    "startup handshake timed out",
		},
		{
			name:       "canceled",
			connectErr: context.Canceled,
			stderr:     sentinel,
			wantSub:    "startup canceled",
		},
		{
			name:       "generic_handshake_failure",
			connectErr: errors.New("protocol mismatch " + sentinel),
			stderr:     "private failure detail: " + sentinel,
			wantSub:    "upstream MCP handshake failed (run 'opq doctor' to diagnose)",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyStartupError(tc.connectErr, tc.stderr).Error()
			if !strings.HasPrefix(got, "cannot connect to opq:") {
				t.Errorf("error = %q, must start with 'cannot connect to opq:'", got)
			}
			if !strings.Contains(got, tc.wantSub) {
				t.Errorf("error = %q, want substring %q", got, tc.wantSub)
			}
			if strings.Contains(got, sentinel) {
				t.Errorf("raw upstream bytes leaked into startup error: %q", got)
			}
		})
	}
}

func TestRunClassifiesUpstreamStartupStderrWithoutLeakingBytes(t *testing.T) {
	dir := t.TempDir()
	fakeOpq := filepath.Join(dir, "fake-opq.sh")
	const sentinel = "PRIVATE_UPSTREAM_BYTES_DO_NOT_ECHO"
	script := "#!/bin/sh\necho 'opq: opq mcp requires a working subprocess sandbox: " + sentinel + "' >&2\nexit 1\n"
	if err := os.WriteFile(fakeOpq, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(dir, "policy.json")
	cfg := config{Opq: fakeOpq, Operations: []operation{}}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policyPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	err = run(context.Background(), policyPath)
	if err == nil {
		t.Fatal("expected run() to fail when fake upstream exits on sandbox error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "upstream subprocess sandbox unavailable") {
		t.Errorf("expected sandbox hint in error, got %q", msg)
	}
	if strings.Contains(msg, sentinel) {
		t.Errorf("raw upstream stderr leaked into run() error: %q", msg)
	}
}
