package main

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
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
