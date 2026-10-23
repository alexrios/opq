package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Re-exec the test binary as both the deployed proxy and its private upstream.
// The upstream receives only the fixed "mcp" argv from run(), without a keyring.
func TestMain(m *testing.M) {
	if os.Getenv("OPQ_PROXY_TEST_HELPER") == "stdio" {
		var err error
		if len(os.Args) > 1 && os.Args[1] == "mcp" {
			err = fakeStdioUpstream(os.Getenv("OPQ_PROXY_TEST_STATE"))
		} else {
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			err = run(ctx, filepath.Join(os.Getenv("OPQ_PROXY_TEST_STATE"), "policy.json"))
			stop()
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func fakeStdioUpstream(dir string) error {
	if err := os.WriteFile(filepath.Join(dir, "upstream.pid"), []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "synthetic-private-stderr")
	if os.Getenv("OPQ_PROXY_TEST_FAILURE") == "unsupported" {
		var request struct {
			ID json.RawMessage `json:"id"`
		}
		scanner := bufio.NewScanner(os.Stdin)
		if !scanner.Scan() || json.Unmarshal(scanner.Bytes(), &request) != nil {
			return errors.New("missing initialize request")
		}
		response := map[string]any{"jsonrpc": "2.0", "id": request.ID, "result": map[string]any{"protocolVersion": "unsupported", "capabilities": map[string]any{}, "serverInfo": map[string]any{"name": "fake", "version": "1"}}}
		if err := json.NewEncoder(os.Stdout).Encode(response); err != nil {
			return err
		}
		_, err := io.Copy(io.Discard, os.Stdin)
		return err
	}
	lifetime, cancelLifetime := context.WithCancel(context.Background())
	defer cancelLifetime()
	srv := mcp.NewServer(&mcp.Implementation{Name: "synthetic-upstream", Version: "1"}, nil)
	type output struct {
		Succeeded bool   `json:"succeeded"`
		TimedOut  bool   `json:"timed_out"`
		Stdout    string `json:"stdout"`
		Stderr    string `json:"stderr"`
	}
	calls := 0
	mcp.AddTool(srv, &mcp.Tool{Name: "run_with_secrets"}, func(ctx context.Context, _ *mcp.CallToolRequest, input map[string]any) (*mcp.CallToolResult, output, error) {
		ctx, cancel := context.WithCancel(ctx)
		stop := context.AfterFunc(lifetime, cancel)
		defer stop()
		defer cancel()
		if lifetime.Err() != nil {
			cancel()
		}
		calls++
		data, err := json.Marshal(struct {
			Calls     int            `json:"calls"`
			Arguments map[string]any `json:"arguments"`
		}{calls, input})
		if err == nil {
			err = os.WriteFile(filepath.Join(dir, "request.json"), data, 0o600)
		}
		if err != nil {
			return nil, output{}, err
		}
		if os.Getenv("OPQ_PROXY_TEST_FAILURE") == "blocking" {
			if err := os.WriteFile(filepath.Join(dir, "operation.started"), []byte("started"), 0o600); err != nil {
				return nil, output{}, err
			}
			<-ctx.Done()
			if err := os.WriteFile(filepath.Join(dir, "operation.canceled"), []byte("request canceled"), 0o600); err != nil {
				return nil, output{}, err
			}
			return nil, output{}, ctx.Err()
		}
		return nil, output{Succeeded: true, Stdout: "synthetic-private-stdout", Stderr: "synthetic-private-result-stderr"}, nil
	})
	if err := srv.Run(lifetime, &disconnectTransport{Transport: &mcp.StdioTransport{}, cancel: cancelLifetime}); err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, context.Canceled) {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "upstream.closed"), []byte("stdin EOF; server returned; process exiting\n"), 0o600)
}

func stdioProxyCommand(t *testing.T, failure string) (*exec.Cmd, string, *bytes.Buffer) {
	t.Helper()
	dir := t.TempDir()
	cfg := approvedConfig(t)
	if failure == "blocking" {
		cfg.Operations[0].TimeoutSeconds = 60
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Opq = binary
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "policy.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary)
	// Keep race instrumentation, but avoid its one-second exit sleep in each
	// nested fixture process competing with the production shutdown grace.
	cmd.Env = append(os.Environ(), "OPQ_PROXY_TEST_HELPER=stdio", "OPQ_PROXY_TEST_STATE="+dir, "OPQ_PROXY_TEST_FAILURE="+failure, "GORACE=atexit_sleep_ms=0")
	stderr := new(bytes.Buffer)
	cmd.Stderr = stderr
	return cmd, dir, stderr
}

func upstreamPID(t *testing.T, dir string) int {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "upstream.pid"))
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(string(data))
	if err != nil {
		t.Fatal(err)
	}
	return pid
}

func assertProcessGone(t *testing.T, pid int) {
	t.Helper()
	if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("process %d still exists after teardown: %v", pid, err)
	}
}

func TestProxyStdioStartupForwardingAndDisconnectCleanup(t *testing.T) {
	cmd, dir, stderr := stdioProxyCommand(t, "")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client := mcp.NewClient(&mcp.Implementation{Name: "stdio-test", Version: "1"}, nil)
	session, err := client.Connect(ctx, &mcp.CommandTransport{Command: cmd, TerminateDuration: 2 * time.Second}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { session.Close() })
	pid := upstreamPID(t, dir)
	tools, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(tools.Tools) != 1 || tools.Tools[0].Name != "probe" {
		t.Fatal("unexpected stdio tools")
	}
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "probe", Arguments: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(result)
	if strings.Contains(string(encoded), "synthetic-private") {
		t.Fatal("private stdio response escaped proxy")
	}
	fields, ok := result.StructuredContent.(map[string]any)
	if !ok || len(fields) != 2 || fields["succeeded"] != true || fields["timed_out"] != false {
		t.Fatalf("stdio response lost projected status: %s", encoded)
	}
	result, err = session.CallTool(ctx, &mcp.CallToolParams{Name: "probe", Arguments: map[string]any{"args": []string{"unapproved"}}})
	if err == nil && !result.IsError {
		t.Fatal("stdio caller arguments accepted")
	}
	var forwarded struct {
		Calls     int                        `json:"calls"`
		Arguments map[string]json.RawMessage `json:"arguments"`
	}
	data, err := os.ReadFile(filepath.Join(dir, "request.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &forwarded); err != nil {
		t.Fatal(err)
	}
	wantArguments, _ := json.Marshal(map[string]any{
		"command": "/usr/bin/true", "args": []string{}, "env": map[string]string{"API_TOKEN": "example_token"},
		"timeout_seconds": 1, "allow_network": false, "isolation": "full",
	})
	gotArguments, _ := json.Marshal(forwarded.Arguments)
	if forwarded.Calls != 1 || !bytes.Equal(gotArguments, wantArguments) {
		t.Fatal("stdio request departed from approved operation")
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	if cmd.ProcessState == nil || !cmd.ProcessState.Success() {
		t.Fatal("proxy process did not exit cleanly")
	}
	assertProcessGone(t, pid)
	closed, err := os.ReadFile(filepath.Join(dir, "upstream.closed"))
	if err != nil {
		t.Fatalf("upstream did not observe stdin EOF: %v", err)
	}
	if stderr.Len() != 0 {
		t.Fatal("upstream stderr escaped private connection")
	}
	t.Logf("proxy_pid=%d exited=0 upstream_pid=%d absent=true teardown=%s", cmd.Process.Pid, pid, strings.TrimSpace(string(closed)))
}

func TestProxyStdioFailedInitializationReapsUpstream(t *testing.T) {
	cmd, dir, stderr := stdioProxyCommand(t, "unsupported")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client := mcp.NewClient(&mcp.Implementation{Name: "stdio-test", Version: "1"}, nil)
	if session, err := client.Connect(ctx, &mcp.CommandTransport{Command: cmd, TerminateDuration: 2 * time.Second}, nil); err == nil {
		session.Close()
		t.Fatal("unsupported upstream initialized")
	}
	if cmd.ProcessState == nil || cmd.ProcessState.Success() {
		t.Fatal("failed proxy initialization did not reap proxy process")
	}
	pid := upstreamPID(t, dir)
	assertProcessGone(t, pid)
	if strings.Contains(stderr.String(), "synthetic-private") || !strings.Contains(stderr.String(), "cannot connect to opq") {
		t.Fatal("initialization error was not sanitized")
	}
	t.Logf("proxy_pid=%d reaped=true upstream_pid=%d absent=true initialization_error=sanitized", cmd.Process.Pid, pid)
}

func TestRunRejectsUnsafeConfigBeforeStartingProcess(t *testing.T) {
	for _, test := range []struct {
		name, data string
		mode       os.FileMode
	}{
		{name: "group_writable", data: validConfig, mode: 0o620},
		{name: "unknown_field", data: strings.Replace(validConfig, `"opq":`, `"unexpected":true,"opq":`, 1), mode: 0o600},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "policy.json")
			if err := os.WriteFile(path, []byte(test.data), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, test.mode); err != nil {
				t.Fatal(err)
			}
			if err := run(context.Background(), path); err == nil {
				t.Fatal("unsafe configuration started proxy")
			}
		})
	}
}

func waitForFixtureFile(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("fixture did not create %s", filepath.Base(path))
}

func TestProxyStdioCancelsActiveOperationOnDisconnectAndSignal(t *testing.T) {
	for _, mode := range []string{"EOF", "SIGTERM"} {
		t.Run(mode, func(t *testing.T) {
			cmd, dir, stderr := stdioProxyCommand(t, "blocking")
			stdin, err := cmd.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			// Always reap the fixtures, including when exercising a broken shutdown.
			reaped := false
			t.Cleanup(func() {
				if !reaped {
					cmd.Process.Kill()
					cmd.Wait()
				}
				if data, err := os.ReadFile(filepath.Join(dir, "upstream.pid")); err == nil {
					if pid, err := strconv.Atoi(string(data)); err == nil {
						syscall.Kill(pid, syscall.SIGKILL)
					}
				}
			})
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			client := mcp.NewClient(&mcp.Implementation{Name: "stdio-cancel-test", Version: "1"}, nil)
			session, err := client.Connect(ctx, &mcp.IOTransport{Reader: stdout, Writer: stdin}, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { session.Close() })
			callDone := make(chan struct{})
			go func() {
				defer close(callDone)
				session.CallTool(ctx, &mcp.CallToolParams{Name: "probe", Arguments: map[string]any{}})
			}()
			waitForFixtureFile(t, filepath.Join(dir, "operation.started"))
			pid := upstreamPID(t, dir)
			start := time.Now()
			if mode == "EOF" {
				err = stdin.Close()
			} else {
				err = cmd.Process.Signal(syscall.SIGTERM)
			}
			if err != nil {
				t.Fatal(err)
			}
			waitDone := make(chan error, 1)
			go func() { waitDone <- cmd.Wait() }()
			select {
			case err := <-waitDone:
				reaped = true
				if err != nil {
					t.Fatalf("proxy shutdown failed: %v", err)
				}
			case <-time.After(3 * time.Second):
				cmd.Process.Kill()
				<-waitDone
				reaped = true
				t.Fatal("proxy kept a 60-second operation alive after client shutdown")
			}
			select {
			case <-callDone:
			case <-ctx.Done():
				t.Fatal("client call did not finish after shutdown")
			}
			if _, err := os.Stat(filepath.Join(dir, "operation.canceled")); err != nil {
				t.Fatal("upstream operation was killed without request cancellation")
			}
			if _, err := os.Stat(filepath.Join(dir, "upstream.closed")); err != nil {
				t.Fatal("upstream did not close gracefully through stdin EOF")
			}
			assertProcessGone(t, pid)
			if stderr.Len() != 0 {
				t.Fatal("private stderr escaped on shutdown")
			}
			t.Logf("mode=%s operation_timeout_s=60 shutdown_ms=%d request_canceled=true upstream_EOF=true proxy_pid=%d exited=0 upstream_pid=%d absent=true", mode, time.Since(start).Milliseconds(), cmd.Process.Pid, pid)
		})
	}
}
