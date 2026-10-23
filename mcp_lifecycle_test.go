package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Closing a ClientSession is graceful and waits for outgoing calls. Capture the
// underlying connection to model an abruptly disconnected stdio peer instead.
type captureLifecycleTransport struct {
	mcp.Transport
	conn mcp.Connection
}

func (t *captureLifecycleTransport) Connect(ctx context.Context) (mcp.Connection, error) {
	conn, err := t.Transport.Connect(ctx)
	t.conn = conn
	return conn, err
}

func TestMCPLifetimeCancelsActiveSDKTool(t *testing.T) {
	exerciseMCPLifecycleCancellation(t, false)
}

func TestMCPDisconnectCancelsActiveSDKTool(t *testing.T) {
	exerciseMCPLifecycleCancellation(t, true)
}

func exerciseMCPLifecycleCancellation(t *testing.T, disconnect bool) {
	t.Helper()
	lifetime, cancelLifetime := context.WithCancel(t.Context())
	// A separate cleanup context lets a broken regression exit its dummy handler
	// after reporting failure, instead of leaking a blocked SDK goroutine.
	cleanup, stopCleanup := context.WithCancel(t.Context())
	callCtx, cancelCall := context.WithTimeout(t.Context(), 3*time.Second)
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	capture := &captureLifecycleTransport{Transport: clientTransport}
	var session *mcp.ClientSession
	defer func() {
		cancelLifetime()
		stopCleanup()
		cancelCall()
		if capture.conn != nil {
			capture.conn.Close()
		}
		if session != nil {
			session.Close()
		}
	}()

	started := make(chan struct{})
	handlerCanceled := make(chan struct{})
	srv := mcp.NewServer(&mcp.Implementation{Name: "lifecycle-test", Version: "test"}, nil)
	handler := func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, struct{}, error) {
		close(started)
		select {
		case <-ctx.Done():
			close(handlerCanceled)
			return nil, struct{}{}, ctx.Err()
		case <-cleanup.Done():
			return nil, struct{}{}, errors.New("test cleanup")
		}
	}
	mcp.AddTool(srv, &mcp.Tool{Name: "blocking_test_tool"}, withServerLifetime(lifetime, handler))
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- srv.Run(lifetime, &disconnectTransport{Transport: serverTransport, cancel: cancelLifetime})
	}()
	client := mcp.NewClient(&mcp.Implementation{Name: "lifecycle-test-client", Version: "test"}, nil)
	var err error
	session, err = client.Connect(callCtx, capture, nil)
	if err != nil {
		t.Fatal(err)
	}
	callDone := make(chan error, 1)
	go func() {
		_, err := session.CallTool(callCtx, &mcp.CallToolParams{Name: "blocking_test_tool", Arguments: map[string]any{}})
		callDone <- err
	}()
	select {
	case <-started:
	case <-callCtx.Done():
		t.Fatal("blocking tool did not start")
	}

	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	if disconnect {
		if err := capture.conn.Close(); err != nil {
			t.Fatal(err)
		}
	} else {
		cancelLifetime()
	}
	select {
	case <-handlerCanceled:
	case <-deadline.C:
		t.Fatal("active SDK handler ignored server shutdown")
	}
	select {
	case <-serverDone:
	case <-deadline.C:
		t.Fatal("SDK server did not finish after handler cancellation")
	}
	select {
	case <-callDone:
	case <-deadline.C:
		t.Fatal("SDK client call remained blocked after server shutdown")
	}
}
