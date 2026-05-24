package main

import (
	"context"
	"fmt"
)

type MCPCmd struct{}

func (c *MCPCmd) Run() error {
	SetCallerTag("mcp")
	srv, err := newMCPServer()
	if err != nil {
		return err
	}
	if err := runMCPServer(context.Background(), srv); err != nil {
		return fmt.Errorf("mcp server: %w", err)
	}
	return nil
}
