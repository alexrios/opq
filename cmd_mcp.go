package main

import (
	"context"
	"fmt"
)

type MCPCmd struct{}

func (c *MCPCmd) Run() error {
	SetCallerTag("mcp")
	// The MCP server's default isolation is SandboxNet for every
	// run_with_secrets call. If the sandbox cannot start, refuse to
	// expose the tool surface — running unsandboxed would silently
	// regress the v1.1 security guarantee.
	if err := VerifySandboxAvailable(); err != nil {
		return fmt.Errorf("opq mcp requires a working subprocess sandbox: %w\nInstall bubblewrap (Debian/Ubuntu: apt install bubblewrap; Fedora: dnf install bubblewrap; Arch: pacman -S bubblewrap)", err)
	}
	srv, err := newMCPServer()
	if err != nil {
		return err
	}
	if err := runMCPServer(context.Background(), srv); err != nil {
		return fmt.Errorf("mcp server: %w", err)
	}
	return nil
}
