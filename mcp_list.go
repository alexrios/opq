// Package main: the list_secrets MCP tool.
//
// Returns secret NAMES only (never values), and audits before the backend call
// so probing a degraded keyring still leaves a trace. Companion "meta/" keys
// and revoked tombstones are hidden via filterVisibleSecretNames.
package main

import (
	"context"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type listSecretsInput struct{}

type listSecretsOutput struct {
	Names []string `json:"names"`
}

func handleListSecrets(ctx context.Context, _ *mcp.CallToolRequest, _ listSecretsInput) (*mcp.CallToolResult, listSecretsOutput, error) {
	// Audit BEFORE the backend call so an AI probing a degraded backend (D-Bus
	// down, keyring locked) by hammering list_secrets still leaves a trace even
	// when every call errors.
	_ = AppendAudit(AuditEvent{Action: ActionList, Caller: callerTag()})
	backend, err := OpenDefaultBackend()
	if err != nil {
		// Sanitize: backend errors may carry keyring/D-Bus text.
		return aiErr("backend_error"), listSecretsOutput{}, nil
	}
	names, err := backend.List(ctx)
	if err != nil {
		return aiErr("backend_error"), listSecretsOutput{}, nil
	}
	// backend.List returns raw keys including companion "meta/" items; the AI
	// must never see the scheme or a revoked secret's surviving tombstone.
	visible := filterVisibleSecretNames(names)
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: strings.Join(visible, "\n")}},
	}, listSecretsOutput{Names: visible}, nil
}
