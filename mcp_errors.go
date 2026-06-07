// Package main: AI-facing error helpers for the MCP surface.
//
// Two return shapes guard the AI boundary: aiErr for anything that may carry
// backend/system bytes (sanitized to a fixed taxonomy) and aiUserErr for text
// composed only of literals or AI-supplied values. sanitizeErrForAI maps raw
// errors to the stable taxonomy used by aiErr.
package main

import (
	"errors"
	"io/fs"
	"os/exec"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// sanitizeErrForAI converts any error into a fixed-taxonomy string that is
// safe to surface to an MCP caller. The original error is preserved for the
// audit log; only the AI-visible CallToolResult uses the sanitized form.
//
// Call context: handleRunWithSecrets uses this only for process-start
// failures. Backend and sandbox errors are mapped at their own call sites.
//
// Taxonomy keys (stable interface, do not change without a version bump):
//
//	not_found                 named secret does not exist
//	exec_not_found            command binary not found on PATH
//	exec_permission_denied    binary exists but not executable
//	exec_start_failed         other process-start failure (fallback)
func sanitizeErrForAI(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, ErrSecretNotFound) {
		return "not_found"
	}
	if errors.Is(err, exec.ErrNotFound) {
		return "exec_not_found"
	}
	if errors.Is(err, fs.ErrPermission) {
		return "exec_permission_denied"
	}
	return "exec_start_failed"
}

// aiErr returns an IsError CallToolResult with a sanitized, fixed-taxonomy
// error string. Use this for all errors that may carry backend or system
// bytes (backend errors, exec start errors, sandbox errors, audit errors).
// The original err is NOT exposed to the AI; log it via AppendAudit before
// calling aiErr if operator visibility is needed.
func aiErr(sanitized string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{&mcp.TextContent{Text: sanitized}},
	}
}

// aiUserErr returns an IsError CallToolResult with caller-controlled text
// (e.g. input-validation messages). Use this ONLY for errors whose text is
// composed entirely of literals or values the AI itself supplied; never for
// errors that may carry backend or system bytes.
func aiUserErr(msg string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
	}
}
