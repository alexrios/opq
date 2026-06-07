// Package main: the audit_tail MCP tool.
//
// Returns recent operator audit entries to the AI, filtered through
// filterAuditLineForAI. The read is itself audited (with a per-call random
// nonce) BEFORE it runs, so an AI scraping operator activity is visible in the
// log; the just-written self-entry is then stripped from the AI's window by
// nonce match (position-independent; see stripSelfAuditTailEntry).
package main

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type auditTailInput struct {
	N int `json:"n,omitempty" jsonschema:"number of trailing entries; default 20, capped at 200"`
}

type auditTailOutput struct {
	Entries []string `json:"entries"`
}

// clampAuditTailN caps the requested tail size so audit_tail can't become a
// wholesale-history enumeration channel.
func clampAuditTailN(requested int) int {
	if requested <= 0 {
		return 20
	}
	if requested > mcpMaxAuditTailN {
		return mcpMaxAuditTailN
	}
	return requested
}

func handleAuditTail(_ context.Context, _ *mcp.CallToolRequest, input auditTailInput) (*mcp.CallToolResult, auditTailOutput, error) {
	// Over-fetch from the log so that after the MCP-caller filter is applied
	// we still return up to n entries. In the worst case all entries are CLI
	// entries and we return an empty list; that is correct behaviour.
	n := clampAuditTailN(input.N)
	// Record every audit_tail call BEFORE the read, so an AI scraping operator
	// activity is itself visible even if the read then fails. A per-call random
	// nonce tags our self-entry so the strip below finds it regardless of
	// position (a PID match broke under concurrent writers / PID reuse). If
	// crypto/rand fails the nonce is empty and the strip no-ops; the AI sees
	// one bookkeeping row, not a security violation; better than crashing.
	nonce := generateAuditNonce()
	_ = AppendAudit(AuditEvent{
		Action:  ActionAuditTail,
		Caller:  callerTag(),
		Message: fmt.Sprintf("n=%d", n),
		Nonce:   nonce,
	})
	lines, err := tailAudit(mcpMaxAuditTailN)
	if err != nil {
		return aiErr("internal_error"), auditTailOutput{}, nil
	}

	// Apply MCP-specific filters (M3 caller filter, C1 raw_exit strip).
	// The self-log entry we just appended (J-5) is included in `lines` and
	// passes the filter, so strip it so the AI's requested-n window isn't
	// occupied by its own bookkeeping. The self-log entry's existence
	// remains visible to the operator via `opq audit` and to subsequent
	// AI calls (we strip OUR row only, identified by nonce; older
	// audit_tail entries from prior calls survive as the deterrent the
	// design promises).
	filtered := make([]string, 0, len(lines))
	for _, line := range lines {
		if out, ok := filterAuditLineForAI(line); ok {
			filtered = append(filtered, out)
		}
	}
	filtered = stripSelfAuditTailEntry(filtered, nonce)
	// Return at most the requested n entries (last n after filter).
	if len(filtered) > n {
		filtered = filtered[len(filtered)-n:]
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: strings.Join(filtered, "\n")}},
	}, auditTailOutput{Entries: filtered}, nil
}

// generateAuditNonce returns 32 hex chars (16 random bytes / 128 bits)
// suitable for tagging a single audit entry so the writer can identify
// it among later log lines. Returns the empty string on the (vanishingly
// rare) event that crypto/rand fails; callers must treat the empty
// nonce as "no strip possible" rather than crashing. 128 bits is
// overkill for the tiny collision domain (a few hundred entries in a
// tail window) but cheap and removes any need to think about birthday
// bounds.
func generateAuditNonce() string {
	var buf [16]byte
	if _, err := cryptorand.Read(buf[:]); err != nil {
		return ""
	}
	return hex.EncodeToString(buf[:])
}

// stripSelfAuditTailEntry scans the filtered audit lines and removes
// every ActionAuditTail entry whose Nonce matches the provided value.
// Returns the input unchanged if nonce is empty (graceful degradation
// path when crypto/rand fails) or no match is found.
//
// Why scan instead of strip-last (joint-review 2026-05 P3):
// handleAuditTail writes its self-entry BEFORE reading the log, but a
// concurrent AppendAudit (CLI process, another MCP handler, etc.) can
// land between our write and our read, so our entry may then sit anywhere
// in the filtered window, not just at the end. A position-based strip
// either misses our entry (leak) or strips the wrong line (incorrect
// truncation of operator activity). Nonce-based matching is immune to
// reordering and to PID reuse (a previous process that wrote an
// audit_tail entry with the same PID is no longer our concern).
//
// Duplicate nonces would indicate a catastrophic RNG failure (128 bits
// of crypto/rand output colliding). We strip ALL matches rather than
// stop at the first: a defensive choice that costs nothing in the
// success path (zero duplicates) and avoids surfacing a duplicate-row
// puzzle to the AI in the failure path. Malformed JSON entries pass
// through unchanged.
func stripSelfAuditTailEntry(filtered []string, nonce string) []string {
	if nonce == "" {
		return filtered
	}
	out := make([]string, 0, len(filtered))
	for _, line := range filtered {
		var ev AuditEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			// Malformed lines pass through; the AI-visible filter would
			// already have dropped them upstream if they were invalid.
			out = append(out, line)
			continue
		}
		if ev.Action == ActionAuditTail && ev.Nonce == nonce {
			// Strip this entry.
			continue
		}
		out = append(out, line)
	}
	return out
}
