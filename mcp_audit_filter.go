// Package main: AI-visible audit-log filtering.
//
// audit_tail returns operator audit entries to the AI, so each line is passed
// through filterAuditLineForAI (caller filter + message allowlist) before it
// leaves the boundary. The allowlist is closed: every key=value token not on
// aiAuditMessageAllowlist is stripped because it would re-open a side-channel
// (raw_exit, elapsed_ms, *_truncated). See CLAUDE.md for the per-token rationale.
package main

import (
	"encoding/json"
	"strings"
)

// filterAuditLineForAI filters one raw audit line before it reaches an AI:
//   - caller filter: drop anything not caller="mcp", so CLI-driven entries
//     (get/set/delete, gate failures, operator-chosen sandbox profiles) stay
//     invisible. The prefix match is future-proof for session IDs ("mcp:abc").
//   - message allowlist: for key=value-shaped Messages, strip every token not
//     on aiAuditMessageAllowlist (raw_exit, elapsed_ms, ... are oracles).
//
// Returns ("", false) to drop the line entirely.
func filterAuditLineForAI(line string) (string, bool) {
	// Fast path: skip obviously empty lines.
	if strings.TrimSpace(line) == "" {
		return "", false
	}

	var ev AuditEvent
	if err := json.Unmarshal([]byte(line), &ev); err != nil {
		// Unparseable lines are dropped rather than forwarded; they could
		// contain arbitrary bytes from a future or corrupt log format.
		return "", false
	}

	// Only MCP-originated (caller="mcp") entries are visible to the AI.
	if !strings.HasPrefix(ev.Caller, "mcp") {
		return "", false
	}

	// The allowlist gate must cover EVERY action whose Message uses the
	// key=value shape: ActionMCPRun, ActionNetworkAllowed, and ActionSet
	// (expires_at). ActionSet is CLI-only today and dropped by the caller
	// filter above, but is listed so a future MCP set path can't leak it.
	// Bare-token actions (ActionDenied: env_blocked, ...) deliberately bypass
	// the gate; the allowlist would drop their whole payload.
	switch ev.Action {
	case ActionMCPRun, ActionNetworkAllowed, ActionSet:
		if ev.Message != "" {
			ev.Message = filterAuditMessageForAI(ev.Message)
		}
	}

	out, err := json.Marshal(ev)
	if err != nil {
		// Should never happen with a valid AuditEvent, but be safe.
		return "", false
	}
	return string(out), true
}

// aiAuditMessageAllowlist is the closed set of `key=value` tokens that may
// appear in an AI-visible audit-log Message. Every other token is dropped.
// Bare (no '=') tokens are also dropped. Adding a key here is a deliberate
// audit-channel widening; every entry below has been reviewed for AI-leak
// implications.
//
//	timed_out: 1-bit oracle, already exposed in the run_with_secrets
//	           result (TimedOut), so allowlisting it in the audit stream
//	           does not enlarge the AI's information surface.
//
// Explicitly NOT on the list (and therefore stripped):
//
//	raw_exit          8-bit exit-code oracle; normalizeExit withholds it.
//	elapsed_ms        wall-clock timing oracle; never exposed in the
//	                  run_with_secrets result, must not leak via audit.
//	stdout_truncated  output-volume oracle; removed from the response
//	                  struct (see gap #3 in the mcp.go header). The AI
//	                  must not be able to recover the flag via audit_tail.
//	stderr_truncated  same.
//	exec_*            operator-facing diagnostic detail; not for AI.
//
// Future contributors: do NOT add a key here without writing a one-line
// justification of why the AI seeing it does not enable a side-channel.
var aiAuditMessageAllowlist = map[string]bool{
	"timed_out": true,
}

// filterAuditMessageForAI rebuilds an audit Message containing only tokens
// whose key is on the aiAuditMessageAllowlist. The empty string is returned
// if no tokens survive; that is a valid audit-line state (the `msg` field
// is `omitempty` JSON).
//
// Invariant: every allowlisted token's value MUST NOT contain a literal
// space. The function splits on ' ' to identify tokens, so a space inside a
// value would split it and silently drop the trailing portion. Today every
// producer (auditMCPRunMessage) emits boolean-shaped values; if a future
// allowlist entry needs spaces in its value, switch the format to a
// space-free encoding (e.g. URL encoding) before adding the key.
func filterAuditMessageForAI(msg string) string {
	if msg == "" {
		return ""
	}
	tokens := strings.Split(msg, " ")
	// Allocate a fresh slice instead of aliasing tokens[:0]. The forward-
	// scan loop happens to be safe with aliasing because every append
	// position has already been read, but the invariant is non-local and
	// would silently break if the loop is ever rewritten as a backward
	// scan or rearranged to read positions after writes.
	out := make([]string, 0, len(tokens))
	for _, tok := range tokens {
		key, _, ok := strings.Cut(tok, "=")
		if !ok {
			// Bare token with no '='; drop (cannot be on allowlist).
			continue
		}
		if !aiAuditMessageAllowlist[key] {
			continue
		}
		out = append(out, tok)
	}
	return strings.Join(out, " ")
}
