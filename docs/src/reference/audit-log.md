# Audit Log

Every operation `opq` performs is recorded to an append-only audit log.

## Location and format

```text
${XDG_STATE_HOME:-$HOME/.local/state}/opq/audit.log
```

Mode `0600`, one JSON object per line. A sibling `audit.lock` file (also `0600`)
serializes appends and tail reads across concurrent `opq` processes with `flock(2)`
(`LOCK_EX` for writes, `LOCK_SH` for reads); rotation is atomic across processes and
never drops the lock. The active log is capped at 10 MiB, with one historical rotation
kept at `audit.log.1`. `opq audit --tail N` spans both files.

## Actions

| Action | When |
| --- | --- |
| `set` | A secret was stored (with `expires_at=` if a TTL was set). |
| `get` | A plaintext read via `opq get --plaintext`. |
| `delete` | A secret was removed. |
| `revoke` | A secret was revoked: its value wiped, a tombstone left. |
| `prune` | Expired secrets were deleted (`opq prune`). |
| `list` | Names were listed. |
| `exec_inject` | A secret was injected into a CLI `opq exec` child. |
| `mcp_run` | The MCP `run_with_secrets` tool ran a subprocess. |
| `audit_tail` | The MCP `audit_tail` tool was invoked. |
| `redaction_disabled` | `exec --no-redact` passed its gate. |
| `network_allowed` | An MCP run was granted `allow_network=true` (carries `secret_names`). |
| `denied` | A gate or policy refused an action (`no_redact_refused:<reason>`, `env_blocked`, ...). |

## Fields

| Field | Meaning |
| --- | --- |
| `ts` | RFC 3339 timestamp. |
| `action` | One of the actions above. |
| `secret_name` / `secret_names` | The secret(s) involved. `secret_names` is a JSON array for MCP runs. |
| `caller` | `cli` for direct CLI use, `mcp` when the request came through the MCP server. |
| `pid` / `ppid` | Process identifiers. |
| `nonce` | Per-call random hex for `audit_tail` self-entry stripping (omitted elsewhere). |
| `msg` | Fixed-taxonomy tokens, never raw error text. For `mcp_run` it is `key=value`-shaped (`raw_exit=0 elapsed_ms=143 ...`). |

## CLI view vs. AI view

The same entry looks different depending on who reads it. `opq audit` (CLI) shows full
operator detail; the MCP `audit_tail` tool applies a closed allowlist.

```json
// CLI view via `opq audit` (full detail)
{"ts":"2026-05-24T15:50:17.189Z","action":"exec_inject","secret_name":"openai_key","caller":"cli","pid":50770,"ppid":50701}
{"ts":"2026-05-24T15:50:18.012Z","action":"mcp_run","secret_names":["openai_key","stripe_secret_key"],"caller":"mcp","pid":50770,"ppid":50701,"msg":"raw_exit=0 elapsed_ms=143"}
{"ts":"2026-05-24T15:50:19.422Z","action":"audit_tail","caller":"mcp","pid":50770,"ppid":50701,"msg":"n=20"}

// Same mcp_run entry as seen by the AI via the `audit_tail` MCP tool (allowlist applied)
{"ts":"2026-05-24T15:50:18.012Z","action":"mcp_run","secret_names":["openai_key","stripe_secret_key"],"caller":"mcp","pid":50770,"ppid":50701}
```

For `mcp_run`, the AI-visible `msg` keeps only `timed_out`; for a clean exit the field
is empty and omitted by `omitempty`. `raw_exit`, `elapsed_ms`, and truncation flags are
stripped from the AI view because each was a usable side channel; see
[Audit Log Integrity](../security/audit-integrity.md).

## Error sanitization

Backend and subprocess-start errors are mapped to a fixed taxonomy (`not_found`,
`backend_error`, `exec_not_found`, `exec_permission_denied`, `exec_start_failed`) before
being written to `msg`. The wrapped error returned to the caller keeps full detail, but
the log carries only tokens, so a buggy or hostile backend cannot leak secret bytes into
the audit stream.
