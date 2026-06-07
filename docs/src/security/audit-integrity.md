# Audit Log Integrity

> Implementation internals. For the user-facing log format see the
> [Audit Log reference](../reference/audit-log.md); for the concepts, the
> [Threat Model](./threat-model.md).

The audit log serves two readers with opposite trust levels: the operator (full detail)
and the AI (a filtered view via the `audit_tail` MCP tool). This page covers how the log
stays consistent under concurrency and how the AI's view is narrowed so the log itself is
not a side channel. Code: `audit.go`, `mcp_audit_filter.go`, `mcp_audit_tail.go`.

## Cross-process integrity

Appends and tail reads serialize across processes through a dedicated `audit.lock` file
(separate from `audit.log`, never rotated). `appendAuditInternal` takes the in-process
`auditMu`, then `LOCK_EX` on `audit.lock`. `tailAudit` takes `auditMu`, then `LOCK_SH` on
a freshly-opened `audit.lock` fd, a distinct OFD from the writer's cached fd, so flock
self-conflicts work in-process.

Rotation (at 10 MiB, keeping one `audit.log.1`) never drops the lock, so readers cannot
observe torn or duplicated entries even when a writer rotates mid-read. Do not open
`audit.log` for write outside `appendAuditInternal`, or read it outside `tailAudit`.

## No raw backend errors in the log

Audit `msg` fields never contain raw `err.Error()` from a backend or `os/exec` start
failure; those go through `sanitizeBackendErr` / `sanitizeExecStartErr` first, mapping to a
fixed taxonomy. The wrapped error returned to the caller still carries full detail; the
log carries only tokens, so a buggy or hostile backend cannot write secret bytes into the
audit stream.

## The AI-visible allowlist

The AI's view of `mcp_run` and `network_allowed` messages passes through a closed
allowlist (`aiAuditMessageAllowlist`) in `filterAuditMessageForAI`. Only the `timed_out`
token survives. Stripped:

| Token | Oracle it would give the AI |
| --- | --- |
| `raw_exit` | Per-call exit-code oracle. |
| `elapsed_ms` | Wall-clock timing oracle. |
| `stdout_truncated` / `stderr_truncated` | Output-volume oracle (1 bit/call). |
| `network_allowed` `command=` / `args=` | AI-supplied bytes echoed back. |

These tokens are still recorded for the operator (visible via `opq audit`) as
diagnostics; they are only stripped on the way to the AI. Adding a key to the allowlist,
or a new action to the coverage gate in `filterAuditLineForAI`, widens the audit channel,
and each entry needs a one-line justification that the AI seeing it does not enable a side
channel.

Bare-token taxonomy actions (for example `denied` with `env_blocked`) intentionally bypass
the allowlist; the allowlist's bare-token rule would otherwise drop their entire payload,
and they carry no AI-exploitable detail.

## audit_tail is itself audited

`handleAuditTail` calls `AppendAudit` with `Action: audit_tail` and a 128-bit `crypto/rand`
nonce before invoking `tailAudit`, so an AI scraping the operator's log is itself visible
in the log.

The self-entry is stripped from the AI's response window by `stripSelfAuditTailEntry`,
which scans the filtered slice for an `audit_tail` row whose `nonce` matches this call's
nonce, position-independent. The old PID-based match was fragile: a concurrent
`AppendAudit` could displace the self-entry from the last-line slot, and PID reuse could
match a prior process's row. On the rare `crypto/rand` failure the nonce stays empty and
the strip becomes a no-op (a one-row bookkeeping leak, preferred to a panic). Older
`audit_tail` entries from prior calls survive as the deterrent.

## Caller attribution

The `caller` field is `cli` for direct CLI invocations and `mcp` when the request came
through the MCP server. The MCP `audit_tail` view is further restricted to `caller="mcp"`
entries, so an AI cannot read the operator's CLI activity. `opq audit` shows everything.
