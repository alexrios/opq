# MCP Tools

`opq mcp` exposes three tools over stdio. There is no `get_secret_value` tool; that
absence is the security control. Register the server as shown in the
[MCP tutorial](../tutorials/mcp-claude-code.md#1-register-the-mcp-server).

## `list_secrets`

```jsonc
list_secrets()  →  { "names": ["api_token", "openai_key"] }
```

Returns secret names only. Internal policy items (`meta/...`) and revoked tombstones are
filtered out, so the AI never sees the storage scheme or a tombstone's existence. The
call is audited before the backend is queried, so probing a degraded keyring still
leaves a trace.

## `run_with_secrets`

```jsonc
run_with_secrets({
  command: "sh",
  args: ["-c", "curl -s -H \"Authorization: Bearer $TOK\" https://api.example.com"],
  env: { TOK: "api_token" },
  timeout_seconds: 60,        // optional, default 60, capped at 600
  allow_network: true,        // optional, default false (external curl needs it)
  isolation: "net"            // optional: "net" (default) | "full"
})
```

Runs `command` with the named secrets injected as environment variables, inside a
bubblewrap sandbox. It returns redacted stdout and stderr (every occurrence of every
injected secret, plus its base64/hex forms, replaced with `[REDACTED:VAR]`), a
normalized exit of `success` or `failure` (the raw status goes to the audit log, never
to the AI), and a `timed_out` flag.

### Parameters

| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| `command` | string | — | Resolved and sandbox-wrapped before secret values are built into the env. |
| `args` | string[] | `[]` | Capped at 256 entries. |
| `env` | object | `{}` | `VAR → secret_name`. Max 32 entries; names ≤ 256 bytes and checked against the [deny-list](./env-deny-list.md). |
| `timeout_seconds` | number | 60 | Capped at 600. |
| `allow_network` | bool | false | `true` lifts the network block (audited as `network_allowed`); filesystem sandbox still applies. |
| `isolation` | string | `"net"` | `"net"` or `"full"`; see [Sandbox profiles](../tutorials/sandbox-and-hardening.md#isolation-profiles). |

### Limits and quantization

Each output stream is capped at 256 KiB. Truncation happens silently: no truncation flag
is returned to the AI, since that flag was an output-volume oracle. AI-visible
stdout/stderr lengths are bucket-quantized, padded up to 1/4/16/64 KiB or 256 KiB, to
blunt the length side channel; the padding tail starts with a visible `\n[opq-pad]\n`
marker so tooling can strip it.

### Error taxonomy

Errors returned to the AI are fixed-taxonomy strings, never wrapped backend or library
text:

`backend_error` · `not_found: <name>` · `exec_not_found` · `exec_permission_denied` ·
`exec_start_failed` · `sandbox_unavailable` · `wrap_command_failed` · `invalid_input`
· `invalid_secret_name`

Revoked, expired, and missing secrets all collapse to `not_found`, so the error channel
cannot be used as a policy-state oracle. The precise reason goes to the audit log only.

## `audit_tail`

```jsonc
audit_tail({ n: 20 })   // n capped at 200
```

Returns recent audit entries. Over MCP the results are restricted to `caller="mcp"`
entries, and the `msg` field of `mcp_run` lines passes through a closed allowlist where
only `timed_out` survives; `raw_exit`, `elapsed_ms`, truncation flags, and AI-supplied
command/args echoes are stripped, closing the exit-code, timing, and output-volume
oracle paths.

Each `audit_tail` call appends its own `audit_tail` entry before reading, so an AI
scraping operator activity is itself visible. The self-entry is stripped from the AI's
response window (matched by a per-call random nonce) but persists in the
operator-visible log. CLI users see the full, unfiltered log via `opq audit`.

See [Audit Log](./audit-log.md) and [Audit Log Integrity](../security/audit-integrity.md).
