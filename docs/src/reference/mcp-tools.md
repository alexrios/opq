# MCP Tools

`opq mcp` exposes three tools over stdio. There is no `get_secret_value` tool; that
absence blocks direct value retrieval. Arbitrary consuming commands still have output
and encoding channels. Register the server as shown in the
[MCP tutorial](../tutorials/mcp-claude-code.md#1-register-the-mcp-server).

## Tool annotations

Each tool advertises MCP `ToolAnnotations` so clients can apply appropriate confirmation
and safety policies:

| Tool | `readOnlyHint` | `idempotentHint` | `destructiveHint` | `openWorldHint` | Notes |
| --- | --- | --- | --- | --- | --- |
| `list_secrets` | `true` | `true` | `false` | `false` | Reads secret names only (audited). |
| `run_with_secrets` | `false` | — | `true` | `true` | Executes an external command with injected credentials. |
| `audit_tail` | `true` | `false` | `false` | `false` | Appends a self-audit entry on every call, so not idempotent. |

## `list_secrets`

```jsonc
list_secrets()  →  { "names": ["api_token", "openai_key"] }
```

Returns secret names only. Internal policy items (`meta/...`) and revoked tombstones are
filtered out, so the AI never sees the storage scheme or a tombstone's existence. The
call is audited before the backend is queried, so probing a degraded keyring still
leaves a trace.

## `run_with_secrets`

Prefer consumers that read credentials directly from the environment (or feed headers via
stdin such as `curl -K -` so secrets stay off `argv` and `ps`):

```jsonc
run_with_secrets({
  command: "/usr/local/libexec/provider-status",
  args: [],
  env: { API_TOKEN: "api_token" },
  timeout_seconds: 60,        // optional, default 60, bounds 1..600
  allow_network: true,        // optional, default false
  isolation: "readonly"       // optional: "readonly" | "net" (default) | "full"
})
```

Runs `command` with the named secrets injected as environment variables, inside the
OS-native sandbox (`bwrap` on Linux, `sandbox-exec`/Seatbelt on macOS). It returns
redacted stdout and stderr (every occurrence of every
injected secret, plus its base64/hex forms, replaced with `[REDACTED:VAR]`), a
normalized exit of `success` or `failure` (the raw status goes to the audit log, never
to the AI), and a `timed_out` flag.

### Parameters & JSON Schema bounds

| Field | Type | Default | Schema & runtime bounds |
| --- | --- | --- | --- |
| `command` | string | (required) | Resolved and sandbox-wrapped before secret values are built into the env. |
| `args` | string[] | `[]` | `maxItems: 256`; total `command` + `args` text capped at 1 MiB. |
| `env` | object | `{}` | `VAR → secret_name`. Max 32 entries; env names ≤ 256 bytes and checked against the [deny-list](./env-deny-list.md); secret names match `[A-Za-z0-9_.-]{1,128}`. |
| `timeout_seconds` | integer | `60` | `minimum: 1`, `maximum: 600`. |
| `allow_network` | boolean | `false` | `true` lifts the network block (audited as `network_allowed`); filesystem sandbox still applies. |
| `isolation` | string | `"net"` | `enum: ["net", "readonly", "full"]`. `"readonly"` is an alias for `"net"`; see [Sandbox profiles](../tutorials/sandbox-and-hardening.md#isolation-profiles). |

`allow_network: true` requires `"readonly"` (or `"net"`) isolation; combining it with
`isolation: "full"` is rejected as a validation error.

### Child environment & macOS sandbox constraints

- **Minimal child environment:** Subprocesses inherit no parent environment variables
  beyond fixed minimal `PATH=/usr/bin:/usr/sbin:/bin:/sbin`, `HOME=/tmp`, and the
  explicitly requested `env` mappings. On macOS/Homebrew or when running user-installed
  tools outside standard system paths, invoke the binary by its absolute path (for
  example `/opt/homebrew/bin/jq`).
- **Read-only host filesystem & macOS writes:** The host filesystem is read-only under
  all sandbox profiles. On Linux, `SandboxNet` overlays an ephemeral tmpfs at `/tmp`; on
  macOS (Seatbelt), **all filesystem writes — including `/tmp` and `/dev/null` — are
  denied** under the sandbox. Protected Docker, GPG, SSH, audit, and policy Unix sockets
  remain blocked even when `allow_network: true`.

### Resource limits and output

Each output stream is capped at 256 KiB after redaction. Output has no artificial
padding. Content and exact length remain visible; neither padding nor a normalized
exit code prevents a caller-controlled command from encoding secret information.

At most four runs may prepare or execute concurrently. Additional requests return
`server_busy` without waiting. Command and argument strings together are capped at
1 MiB. The deadline starts before preparation and is checked across secret resolution;
native keyring calls cannot be canceled while in flight. Ordinary child process groups
are killed on cancellation and after the direct command exits. Server signals and
abrupt stdio disconnects cancel active tool handlers before shutdown waits for them. Pipe draining is bounded
by a further 250 ms, including when a child leaves inherited pipes open. Completion
auditing has its own bounded 250 ms lock-wait budget after cancellation. Native
filesystem operations such as `fsync`, like native keyring prompts, cannot be
preempted while in flight. Processes that
deliberately escape the group require OS-level containment. Interactive CLI commands
retain their foreground terminal group and use bounded pipe draining.

### Error taxonomy

Backend, sandbox, and process errors returned to the AI are fixed-taxonomy strings,
never wrapped backend or library text:

`backend_error` · `not_found: <name>` · `exec_not_found` · `exec_permission_denied` ·
`exec_start_failed` · `sandbox_unavailable` · `wrap_command_failed` · `invalid_input`
· `invalid_secret_name` · `server_busy` · `request_canceled`

Revoked, expired, and missing secrets all collapse to `not_found`, so the error channel
cannot be used as a policy-state oracle. The precise reason goes to the audit log only.

Input-validation errors (a missing `command`, an invalid env-var name, an incompatible
`isolation`) are returned as opq's own literal messages rather than taxonomy codes; they
carry no backend or library text.

## `audit_tail`

```jsonc
audit_tail({ n: 20 })   // integer, schema bounds: minimum 1, maximum 200
```

Returns recent audit entries. Over MCP the results are restricted to `caller="mcp"`
entries, and the `msg` field of `mcp_run` lines passes through a closed allowlist where
only `timed_out` survives; `raw_exit`, `elapsed_ms`, truncation flags, and AI-supplied
command/args echoes are stripped, avoiding those additional detailed disclosures. Command output, success, and observable
request timing remain channels.

Each `audit_tail` call appends its own `audit_tail` entry before reading, so an AI
scraping operator activity is itself visible. The self-entry is stripped from the AI's
response window (matched by a per-call random nonce) but persists in the
operator-visible log. CLI users see the full, unfiltered log via `opq audit`.

See [Audit Log](./audit-log.md) and [Audit Log Integrity](../security/audit-integrity.md).
