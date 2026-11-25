# opq + Claude Code (MCP)

This registers `opq` with an MCP-aware client (Claude Code, Claude Desktop, Cursor, or
VS Code), then explains name-based credential use and accidental-output redaction.
Arbitrary consuming commands can still encode secrets or exfiltrate them when networking
is allowed. For adversarial agents, use the
[fixed-operation proxy](./sandbox-and-hardening.md#the-policy-proxy-pattern).

## 1. Register the MCP server

First confirm your keyring and OS sandbox pass locally:

```sh
opq doctor
```

Then register `opq mcp` in your client:

### Claude Code

```sh
claude mcp add opq -- opq mcp
```

Claude Code stores this in `~/.claude.json` (or commit the JSON block below to `.mcp.json`
for a shared project). Confirm it registered with `claude mcp list` (or `/mcp` inside
Claude Code); `opq` should show as connected.

### Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or
`~/.config/Claude/claude_desktop_config.json` (Linux):

```json
{
  "mcpServers": {
    "opq": {
      "command": "/opt/homebrew/bin/opq",
      "args": ["mcp"]
    }
  }
}
```

### Cursor

Add to `~/.cursor/mcp.json` (global) or `.cursor/mcp.json` (per-project):

```json
{
  "mcpServers": {
    "opq": {
      "command": "opq",
      "args": ["mcp"]
    }
  }
}
```

### VS Code

Add to `.vscode/mcp.json` (workspace) or your user MCP settings:

```json
{
  "servers": {
    "opq": {
      "type": "stdio",
      "command": "opq",
      "args": ["mcp"]
    }
  }
}
```

### Generic `mcpServers` JSON

Most other stdio MCP clients accept the standard `mcpServers` block:

```json
{
  "mcpServers": {
    "opq": {
      "command": "opq",
      "args": ["mcp"]
    }
  }
}
```

> **Minimal `PATH` in GUI apps:** Desktop clients such as Claude Desktop often start
> with a minimal `PATH` that excludes Homebrew (`/opt/homebrew/bin`) or `~/go/bin`. If
> the server fails to start with `ENOENT`, replace `"opq"` with the absolute path printed
> by `which opq`.

`opq mcp` speaks the Model Context Protocol over stdio. At startup it runs an OS sandbox
probe (on Linux, a bubblewrap namespace probe; see
[Installation](../getting-started/installation.md#troubleshooting-the-bubblewrap-startup-probe)) and
stops if the sandbox cannot be built.

## 2. The three tools

| Tool | What it does |
| --- | --- |
| `list_secrets()` | Returns secret names only. |
| `run_with_secrets({ command, args, env, ... })` | Runs a command with named secrets injected as env vars; returns redacted stdout/stderr. |
| `audit_tail({ n })` | Returns recent audit entries (the AI-filtered view). |

There is no `get_secret_value` tool. This blocks direct retrieval; consuming programs
still receive plaintext, and their output can carry information. The
[MCP Tools reference](../reference/mcp-tools.md) has every parameter, tool annotation,
schema bound, and the error taxonomy.

## 3. Store a secret to use

From your own shell, not the agent:

```sh
opq set api_token --ttl 24h
```

The agent references `api_token` by name; the consuming subprocess receives its value.
MCP children inherit a minimal environment (`PATH=/usr/bin:/usr/sbin:/bin:/sbin`,
`HOME=/tmp`, plus the requested `env` mappings), so pass absolute paths for Homebrew or
user-installed binaries (for example `/opt/homebrew/bin/gh`).

The subprocess is network-blocked by default, so start with a local command that works
under the default sandbox:

```jsonc
run_with_secrets({
  command: "sh",
  args: ["-c", "echo \"token length: $(printf %s \"$TOK\" | wc -c)\""],
  env: { TOK: "api_token" }
})
```

To reach an external service, the agent opts into the network explicitly with
`allow_network: true` (recorded in the audit log as `network_allowed`) and `isolation: "readonly"`
(an alias for `"net"`). Prefer a consumer that reads credentials directly from the
environment (such as `gh`, `aws`, or an operator-reviewed wrapper):

```jsonc
run_with_secrets({
  command: "/opt/homebrew/bin/gh",
  args: ["api", "/user"],
  env: { GH_TOKEN: "github_token" },
  isolation: "readonly",
  allow_network: true
})
```

When calling `curl`, feed the header over stdin (`-K -`) instead of expanding `$TOK`
into `curl -H`, so the secret stays off `argv` and `ps`:

```jsonc
run_with_secrets({
  command: "/usr/bin/sh",
  args: ["-c", "printf 'header = \"Authorization: Bearer %s\"\\n' \"$TOK\" | /usr/bin/curl -sS -K - https://api.example.com/me"],
  env: { TOK: "api_token" },
  isolation: "readonly",
  allow_network: true
})
```

See [Sandbox & Hardening](./sandbox-and-hardening.md).

## Trying to extract the secret

The following illustrative examples show which raw/base64/hex forms the redactor
recognizes. They are not recommended agent workflows and do not establish protection
against arbitrary encoding or output-content channels.

### The AI can see names, not values

```jsonc
list_secrets()  →  { "names": ["api_token"] }
```

### The AI uses the secret, then tries to echo it

```jsonc
run_with_secrets({
  command: "sh",
  args: ["-c", "echo \"len=$(printf %s \"$TOK\" | wc -c)\"; \
                echo \"sha256=$(printf %s \"$TOK\" | shasum -a 256 | cut -d' ' -f1)\"; \
                echo \"raw_value=$TOK\""],
  env: { TOK: "api_token" }
})
```
```text
len=51
sha256=3864f9119bfdcf91e616f1e6307bb8325a453f78805519bdcf9e921edd8778e4
raw_value=[REDACTED:TOK]
```

The subprocess computed the secret's real length and SHA-256, so it received and used
the plaintext. The value read back is `[REDACTED:TOK]`; the raw value was redacted. Length and hash remain visible, so this demonstration is
not a secrecy guarantee. Agent workflows should not request lengths, hashes, or
encoded credential output.

### Common base64 and hex forms are redacted

```jsonc
run_with_secrets({ command: "sh", args: ["-c",
  "echo \"b64=$(printf %s \"$TOK\" | base64 | tr -d '\\n')\"; \
   echo \"hex=$(printf %s \"$TOK\" | od -An -tx1 | tr -d ' \\n')\""],
  env: { TOK: "api_token" } })
```
```text
b64=[REDACTED:TOK]
hex=[REDACTED:TOK]
```

The redactor registers the base64 (std/URL, padded/unpadded) and hex (lower/upper)
forms of each secret, so the "just base64 it" route is caught.

### Default networking blocks outbound TCP

```jsonc
run_with_secrets({ command: "bash", args: ["-c",
  "exec 3<>/dev/tcp/1.1.1.1/53 && echo EGRESS_OPEN || echo EGRESS_BLOCKED"],
  env: { TOK: "api_token" } })
```
```text
stderr: bash: connect: Network is unreachable
stdout: EGRESS_BLOCKED (exit 1)
```

The subprocess has no route out, so an outbound TCP `connect()` fails: `ENETUNREACH`
under Linux's network namespace, or a sandbox denial under macOS Seatbelt.

### Audit visibility

```jsonc
audit_tail({ n: 3 })
```
```text
{"ts":"…","action":"mcp_run","secret_names":["api_token"],"caller":"mcp","pid":…}
{"ts":"…","action":"mcp_run","secret_names":["api_token"],"caller":"mcp","pid":…}
{"ts":"…","action":"mcp_run","secret_names":["api_token"],"caller":"mcp","pid":…}
```

The operator sees which secrets were used and when (full detail via `opq audit`). The
agent's own `audit_tail` view is allowlist-filtered to remove the exit-code, timing,
and output-volume oracles, and each `audit_tail` call attempts to record its own entry. Audit storage failures
are reported to the operator; execution currently continues.

## Hardening for adversarial deployments

The default sandbox blocks a lot but is not a complete jail; loopback services, custom
Unix sockets, and timing channels remain. For high-risk environments, front `opq mcp`
with a policy-enforcing wrapper that allowlists `(command, args, env)` tuples. See
[Sandbox & Hardening](./sandbox-and-hardening.md#the-policy-proxy-pattern) and the
[Threat Model](../security/threat-model.md).
