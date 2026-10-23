# opq + Claude Code (MCP)

This registers `opq` with an MCP-aware client (Claude Code here), then explains
name-based credential use and accidental-output redaction. Arbitrary consuming
commands can still encode secrets or exfiltrate them when networking is allowed.
For adversarial agents, use the [fixed-operation proxy](./sandbox-and-hardening.md#the-policy-proxy-pattern).

## 1. Register the MCP server

Add `opq` to your MCP client's server configuration. In Claude Code the quickest way is
the CLI:

```sh
claude mcp add opq -- opq mcp
```

That writes an entry equivalent to this `mcpServers` block, which is the format other
MCP clients accept directly (Claude Code stores it in `~/.claude.json`; a project can
also commit it to `.mcp.json`):

```jsonc
{
  "mcpServers": {
    "opq": {
      "command": "opq",
      "args": ["mcp"]
    }
  }
}
```

`opq mcp` speaks the Model Context Protocol over stdio. At startup it runs an OS sandbox
probe (on Linux, a bubblewrap namespace probe; see
[Installation](../getting-started/installation.md#troubleshooting-the-bubblewrap-startup-probe)) and
stops if the sandbox cannot be built. Confirm the server registered with `claude mcp
list` (or `/mcp` inside Claude Code); `opq` should show as connected.

## 2. The three tools

| Tool | What it does |
| --- | --- |
| `list_secrets()` | Returns secret names only. |
| `run_with_secrets({ command, args, env, ... })` | Runs a command with named secrets injected as env vars; returns redacted stdout/stderr. |
| `audit_tail({ n })` | Returns recent audit entries (the AI-filtered view). |

There is no `get_secret_value` tool. This blocks direct retrieval; consuming programs
still receive plaintext, and their output can carry information. The
[MCP Tools reference](../reference/mcp-tools.md) has every parameter and the error
taxonomy.

## 3. Store a secret to use

From your own shell, not the agent:

```sh
opq set api_token --ttl 24h
```

The agent references `api_token` by name; the consuming subprocess receives its value.
The subprocess is
network-blocked by default, so start with a local command that works under the default
sandbox:

```jsonc
run_with_secrets({
  command: "sh",
  args: ["-c", "echo \"token length: $(printf %s \"$TOK\" | wc -c)\""],
  env: { TOK: "api_token" }
})
```

To reach an external service, the agent opts into the network explicitly with
`allow_network: true` (recorded in the audit log as `network_allowed`):

```jsonc
run_with_secrets({
  command: "sh",
  args: ["-c", "curl -s -H \"Authorization: Bearer $TOK\" https://api.example.com/me"],
  env: { TOK: "api_token" },
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
