# opq + Claude Code (MCP)

This wires `opq` into an MCP-aware client (Claude Code here) and shows the agent
trying, and failing, to read a secret it is allowed to use.

## 1. Register the MCP server

Add `opq` to the client's MCP server configuration. For Claude Code that is the
`mcpServers` block:

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

`opq mcp` speaks the Model Context Protocol over stdio. At startup it runs a bubblewrap
namespace probe (see
[Installation](../getting-started/installation.md#the-bubblewrap-startup-probe)) and
stops if the sandbox cannot be built.

## 2. The three tools

| Tool | What it does |
| --- | --- |
| `list_secrets()` | Returns secret names only. |
| `run_with_secrets({ command, args, env, ... })` | Runs a command with named secrets injected as env vars; returns redacted stdout/stderr. |
| `audit_tail({ n })` | Returns recent audit entries (the AI-filtered view). |

There is no `get_secret_value` tool. An AI can use secrets, not read them. The
[MCP Tools reference](../reference/mcp-tools.md) has every parameter and the error
taxonomy.

## 3. Store a secret to use

From your own shell, not the agent:

```sh
printf 'sk-prod-XXXX' | opq set api_token
```

An agent call like this then works without the agent touching the value:

```jsonc
run_with_secrets({
  command: "sh",
  args: ["-c", "curl -s -H \"Authorization: Bearer $TOK\" https://api.example.com/me"],
  env: { TOK: "api_token" }
})
```

The subprocess runs network-blocked by default, so a `curl` to an external host fails
unless the agent passes `allow_network: true` (recorded in the audit log as
`network_allowed`). See [Sandbox & Hardening](./sandbox-and-hardening.md).

## Trying to extract the secret

The session below runs against a stored secret `api_token`, injected as `$TOK`, with
the agent acting as the adversary. Every output is what the model received back.

### The AI can see names, not values

```jsonc
list_secrets()  →  { "names": ["api_token"] }
```

### The AI uses the secret, then tries to echo it

```jsonc
run_with_secrets({
  command: "sh",
  args: ["-c", "echo \"len=$(printf %s \"$TOK\" | wc -c)\"; \
                echo \"sha256=$(printf %s \"$TOK\" | sha256sum | cut -d' ' -f1)\"; \
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
the plaintext. The value read back is `[REDACTED:TOK]`; the plaintext did not cross the
AI boundary.

### Encoding to dodge a byte-exact match also fails

```jsonc
run_with_secrets({ command: "sh", args: ["-c",
  "echo \"b64=$(printf %s \"$TOK\" | base64 -w0)\"; \
   echo \"hex=$(printf %s \"$TOK\" | od -An -tx1 | tr -d ' \\n')\""],
  env: { TOK: "api_token" } })
```
```text
b64=[REDACTED:TOK]
hex=[REDACTED:TOK]
```

The redactor registers the base64 (std/URL, padded/unpadded) and hex (lower/upper)
forms of each secret, so the "just base64 it" route is caught.

### A leaked value still cannot leave the box

```jsonc
run_with_secrets({ command: "bash", args: ["-c",
  "exec 3<>/dev/tcp/1.1.1.1/53 && echo EGRESS_OPEN || echo EGRESS_BLOCKED"],
  env: { TOK: "api_token" } })
```
```text
stderr: bash: connect: Network is unreachable
stdout: EGRESS_BLOCKED (exit 1)
```

The subprocess runs in a network namespace with no route out, so an outbound TCP
`connect()` fails with `ENETUNREACH`.

### Every use is logged

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
and output-volume oracles, and each `audit_tail` call leaves its own entry, so the
scraping is visible too.

## Hardening for adversarial deployments

The default sandbox blocks a lot but is not a complete jail; loopback services, custom
Unix sockets, and timing channels remain. For high-risk environments, front `opq mcp`
with a policy-enforcing wrapper that allowlists `(command, args, env)` tuples. See
[Sandbox & Hardening](./sandbox-and-hardening.md#the-policy-proxy-pattern) and the
[Threat Model](../security/threat-model.md).
