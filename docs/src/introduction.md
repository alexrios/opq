# Introduction

`opq` stores secrets in your OS keyring and runs programs with those secrets injected
as environment variables. The program receives the value; anything it prints is
scanned, and the secret is replaced with `[REDACTED:VAR]` before the output comes
back. An AI agent can use a secret to run a command without reading the secret itself.

Status: v1.1.6. Linux only; a macOS Keychain backend is planned for v1.2.

## The problem

An AI agent that runs shell commands should not see your API keys, but the subprocess
it spawns usually needs them. `opq` sits between the two:

- The agent runs `opq exec --env VAR=secret_name -- ...`, or calls the
  `run_with_secrets` MCP tool.
- `opq` reads the secret from the keyring and passes it to the child process as an
  environment variable.
- The child uses it. `opq` scans the child's stdout and stderr and replaces the value
  with `[REDACTED:VAR]`.
- The agent receives the redacted output, not the plaintext.

```
opq exec --env OPENAI_API_KEY=openai_key -- curl ...   # runs
opq get  openai_key | cat                              # refused
opq mcp                                                # MCP server over stdio
```

## Guarantees

These rules hold even when the calling agent is trying to extract the secret:

- Reading a value to anything other than a terminal is refused.
- Secret values never appear on argv. `set` reads from stdin or a hidden prompt.
- The MCP server has no tool that returns a value. `list_secrets` returns names;
  `run_with_secrets` returns redacted output.
- Subprocess output is redacted by default, including base64 and hex forms of the
  value.
- MCP subprocesses run with no network route and a private PID namespace, so a leaked
  value still cannot leave the machine.
- Every use is written to an audit log the agent cannot read in full.

The [MCP tutorial](./tutorials/mcp-claude-code.md) includes a session where the agent
tries each of these in turn and fails.

## Where to start

- [Installation](./getting-started/installation.md) and
  [Quick Start](./getting-started/quick-start.md) for a first run.
- The [Tutorials](./tutorials/cli-basics.md) for hands-on walkthroughs.
- The [Reference](./reference/cli-commands.md) for the full command and tool surface.
- The [Security Model](./security/threat-model.md) for the threat model and sandbox
  internals.
