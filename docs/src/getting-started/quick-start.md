# Quick Start

Five commands, assuming `opq` is [installed](./installation.md) and your keyring
session is unlocked. This first run stays local, so it needs no API key and no network.

```sh
# 1. Store a secret under the name "demo_key"
printf 'super-secret-value' | opq set demo_key

# 2. List names (values are never printed)
opq list

# 3. Use it: inject "demo_key" as $API, then watch the redactor catch it
opq exec --env API=demo_key -- sh -c 'echo "leaked: $API"'
# → leaked: [REDACTED:API]

# 4. Review what happened
opq audit --tail 10

# 5. Clean up
opq delete demo_key
```

The subprocess received `super-secret-value` in `$API` and tried to print it; `opq`
scanned the output and replaced the value with `[REDACTED:API]` before it came back.
That redaction is the core promise, and it just worked offline.

`set` reads the value from stdin (never argv, so it stays out of shell history and `ps`
output). `list` prints names only. `exec` resolves `demo_key`, injects its value as
`API`, and scans the output; the base64 and hex forms of the value are caught too, and
the `[REDACTED:API]` token uses the env var name. `audit` shows the `set`,
`exec_inject`, and `delete` entries.

## Use it for real

Swap the demo for a real credential and command. `--env OPENAI_API_KEY=openai_key` maps
the environment variable `OPENAI_API_KEY` (what the subprocess reads) to the secret
stored as `openai_key` (left side is the env var, right side is the opq name):

```sh
printf 'sk-...' | opq set openai_key
opq exec --env OPENAI_API_KEY=openai_key -- \
  sh -c 'curl https://api.openai.com/v1/models -H "Authorization: Bearer $OPENAI_API_KEY"'
```

The value exists only in the child's environment; it never reaches your shell's argv,
and if the response echoed it back it would return as `[REDACTED:OPENAI_API_KEY]`.

## Next

- [CLI Basics](../tutorials/cli-basics.md) walks the same commands in more depth.
- [opq + Claude Code](../tutorials/mcp-claude-code.md) wires `opq` into an AI agent.
- [CLI Commands](../reference/cli-commands.md) is the full command surface.
