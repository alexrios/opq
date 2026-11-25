# Quick Start

Five commands, assuming `opq` is [installed](./installation.md) and `opq doctor` passes.
This first run stays local, so it needs no API key and no network.

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

Swap the demo for a real credential and command. `--env VAR=secret_name` (or `-e VAR=secret_name`)
maps an environment variable (left side) to a stored `opq` secret name (right side);
when both names match, shorthand `-e VAR` maps `VAR=VAR`.

Prefer tools and SDKs that read credentials directly from their environment — the secret
never leaves the process environment or touches command arguments:

```sh
printf 'ghp_...' | opq set GH_TOKEN
opq exec -e GH_TOKEN -- gh api /user
```

When using `curl`, pass the authorization header over stdin (`-K -`) instead of
expanding `$OPENAI_API_KEY` into a `-H` flag:

```sh
printf 'sk-...' | opq set openai_key
opq exec -e OPENAI_API_KEY=openai_key -- \
  sh -c 'printf "header = \"Authorization: Bearer %s\"\n" "$OPENAI_API_KEY" | curl -sS -K - https://api.openai.com/v1/models'
```

> **Why not `curl -H "Authorization: Bearer $OPENAI_API_KEY"`?** Expanding a secret via
> `sh -c` into a child command's `argv` makes the plaintext visible to other processes
> via `ps` or `/proc/<pid>/cmdline`. Reading from the environment directly (SDKs, `gh`,
> `aws`) or passing config over stdin (`curl -K -`) keeps the value off `argv`.

If the response echoes the key back, `opq` redacts it to `[REDACTED:OPENAI_API_KEY]`
before it reaches your terminal or agent.

## Next

- [CLI Basics](../tutorials/cli-basics.md) walks the same commands in more depth.
- [opq + Claude Code](../tutorials/mcp-claude-code.md) wires `opq` into an AI agent.
- [CLI Commands](../reference/cli-commands.md) is the full command surface.
