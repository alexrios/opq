# CLI Basics

The everyday loop: store a secret, use it, check the audit trail, clean up. Every
command here is safe to run with an unlocked keyring.

## 1. Store a secret

Values are never read from argv. `opq set` reads from stdin, or prompts on the hidden
TTY if stdin is a terminal.

```sh
# From stdin (pipe, here-string, or file):
printf 'sk-live-abc123' | opq set stripe_secret_key

# Interactive hidden prompt (nothing echoes as you type — not even asterisks):
opq set stripe_secret_key
# Enter value for 'stripe_secret_key':
```

The interactive prompt strips surrounding whitespace and bracketed-paste markers, so
pasting from a web page or a `.env` line works. The piped path stores bytes verbatim so
whitespace-significant values stay intact; if piped input ends with a newline (`\n` or
`\r\n`), `opq` warns on stderr and suggests using `printf` or passing `--trim` to strip
trailing newlines automatically.

Use `--no-clobber` to refuse overwriting an existing live secret, or `--keep-ttl` to
rotate a secret's value while keeping its current expiry. When overwriting an existing
secret or reviving a `REVOKED`/`UPDATE-PENDING` entry, `opq set` prints a notice to
stderr (before prompting in interactive mode).

Secret names match `[A-Za-z0-9_.-]{1,128}`: no slashes, no spaces.

## 2. List and inspect your secrets

```sh
opq list
```

`list` prints names only, never values, with aligned columns on a terminal and human-friendly
expiry annotations (respecting `NO_COLOR`):

```text
stripe_secret_key
openai_key         expires in 7d (2026-06-14 12:00 UTC)
old_token          REVOKED
stale_token        EXPIRED
```

When stdout is piped (non-TTY), default `opq list` emits tab-separated `<name>` /
`<name>\t<status>` lines so scripts stay stable. Add flags to dig deeper without ever
touching secret values:

```sh
opq list --long                 # (-l) include status, created_at, expires_at / revoked_at
opq list --status expired       # filter: all | active | expired | revoked | pending
opq list --json                 # structured JSON array (metadata only, never values)
opq info stripe_secret_key      # detailed metadata for a single secret (supports --json)
```

## 3. Use a secret in a command

`opq exec` injects one or more named secrets as environment variables and redacts the
child's output. Everything after `--` is the command and its arguments; the values
exist only in the child's environment and never reach your shell's argv.

Start local, with no network, to see redaction directly:

```sh
opq exec --env API=stripe_secret_key -- sh -c 'echo "value is $API"'
# → value is [REDACTED:API]
```

Against a real service, prefer tools and SDKs that read credentials straight from the
environment. When the env var name and secret name match, `-e VAR` is shorthand for
`-e VAR=VAR`:

```sh
# Native env-reading consumer (secret never enters argv/ps):
opq exec -e GH_TOKEN -- gh api /user

# With curl, pass credentials over stdin (-K -) so the value stays off argv/ps:
opq exec -e STRIPE_KEY=stripe_secret_key -- \
  sh -c 'printf "user = \"%s:\"\n" "$STRIPE_KEY" | curl -sS -K - https://api.stripe.com/v1/charges'
```

> **Keep secrets out of `argv`:** Avoid patterns like
> `sh -c 'curl -u "$STRIPE_KEY:" ...'` in real workflows. Even though `opq` never puts
> secrets on its own argv, expanding `$STRIPE_KEY` into a child command's arguments
> exposes the value in `ps` and `/proc/<pid>/cmdline`. Use native env variables or stdin
> config (`curl -K -`) instead.

Inject several at once:

```sh
opq exec \
  -e STRIPE_KEY=stripe_secret_key \
  -e OPENAI_KEY=openai_key \
  -- ./my-script.sh
```

The redactor also catches base64 and hex forms, so a subprocess that pipes the secret
through `base64` or `xxd` does not leak it by accident. See
[The Redactor](../security/redactor.md) for what is and is not covered.

## 4. Inspect the audit log

```sh
opq audit --tail 10
```

On a terminal, `opq audit` prints an aligned table (highlighting `denied`,
`redaction_disabled`, and `network_allowed` entries; respects `NO_COLOR`):

```text
TIME                  CALLER  ACTION       SECRET             DETAIL
2026-06-07 12:00:00Z  cli     set          stripe_secret_key
2026-06-07 12:00:05Z  cli     exec_inject  stripe_secret_key
```

When piped or passed `--json`, it emits raw JSONL for tooling like `jq`:

```json
{"ts":"2026-06-07T12:00:00.000Z","action":"set","secret_name":"stripe_secret_key","caller":"cli","pid":1234}
{"ts":"2026-06-07T12:00:05.000Z","action":"exec_inject","secret_name":"stripe_secret_key","caller":"cli","pid":1240}
```

Filter before taking the tail with `--caller cli|mcp`, `--action <action>`,
`--secret <name>`, or inspect the entire log with `--all`:

```sh
opq audit -n 20 --action denied
opq audit --caller mcp --secret stripe_secret_key
```

`caller` is `cli` for direct CLI use and `mcp` when the request came through the MCP
server, so human and AI access are distinguishable. See the
[Audit Log reference](../reference/audit-log.md) for the full schema.

## 5. Clean up

```sh
opq delete stripe_secret_key
```

`delete` removes one or more secrets (values and any TTL or revocation records) in one
call (`opq delete key_a key_b`).

## Reading a value

Sometimes a human needs to see a value. `opq get --plaintext` does that, gated so an
automated caller cannot use it:

```sh
OPQ_I_AM_HUMAN=1 opq get stripe_secret_key --plaintext
```

It refuses unless all three hold:

1. stdout is a real TTY, so `opq get ... | cat` and redirects to a file are blocked,
2. `OPQ_I_AM_HUMAN=1` is set inline on the command, and
3. you retype the secret's name on the controlling terminal when prompted.

This is the same gate that protects `exec --no-redact`. See
[CLI Commands](../reference/cli-commands.md#opq-get).

## Next

- [TTL & Revocation](./ttl-and-revocation.md) bounds how long a secret stays usable.
- [opq + Claude Code](./mcp-claude-code.md) hands secrets to an AI agent.
