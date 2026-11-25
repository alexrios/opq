# Introduction

`opq` stores secrets in your OS keyring and runs programs with those secrets injected
as environment variables. The program receives the value; anything it prints is
scanned, and the secret is replaced with `[REDACTED:VAR]` before the output comes
back. This protects against accidental disclosure by consuming programs; a hostile
caller-controlled command can still encode a secret into output.

It pays off without an AI agent, too: secrets stay out of command arguments and shell
history and live in the OS keyring instead of a `.env` file. The consuming program
receives plaintext in its environment, which may be inspectable by privileged or
same-user processes depending on the operating system. The AI-safety properties
build on that base.

Status: v1.3.0. Supported on Linux (Secret Service) and macOS (Keychain), licensed under
the GNU AGPL-3.0.

## The problem

An AI agent that runs shell commands should not see your API keys, but the subprocess
it spawns usually needs them. `opq` sits between the two:

- The agent runs `opq exec --env VAR=secret_name -- ...`, or calls the
  `run_with_secrets` tool over MCP (the Model Context Protocol, the standard way an
  agent calls external tools).
- `opq` reads the secret from the keyring and passes it to the child process as an
  environment variable.
- The child uses it. `opq` scans the child's stdout and stderr and replaces the value
  with `[REDACTED:VAR]`.
- The agent receives the redacted output, not the plaintext.

```sh
opq exec --env OPENAI_API_KEY=openai_key -- ./my-client  # runs; output redacted
opq get  openai_key | cat                                # refused
opq mcp                                                  # MCP server over stdio
```

## How secrets flow

<figure class="opq-diagram">
<svg role="img" aria-labelledby="flow-title flow-desc" viewBox="0 0 720 248" xmlns="http://www.w3.org/2000/svg">
  <title id="flow-title">opq Data and Redaction Flow</title>
  <desc id="flow-desc">Secret values move from the OS Keyring into memguard locked memory via resolveSecret, enter the isolated child process environment, and pass through RedactingWriter and cappedWriter before reaching the agent or terminal.</desc>
  <defs>
    <marker id="flow-arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path d="M 0 1 L 10 5 L 0 9 z" class="svg-arrow-head"/>
    </marker>
  </defs>
  <circle cx="22" cy="14" r="4.5" class="svg-box-note"/>
  <text x="32" y="18" class="svg-accent-note">Trusted opq process</text>
  <circle cx="196" cy="14" r="4.5" class="svg-box-warn"/>
  <text x="206" y="18" class="svg-accent-warn">Isolated child (plaintext in env)</text>
  <circle cx="436" cy="14" r="4.5" class="svg-box-tip"/>
  <text x="446" y="18" class="svg-accent-tip">Redacted &amp; bounded egress</text>
  <rect x="14" y="34" width="204" height="74" rx="8" class="svg-box-note"/>
  <text x="116" y="56" text-anchor="middle" class="svg-title">1. OS Keyring</text>
  <text x="116" y="74" text-anchor="middle" class="svg-sub">Keychain · Secret Service</text>
  <text x="116" y="91" text-anchor="middle" class="svg-mono">Encrypted store + meta/&lt;name&gt;</text>
  <line x1="218" y1="71" x2="255" y2="71" class="svg-edge" marker-end="url(#flow-arrow)"/>
  <rect x="258" y="34" width="204" height="74" rx="8" class="svg-box-note"/>
  <text x="360" y="56" text-anchor="middle" class="svg-title">2. memguard</text>
  <text x="360" y="74" text-anchor="middle" class="svg-sub">resolveSecret() + policy lock</text>
  <text x="360" y="91" text-anchor="middle" class="svg-mono">Locked RAM · TTL/revoked gate</text>
  <line x1="462" y1="71" x2="499" y2="71" class="svg-edge" marker-end="url(#flow-arrow)"/>
  <rect x="502" y="34" width="204" height="74" rx="8" class="svg-box-warn"/>
  <text x="604" y="56" text-anchor="middle" class="svg-title">3. Child Env</text>
  <text x="604" y="74" text-anchor="middle" class="svg-mono">VAR=&lt;plaintext&gt; in child</text>
  <text x="604" y="91" text-anchor="middle" class="svg-sub">OS sandbox (bwrap / Seatbelt)</text>
  <path d="M 604 108 L 604 133 L 116 133 L 116 155" class="svg-edge" marker-end="url(#flow-arrow)"/>
  <rect x="278" y="122" width="164" height="22" rx="11" class="svg-edge-pill"/>
  <text x="360" y="137" text-anchor="middle" class="svg-edge-label">stdout / stderr pipes</text>
  <rect x="14" y="158" width="204" height="74" rx="8" class="svg-box-tip"/>
  <text x="116" y="180" text-anchor="middle" class="svg-title">4. RedactingWriter</text>
  <text x="116" y="198" text-anchor="middle" class="svg-sub">Raw · Base64 · Hex → [REDACTED]</text>
  <text x="116" y="215" text-anchor="middle" class="svg-sub">Split-write safe; wipes scratch</text>
  <line x1="218" y1="195" x2="255" y2="195" class="svg-edge" marker-end="url(#flow-arrow)"/>
  <rect x="258" y="158" width="204" height="74" rx="8" class="svg-box-tip"/>
  <text x="360" y="180" text-anchor="middle" class="svg-title">5. cappedWriter</text>
  <text x="360" y="198" text-anchor="middle" class="svg-sub">256 KiB cap per stream (MCP)</text>
  <text x="360" y="215" text-anchor="middle" class="svg-sub">Short-circuits scan on overflow</text>
  <line x1="462" y1="195" x2="499" y2="195" class="svg-edge" marker-end="url(#flow-arrow)"/>
  <rect x="502" y="158" width="204" height="74" rx="8" class="svg-box-tip"/>
  <text x="604" y="180" text-anchor="middle" class="svg-title">6. Agent / Terminal</text>
  <text x="604" y="198" text-anchor="middle" class="svg-sub">Redacted output only</text>
  <text x="604" y="215" text-anchor="middle" class="svg-sub">Usage recorded in audit.log</text>
</svg>
<figcaption>End-to-end secret data path. Plaintext enters only the child environment and is scrubbed from stdout/stderr before returning to the caller. On CLI runs, output streams directly after <code>RedactingWriter</code> without the 256 KiB MCP cap.</figcaption>
</figure>

## Guarantees

These controls prevent direct retrieval and accidental output:

- Reading a value to anything other than a terminal is refused.
- Secret values never appear on argv. `set` reads from stdin or a hidden prompt.
- The MCP server has no tool that returns a value. `list_secrets` returns names;
  `run_with_secrets` returns redacted output.
- Subprocess output is redacted by default, including base64 and hex forms of the
  value.
- MCP subprocesses run in an OS-native sandbox with no network route (and, on Linux, a
  private PID namespace) unless network access is explicitly granted. Output and
  non-network channels remain possible; see the [threat model](./security/threat-model.md).
- Uses are submitted to an audit log that MCP cannot read in full. Audit write
  failures are reported to the operator; execution currently continues.

The [MCP tutorial](./tutorials/mcp-claude-code.md) includes a session where the agent
tries each of these in turn and fails.

The network and filesystem sandbox applies to MCP `run_with_secrets` runs and to
`opq exec --sandbox`. A plain CLI `opq exec` still injects and redacts, but does not
isolate the network, since direct CLI use is the trusted-human path. For a side-by-side
comparison of **CLI `opq exec`**, **MCP Sandbox**, and the **Policy Proxy**, see
[Choosing a trust boundary](./tutorials/sandbox-and-hardening.md#choosing-a-trust-boundary).

## Where to start

- [Installation](./getting-started/installation.md) and
  [Quick Start](./getting-started/quick-start.md) for a first run.
- The [Tutorials](./tutorials/cli-basics.md) for hands-on walkthroughs.
- The [Reference](./reference/cli-commands.md) for the full command and tool surface.
- The [Security Model](./security/threat-model.md) for the threat model and sandbox
  internals.
