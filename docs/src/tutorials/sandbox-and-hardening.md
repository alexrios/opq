# Sandbox & Hardening

Every subprocess launched through the MCP `run_with_secrets` tool runs inside the
OS-native sandbox: `bwrap` (bubblewrap) on Linux, `sandbox-exec` (Seatbelt) on macOS.
This page compares `opq`'s three trust boundaries, then covers the isolation profiles,
the network opt-in, and the policy-proxy pattern for high-risk deployments. The full
bwrap argv, the macOS Seatbelt profiles, and the exploit each mask closes are in
[The Sandbox](../security/sandbox.md).

## Choosing a trust boundary

`opq` supports three deployment tiers depending on how much you trust the caller
invoking commands with your secrets:

<figure class="opq-diagram">
<svg role="img" aria-labelledby="tb-title tb-desc" viewBox="0 0 720 278" xmlns="http://www.w3.org/2000/svg">
  <title id="tb-title">opq Trust-Boundary Comparison</title>
  <desc id="tb-desc">Comparison of three deployment models: CLI opq exec for trusted humans, MCP Sandbox for semi-trusted coding agents, and an operator-owned Policy Proxy for untrusted or adversarial agents.</desc>
  <defs>
    <marker id="tb-arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path d="M 0 1 L 10 5 L 0 9 z" class="svg-arrow-head"/>
    </marker>
  </defs>
  <rect x="10" y="10" width="700" height="78" rx="8" class="svg-lane"/>
  <text x="22" y="26" class="svg-accent-note">1. CLI opq exec — Trusted human workflow</text>
  <rect x="22" y="34" width="116" height="44" rx="6" class="svg-box-note"/>
  <text x="80" y="53" text-anchor="middle" class="svg-title">Human</text>
  <text x="80" y="68" text-anchor="middle" class="svg-sub">CLI caller</text>
  <line x1="138" y1="56" x2="155" y2="56" class="svg-edge" marker-end="url(#tb-arrow)"/>
  <rect x="158" y="34" width="150" height="44" rx="6" class="svg-box-note"/>
  <text x="233" y="53" text-anchor="middle" class="svg-title">opq exec</text>
  <text x="233" y="68" text-anchor="middle" class="svg-sub">injects &amp; redacts</text>
  <line x1="308" y1="56" x2="325" y2="56" class="svg-edge" marker-end="url(#tb-arrow)"/>
  <rect x="328" y="34" width="206" height="44" rx="6" class="svg-box"/>
  <text x="431" y="53" text-anchor="middle" class="svg-title">Arbitrary command</text>
  <text x="431" y="68" text-anchor="middle" class="svg-sub">host FS &amp; net (opt. --sandbox)</text>
  <line x1="534" y1="56" x2="551" y2="56" class="svg-edge" marker-end="url(#tb-arrow)"/>
  <rect x="554" y="34" width="144" height="44" rx="6" class="svg-box-note"/>
  <text x="626" y="53" text-anchor="middle" class="svg-title">Redacted stream</text>
  <text x="626" y="68" text-anchor="middle" class="svg-sub">raw · b64 · hex</text>
  <rect x="10" y="100" width="700" height="78" rx="8" class="svg-lane"/>
  <text x="22" y="116" class="svg-accent-warn">2. MCP Sandbox (opq mcp) — Semi-trusted coding agent</text>
  <rect x="22" y="124" width="116" height="44" rx="6" class="svg-box-warn"/>
  <text x="80" y="143" text-anchor="middle" class="svg-title">AI Agent</text>
  <text x="80" y="158" text-anchor="middle" class="svg-sub">MCP client</text>
  <line x1="138" y1="146" x2="155" y2="146" class="svg-edge" marker-end="url(#tb-arrow)"/>
  <rect x="158" y="124" width="150" height="44" rx="6" class="svg-box-warn"/>
  <text x="233" y="143" text-anchor="middle" class="svg-title">opq mcp</text>
  <text x="233" y="158" text-anchor="middle" class="svg-mono">no get_secret_value</text>
  <line x1="308" y1="146" x2="325" y2="146" class="svg-edge" marker-end="url(#tb-arrow)"/>
  <rect x="328" y="124" width="206" height="44" rx="6" class="svg-box-warn"/>
  <text x="431" y="143" text-anchor="middle" class="svg-title">OS Sandbox (bwrap/Seatbelt)</text>
  <text x="431" y="158" text-anchor="middle" class="svg-sub">ro-FS · net off · sockets masked</text>
  <line x1="534" y1="146" x2="551" y2="146" class="svg-edge" marker-end="url(#tb-arrow)"/>
  <rect x="554" y="124" width="144" height="44" rx="6" class="svg-box-warn"/>
  <text x="626" y="143" text-anchor="middle" class="svg-title">Redacted output</text>
  <text x="626" y="158" text-anchor="middle" class="svg-sub">256 KiB cap / stream</text>
  <rect x="10" y="190" width="700" height="78" rx="8" class="svg-lane"/>
  <text x="22" y="206" class="svg-accent-tip">3. Policy Proxy — Untrusted / adversarial agent (strongest boundary)</text>
  <rect x="22" y="214" width="116" height="44" rx="6" class="svg-box-tip"/>
  <text x="80" y="233" text-anchor="middle" class="svg-title">AI Agent</text>
  <text x="80" y="248" text-anchor="middle" class="svg-sub">separate OS user</text>
  <line x1="138" y1="236" x2="155" y2="236" class="svg-edge" marker-end="url(#tb-arrow)"/>
  <rect x="158" y="214" width="150" height="44" rx="6" class="svg-box-tip"/>
  <text x="233" y="233" text-anchor="middle" class="svg-title">Policy Proxy</text>
  <text x="233" y="248" text-anchor="middle" class="svg-mono">fixed ops, {} args</text>
  <line x1="308" y1="236" x2="325" y2="236" class="svg-edge" marker-end="url(#tb-arrow)"/>
  <rect x="328" y="214" width="206" height="44" rx="6" class="svg-box-tip"/>
  <text x="431" y="233" text-anchor="middle" class="svg-title">Private opq mcp + Sandbox</text>
  <text x="431" y="248" text-anchor="middle" class="svg-sub">operator-approved binary only</text>
  <line x1="534" y1="236" x2="551" y2="236" class="svg-edge" marker-end="url(#tb-arrow)"/>
  <rect x="554" y="214" width="144" height="44" rx="6" class="svg-box-tip"/>
  <text x="626" y="233" text-anchor="middle" class="svg-title">Status only</text>
  <text x="626" y="248" text-anchor="middle" class="svg-mono">succeeded · timed_out</text>
</svg>
<figcaption>Progression of containment across <code>opq</code> deployment tiers, from local developer convenience to fixed-operation policy isolation.</figcaption>
</figure>

| Property | CLI `opq exec` | MCP Sandbox (`opq mcp`) | Policy Proxy (`examples/policy-proxy`) |
| --- | --- | --- | --- |
| **Caller picks command & args?** | Yes | Yes (audited) | No — operator-fixed per named tool (`{}` input) |
| **OS Sandbox** | Optional (`--sandbox net\|full`) | Always on (`bwrap` / Seatbelt) | Always on + separate OS principal |
| **Network default** | Host network | Blocked (`allow_network: true` opt-in) | Per-operation policy only |
| **Output returned** | Redacted stream | Redacted, 256 KiB cap per stream | Booleans only (`succeeded`, `timed_out`) |
| **Secret names visible?** | Yes (`opq list`) | Filtered names (`list_secrets`) | None (opaque operation names only) |
| **Best for** | Human developer workflows | Trusted coding agents (Claude Code, Cursor) | Untrusted or adversarial agents |

The isolation profiles below are described with their Linux (bwrap) primitives; macOS
enforces the same profiles via Seatbelt, with the two divergences (no empty `/tmp`;
allow-default `SandboxFull`) noted in [The Sandbox](../security/sandbox.md#macos-seatbelt).

## Isolation profiles

`run_with_secrets` takes an `isolation` parameter that selects the profile:

| Profile | `isolation` value | Filesystem | Network |
| --- | --- | --- | --- |
| SandboxNet (default) | `"net"` or `"readonly"` | Host root read-only (`--ro-bind / /`); sensitive sockets masked. | Blocked (`--unshare-net`). |
| SandboxNetAllowed | `"net"` / `"readonly"` + `allow_network: true` | Same as SandboxNet. | Allowed. |
| SandboxFull | `"full"` | tmpfs `/home` + `/tmp`; only `/usr`, `/etc`, `/lib*`, `/bin`, `/sbin` ro-bound. | Blocked. |

`"readonly"` is accepted as a descriptive alias for `"net"`. The default profile gives
the subprocess a complete, read-only view of the host filesystem with a set of
sensitive paths masked out:

- `/run/user`, `/tmp`, `/dev/shm`, and the audit directory (tmpfs).
- The session and system D-Bus sockets (`/run/user/$UID/bus`, `/run/dbus`).
- Every detected container-runtime socket (Docker, containerd, podman, CRI-O, k3s,
  libvirt, LXD, Incus, Avahi, BuildKit, snapd).
- Home-directory credential agents (`$HOME/.gnupg`, `$HOME/.docker/run/docker.sock`).

`isolation: "full"` goes further: the subprocess sees an empty home and a fresh
writable `/tmp`, with only the minimal system directories. Use it when the subprocess
should not see the host filesystem at all.

```jsonc
run_with_secrets({
  command: "./build.sh",
  args: [],
  env: { NPM_TOKEN: "npm_token" },
  isolation: "full"
})
```

## The network opt-in

Egress is blocked by default. To let a subprocess reach the network, the agent passes
`allow_network: true` with `"readonly"` (or `"net"`) isolation. Prefer a consumer that
reads credentials directly from the environment, or pass headers to `curl` over stdin
(`-K -`) so the secret never enters `argv`:

```jsonc
run_with_secrets({
  command: "/bin/sh",
  args: ["-c", "printf 'header = \"Authorization: Bearer %s\"\\n' \"$TOK\" | /usr/bin/curl -sS -K - https://api.example.com/me"],
  env: { TOK: "api_token" },
  isolation: "readonly",
  allow_network: true
})
```

Two points. First, the filesystem sandbox still applies: `allow_network: true` routes
to `SandboxNetAllowed`, which is `SandboxNet` without `--unshare-net`, and keeps the
filesystem masks. (An earlier design that dropped them was a confirmed exfil chain; see
[The Sandbox](../security/sandbox.md).) Second, the call is audited: every
`allow_network` call is recorded as a `network_allowed` entry carrying the
`secret_names` that were live, so the operator can correlate which secrets the call
could reach.

Network access is an exfiltration path by design. If the agent is granted
`allow_network: true` and given a secret, nothing at the opq layer stops it from
sending that secret to an external host. The control is that the agent has to ask, and
the operator sees that it asked. Gate it with a policy proxy for untrusted agents.

## opq exec --sandbox from the CLI

The CLI `exec` command can opt into the same sandboxing for human-driven runs:

```sh
opq exec --sandbox net --env TOK=api_token -- ./script.sh
```

Useful for testing what an MCP-driven run would see, or for sandboxing a risky local
command.

## The policy-proxy pattern

The opq CLI is a building block for trusted consuming programs. For an untrusted agent,
put an operator-controlled MCP server in front of the private `opq mcp` process. The
repository includes a runnable example at `examples/policy-proxy/`:

```sh
go build -o /tmp/opq-policy-proxy ./examples/policy-proxy
go test -race ./examples/policy-proxy
```

The operator installs that binary, the opq binary, approved consumer programs, and a JSON
policy outside agent-writable paths. The supplied policy approves no operations. Each
approved operation fixes an absolute command, every argument, the exact secret mapping,
timeout, network permission, and isolation profile (plus an optional `description`). The
proxy exposes one named tool per operation, each accepting only `{}`. It exposes no
arbitrary command, secret-list, or audit passthrough tool.

The proxy discards upstream output, errors, and metadata. Its only response fields are
`succeeded` and `timed_out`; it does not rely on output padding to hide secret-dependent
content or lengths. Closed input schemas and runtime validation reject caller-supplied
arguments. Per-operation deadlines and a two-call concurrency limit bound execution. Client
disconnect and shutdown signals cancel active requests before the proxy closes its private
upstream session, allowing opq to clean up consuming subprocesses.
See `examples/policy-proxy/README.md` for configuration, installation, and a local smoke
operation.

The deployment must also deny the agent direct access to opq, the keyring, and the trusted
programs' writable inputs. A wrapper cannot constrain an agent with unrestricted shell
access as the same OS principal. For network operations, review the fixed consumer's
redirect handling, ambient proxies, native configuration loading, and endpoint behavior.
The example fixes the permission to use the network; it is not a destination firewall.
Never expand credentials into shell arguments; consumers read them directly from the
environment. Approved operations still disclose coarse status and timing, which the
operator must review. The [Threat Model](../security/threat-model.md) describes the
remaining limits.
