# Sandbox & Hardening

Every subprocess launched through the MCP `run_with_secrets` tool runs inside the
OS-native sandbox: `bwrap` (bubblewrap) on Linux, `sandbox-exec` (Seatbelt) on macOS.
This page covers the controls an operator and an AI client can set: the isolation
profiles and the network opt-in, plus the policy-proxy pattern for high-risk
deployments. The full bwrap argv, the macOS Seatbelt profiles, and the exploit each mask
closes are in [The Sandbox](../security/sandbox.md).

The isolation profiles below are described with their Linux (bwrap) primitives; macOS
enforces the same profiles via Seatbelt, with the two divergences (no empty `/tmp`;
allow-default `SandboxFull`) noted in [The Sandbox](../security/sandbox.md#macos-seatbelt).

## Isolation profiles

`run_with_secrets` takes an `isolation` parameter that selects the profile:

| Profile | `isolation` value | Filesystem | Network |
| --- | --- | --- | --- |
| SandboxNet (default) | `"net"` | Host root read-only (`--ro-bind / /`); sensitive sockets masked. | Blocked (`--unshare-net`). |
| SandboxNetAllowed | `"net"` + `allow_network: true` | Same as SandboxNet. | Allowed. |
| SandboxFull | `"full"` | tmpfs `/home` + `/tmp`; only `/usr`, `/etc`, `/lib*`, `/bin`, `/sbin` ro-bound. | Blocked. |

The default profile gives the subprocess a complete, read-only view of the host
filesystem with a set of sensitive paths masked out:

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
`allow_network: true`:

```jsonc
run_with_secrets({
  command: "sh",
  args: ["-c", "curl -s -H \"Authorization: Bearer $TOK\" https://api.example.com/me"],
  env: { TOK: "api_token" },
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
timeout, network permission, and isolation profile. The proxy exposes one named tool per
operation, each accepting only `{}`. It exposes no arbitrary command, secret-list, or audit
passthrough tool.

```text
AI agent -> fixed-operation proxy -> private opq mcp -> approved consumer
             status only               redaction + OS sandbox
```

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
