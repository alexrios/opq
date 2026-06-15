# Threat Model

`opq` keeps one property: an AI agent can use a secret to run a command but never sees
the plaintext value. This page lists what that covers, what it does not, and the residual
risks.

## In scope

`opq` defends against:

- AI reading plaintext from stdout, error messages, or argv.
- AI piping `opq get` to capture values; refused unless stdout is a TTY (plus the
  [human gate](../reference/cli-commands.md#opq-get)).
- Subprocesses accidentally echoing secrets; output is redacted by default, including
  base64 and hex encodings.
- Shell-history exposure; no secret appears on argv.
- Process-list exposure (`ps auxe`); secrets enter the child via `exec` env, not shell
  interpolation.
- Memory swap-out of secret pages; values live in `memguard` mlocked buffers.
- Intentional network exfiltration via the MCP `run_with_secrets` tool, blocked by
  default. On Linux, every MCP subprocess runs in a network namespace (`--unshare-net`), a
  private PID namespace (`--unshare-pid`), and a private `/proc`, so `curl`, DNS-label
  smuggling, and raw TCP/UDP all fail, and concurrent calls cannot read each other's
  `/proc/<pid>/environ`. On macOS, Seatbelt (`sandbox-exec`) denies the subprocess all
  network access; it does not create PID namespaces or a private `/proc`.

### Sandbox-specific vectors

The default `SandboxNet` profile also closes these (see [The Sandbox](./sandbox.md) for
the exploit behind each):

- D-Bus and keyring access: `/run/user` and the session bus are masked, so the AI cannot
  reach the keyring over `/run/user/$UID/bus`.
- Persistent-write exfil chains: the host root is bound read-only (`--ro-bind / /`), so
  the AI cannot write the secret in one call and `cat` it back in a later empty-secret
  call.
- Container-runtime API access: every Docker/containerd/podman/CRI-O/k3s/libvirt/LXD/
  Incus/Avahi/BuildKit/snapd socket is masked, so the AI cannot
  `curl --unix-socket /var/run/docker.sock` to spawn a privileged container.
- System D-Bus and Avahi mDNS: `/run/dbus` is masked, so the AI cannot broadcast the
  secret as an mDNS TXT record on the LAN.
- Home-directory credential agents: `$HOME/.gnupg` and `$HOME/.docker/run/docker.sock`
  are masked, so the AI cannot sign as the operator or drive rootless Docker.
- `opq exec --no-redact` re-entry: gated like `get --plaintext`, so the AI cannot call
  `run_with_secrets({command:"opq", args:["exec","--no-redact",...]})` to bypass
  redaction.
- Audit-log scraping from inside the sandbox: the audit directory is masked.
- `LD_PRELOAD` / `PATH` / `BASH_ENV` injection: refused via the
  [deny-list](../reference/env-deny-list.md).
- Audit-log tampering and torn reads: appends and tails are flock-serialized across
  processes.

## Out of scope (v1)

`opq` does not defend against:

- Root or kernel attacker. Compromise of the logged-in keyring session is total
  compromise.
- Side channels in the legitimate consuming subprocess.
- A malicious subprocess exfiltrating via a non-network path the sandbox does not cover
  (loopback service, kernel keyring, custom Unix socket).
- A tamper-evident audit log. The log is `0600` but not cryptographically signed.
- Exotic encoding evasion of the redactor. Base64 and hex are covered; URL
  percent-encoding, JSON-string escaping, rot13/XOR/base32, and arbitrary ciphers are
  not.
- Terminal-escape exfiltration via the rendering client. `opq` redacts secret values but
  does not strip OSC 52 / DCS escape sequences; clients should sanitize tool output
  before rendering.
- Loopback channels (`curl http://127.0.0.1:6379`, `psql -h 127.0.0.1`). The network
  sandbox blocks egress at the namespace boundary but not loopback to co-resident
  services. Treat loopback as open egress unless you have audited every listening port.
- Process-level resource exhaustion. Per-call limits bound a single call's blast radius,
  but a tight loop can still consume CPU, keyring, or network; rate-limiting belongs in a
  policy proxy.
- `allow_network=true` exfil. When the AI opts in (audited as `network_allowed`), there
  is no opq-layer defense against it shipping the secret to an external host. That is the
  contract of the flag.

## Known residual side channels

Reduced, not eliminated:

- Output-volume oracle. The AI controls subprocess output length, which leaks bits per
  call. Bucket-quantization collapses this from ~17 bits to ~2.3 bits per call (~4 calls
  per byte instead of ~1). Closing it fully requires not returning output to the AI, or a
  policy proxy.
- Custom Unix sockets the operator placed outside the masked paths
  (`~/.local/share/kwalletd/*.socket`, any AF_UNIX endpoint under `$HOME`). Use
  `isolation="full"` for a complete filesystem view.

## High-risk deployments

For environments fronting an actively adversarial model, front `opq mcp` with a small
policy-enforcing wrapper that allowlists `(command, args pattern, env var set)` tuples per
secret and denies everything else. The opq CLI ships as a low-trust building block by
design. See
[Sandbox & Hardening](../tutorials/sandbox-and-hardening.md#the-policy-proxy-pattern).
