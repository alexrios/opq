# The Sandbox

Every subprocess launched through `run_with_secrets` (and `opq exec --sandbox`) runs
inside a [bubblewrap](https://github.com/containers/bubblewrap) (`bwrap`) sandbox. The
argv builder is in `sandbox_linux.go`; the profile enum is in `sandbox.go`.

This page covers each mount and the exploit it closes. Several were confirmed attacks
against earlier versions; the hardening history is in the
[appendix](../appendix/version-history.md).

## Profiles

| Profile | `isolation` | Network | Filesystem |
| --- | --- | --- | --- |
| `SandboxNet` | `"net"` (default) | `--unshare-net` | `--ro-bind / /` + masks |
| `SandboxNetAllowed` | `"net"` + `allow_network:true` | (no `--unshare-net`) | identical to `SandboxNet` |
| `SandboxFull` | `"full"` | `--unshare-all` | tmpfs `/home` + `/tmp`; minimal ro-binds |
| `SandboxNone` | — | none | none (CLI default when `--sandbox` is not given) |

`resolveMCPSandbox(allow_network=true)` routes to `SandboxNetAllowed`, not `SandboxNone`:
lifting the network block must never also drop the filesystem masks. The shared posture
between `SandboxNet` and `SandboxNetAllowed` is factored into `sandboxNetArgvCommon` so
the two cannot drift.

## SandboxNet, mount by mount

The default profile builds roughly this argv:

```text
bwrap \
  --ro-bind / /              # whole host, READ-ONLY
  --proc /proc               # private /proc
  --unshare-pid              # private PID namespace
  --unshare-net              # no network route
  --die-with-parent          # child dies if opq dies
  --new-session              # detach from controlling TTY (no TIOCSTI injection)
  --tmpfs /tmp               # writable scratch that dies with the process
  --tmpfs /run/user          # mask the session bus + runtime dir
  --tmpfs /dev/shm
  --tmpfs <auditDir>         # mask the audit log
  ... runtime-socket masks ...
  ... home-dir socket masks ...
```

### --ro-bind / / (read-only host root)

Earlier versions used `--dev-bind / /` (read-write), which allowed a two-call exfil
chain: call 1 wrote the resolved secret to a persistent path like `/var/tmp/.leak`; call
2 ran `cat /var/tmp/.leak` with an empty env, so the per-call redactor
(`len(secrets)==0`) was a pass-through and the plaintext flowed back. Binding the root
read-only kills the persistent write; writable scratch lives in the tmpfs masks, which
die with the process.

### --tmpfs /run/user (D-Bus and keyring mask)

Without this, an AI inside the network-blocked sandbox could reach the session D-Bus
socket at `/run/user/$UID/bus` and recover keyring secrets directly, a confirmed exploit
against v1.1.1. `--unshare-net` does not help here, because AF_UNIX sockets are
filesystem-namespaced, not network-namespaced.

### --tmpfs auditDir (audit-log mask)

Without this, the AI could `cat ~/.local/state/opq/audit.log` and read every
`caller="cli"` entry the [audit filter](./audit-integrity.md) was designed to hide, plus
the `raw_exit` and `elapsed_ms` tokens the message allowlist strips. The directory is
resolved with `filepath.EvalSymlinks` (TOCTOU defense), `prepareAuditDir` ensures the
mount target exists, and `WrapCommand` fails closed if neither `HOME` nor `XDG_STATE_HOME`
is set.

### Runtime-socket masks

`--ro-bind` blocks write but not `connect(2)`. Without masking the runtime sockets, an AI
under default SandboxNet could `curl --unix-socket /var/run/docker.sock
http://.../containers/create` and, if the operator is in the `docker`/`lxd`/`incus`
group, spawn a privileged container with `-v /:/host` for arbitrary host read; or reach
Avahi over the system D-Bus (`/run/dbus`) and call
`org.freedesktop.Avahi.EntryGroup.AddService` to broadcast the secret as an mDNS TXT
record on the LAN, bypassing `--unshare-net` entirely.

`appendRuntimeSocketMasks` masks every entry in `runtimeSocketDirs` (`/run/dbus`,
`/run/containerd`, `/run/crio`, `/run/podman`, `/run/k3s`, `/run/libvirt`, `/run/lxd`,
`/run/incus`, `/run/avahi-daemon`, `/run/buildkit`) and `runtimeSocketFiles`
(`/run/docker.sock`, `/run/snapd.socket`, `/run/snapd-snap.socket`,
`/var/lib/lxd/unix.socket`, `/var/lib/incus/unix.socket`). Details that matter: entries
are `stat()`-ed at `WrapCommand` time (bwrap 0.11.0 has no `--tmpfs-try`, and `--bind-try`
only skips on a missing source); socket-file masks are emitted before directory tmpfs
masks, so a future file path nested inside a masked dir does not crash bwrap; and
socket-file entries pass an `os.ModeSocket` gate, so a regular file at the same path is
not masked.

### Home-directory credential-agent masks

`appendHomeDirSocketMasks` masks `$HOME/.gnupg` (tmpfs, covering the whole gpg-agent
socket family: `S.gpg-agent`, `.ssh`, `.extra`, `.browser`, `.scdaemon`) and
`$HOME/.docker/run/docker.sock` (`--bind /dev/null`, rootless Docker). Without these, the
same `connect(2)` reachability let an AI sign arbitrary payloads as the operator or drive
rootless Docker. When `$HOME` is unset, the home-dir masks fail open (the broader `/run`
masks still apply) rather than refusing every call.

### The /var/run symlink gotcha

On systemd distros `/var/run` is a symlink to `/run`, so masking `/run/user` also covers
`/var/run/user`. Do not add a second `--tmpfs /var/run/user`: bwrap fails with `Can't
mkdir /var/run/user` when `/var/run` resolves into a now-empty tmpfs. The same `/run`-only
policy applies to the runtime-socket list.

## SandboxFull

`--unshare-all` with explicit ro-binds only (`/usr`, `/etc`, `/lib*`, `/bin`, `/sbin`), a
writable tmpfs `/home` and `/tmp`. Because it tmpfs-masks `/home` and binds nothing else,
it does not need the explicit audit-dir or home-dir socket masks; those paths are not in
the sandbox view. Use it when the subprocess should not see the host filesystem at all.

## Residuals under default SandboxNet

Not masked: custom AF_UNIX sockets the operator placed outside the canonical `/run` tree
and outside `.gnupg` / `.docker/run/` under `$HOME` (for example
`~/.local/share/kwalletd/*.socket`), loopback channels to co-resident services, timing
side-channels, kernel-keyring inheritance, and pre-compromise of host binaries under
`/usr`. `isolation="full"` is the way out for those, not piecemeal additions to the mask
list.

## Startup probe

`opq mcp` runs a no-op `bwrap --unshare-net --unshare-pid -- true` probe at startup. If
AppArmor, seccomp, or a missing `CONFIG_USER_NS` blocks unprivileged namespace creation,
the server stops with a clear error instead of failing at the first tool call.
