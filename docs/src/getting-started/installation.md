# Installation

## Install with `go install`

```sh
go install github.com/alexrios/opq@latest
```

The installed binary is named `opq` (Go names the binary after the last element of the
module path). Put your `$GOBIN` (or `$GOPATH/bin`) on `$PATH`.

## Build from source

```sh
git clone https://github.com/alexrios/opq
cd opq
go build -o opq .          # or: mise run build  → dist/opq
```

## Requirements

On a standard desktop Linux session the requirements below are already met, and `opq`
works out of the box. They matter mainly for headless servers, containers, WSL, and
locked-down hosts.

| Requirement | Why | Notes |
| --- | --- | --- |
| Linux | v1 ships only the Linux Secret Service backend. | macOS Keychain is planned for v1.2. |
| An unlocked Secret Service session | Where secrets are stored. | gnome-keyring, KWallet, or KeePassXC (anything that speaks libsecret over D-Bus). |
| bubblewrap (`bwrap`) ≥ 0.5.0 | The MCP subprocess sandbox and `opq exec --sandbox`. | `apt install bubblewrap` / `dnf install bubblewrap` / `pacman -S bubblewrap`. `opq mcp` will not start without it. |
| Unprivileged user namespaces | bubblewrap needs them to build the sandbox. | Enabled by default on most distros. |

## Troubleshooting: the bubblewrap startup probe

Most desktop users never see this section. It applies only when `opq mcp` refuses to
start on a hardened or headless host.

`opq mcp` runs a no-op namespace probe at startup (`bwrap --unshare-net --unshare-pid
-- true`). If AppArmor (Ubuntu 23.10+ ships a profile on `bwrap`), seccomp, or a kernel
without `CONFIG_USER_NS` blocks unprivileged namespace creation, the server stops with
a clear error instead of failing at the first tool call.

If the probe fails on Ubuntu 23.10+, you likely need to allow `bwrap` in AppArmor or
enable unprivileged user namespaces:

```sh
sysctl kernel.unprivileged_userns_clone 2>/dev/null
cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns 2>/dev/null
```

## Verifying the install

```sh
opq --version
opq list           # succeeds (empty) on a fresh install
which opq          # confirm the right binary is on PATH
```

If `opq list` reports a D-Bus or Secret Service error, your keyring session is not
unlocked. On a desktop, log into a graphical session so the keyring unlocks
automatically. On a headless host, container, or WSL there is usually no session keyring
yet: start one with `gnome-keyring-daemon --unlock` (or wrap the command in
`dbus-run-session -- opq ...`), or install KeePassXC and enable its Secret Service
integration. `opq` needs an unlocked libsecret provider and will not fall back to a
plaintext file.

Next: [Quick Start](./quick-start.md).
