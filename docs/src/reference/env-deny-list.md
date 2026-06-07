# Environment Deny-List

Injecting a secret into an environment variable is what `opq exec` and
`run_with_secrets` do, but some variable names are read by the dynamic linker, the
shell, or an interpreter at startup to locate code. Injecting into one of those would
turn secret-injection into arbitrary code execution.

`opq` refuses to inject into any name on a deny-list. The same check
(`isBlockedEnvName`) runs for the CLI `--env` path and the MCP `run_with_secrets` path.
A blocked name surfaces as `invalid_input` and is recorded as `denied` / `env_blocked`
in the audit log. Closing a new loader-honored escape hatch means adding a deny-list
entry, never bypassing the check at a call site.

## Blocked prefix families

Any name starting with one of these is blocked:

| Prefix | Honored by |
| --- | --- |
| `LD_*` | glibc dynamic linker (`LD_PRELOAD`, `LD_LIBRARY_PATH`, ...) |
| `DYLD_*` | macOS dynamic linker |
| `NSS_*` | Name Service Switch module loading |
| `GIO_*` | GLib I/O module loading |
| `GCONV_*` | glibc charset-conversion module loading |
| `ERL_*` | Erlang runtime startup |
| `BASH_FUNC_*` | Exported bash function definitions (Shellshock-class) |
| `GIT_CONFIG_*` | Git config injection (covers `GIT_CONFIG_GLOBAL`/`_SYSTEM`/`_COUNT`) |

## Blocked exact names (selected)

| Category | Names |
| --- | --- |
| Shell / interpreter startup | `BASH_ENV`, `ENV`, `VIMINIT`, `INPUTRC` |
| Editors and pagers | `EDITOR`, `VISUAL`, `GIT_EDITOR`, `PAGER`, `MANPAGER`, `LESSOPEN` |
| Askpass programs | `SSH_ASKPASS`, `GIT_ASKPASS` |
| JVM build tooling | `MAVEN_OPTS`, `GRADLE_OPTS`, `SBT_OPTS`, `GRADLE_USER_HOME` |
| Go / Rust / Bun | `GOPROXY`, `GOFLAGS`, `RUSTC_WRAPPER`, `RUSTC`, `BUN_OPTIONS` |
| OpenSSL / crypto | `OPENSSL_CONF` |
| Git internals | `GIT_EXEC_PATH`, `GIT_TEMPLATE_DIR`, `GIT_DIR`, `GIT_EXTERNAL_DIFF` |
| Downloaders | `CURL_HOME`, `WGETRC` |
| Terminfo / readline | `TERMINFO`, `TERMINFO_DIRS` |
| Kerberos | `KRB5_CONFIG`, `KRB5CCNAME`, `KRB5_KTNAME` |
| Container runtimes | `DOCKER_HOST`, `DOCKER_CONFIG`, `DOCKER_TLS_VERIFY`, `DOCKER_CERT_PATH`, `BUILDKIT_HOST`, `CONTAINER_HOST` |
| Credential / agent sockets | `SSH_AUTH_SOCK`, `GNUPGHOME` |
| Compilers and build | `CC`, `CXX`, `CMAKE_TOOLCHAIN_FILE` |
| Remote shells | `RSYNC_RSH`, `BORG_RSH` |
| GUI module loaders | `GTK_MODULES`, `QT_PLUGIN_PATH` |
| Other loaders | `PHPRC`, `PHP_INI_SCAN_DIR`, `HGRCPATH`, `RIPGREP_CONFIG_PATH`, `MALLOC_CONF`, plus Lua / R / Julia / Haskell / OCaml / Tcl / Guile / Nix / Scheme / Clojure / Elixir load-path variables |

`PATH` and `TERM` are blocked too: `PATH` is the classic command-resolution hijack, and
`TERM` is denied so an AI cannot influence terminal-escape handling.

The authoritative list is `env_policy.go`. Some near-misses were excluded as too broad;
for example `XDG_CONFIG_HOME` / `XDG_CONFIG_DIRS` would redirect every XDG-compliant
app's config search, so the high-signal config-pointer leaves in that subtree are listed
explicitly instead.
