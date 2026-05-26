package main

import (
	"regexp"
	"strings"
)

// secretNameRe constrains the shape of a secret name accepted by either
// the CLI (--env VAR=secret_name) or the MCP run_with_secrets tool's
// Env map. The character class matches the shape of identifiers used
// in keyring labels and audit logs:
//
//   - alphanumeric, underscore, dot, dash
//   - 1..128 chars
//
// Names outside this shape are rejected at the call site; the keyring
// library itself may accept wider character classes, but allowing
// caller-controlled bytes to flow into the operator-visible audit log
// (even JSON-escaped) is an avoidable readability and parser-hazard
// risk. The cap also bounds the audit-log line size.
var secretNameRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)

// validSecretName reports whether name is on the accepted shape for a
// secret-name argument. Returns false for the empty string.
func validSecretName(name string) bool {
	return secretNameRe.MatchString(name)
}

// Variables on this list change how the dynamic linker, libc, or common
// interpreters locate code, libraries, or config. Allowing an AI caller
// of run_with_secrets (or the operator via --env on the CLI) to set any
// of these to a secret value would amount to RCE — PATH hijacking,
// LD_PRELOAD library injection, BASH_ENV startup-file sourcing, etc.
//
// Scope: this deny-list applies only to *injected* env vars (the --env
// flag on `opq exec` and the Env map on the MCP run_with_secrets tool).
// It deliberately does NOT touch the parent environment of opq itself,
// which is the operator's own shell and out of opaque's threat model
// (see filterParentEnv in cmd_exec.go for the parent-env policy).
var blockedEnv = map[string]bool{

	// dynamic linker / libc (Linux) — see also blockedPrefixes (LD_*, DYLD_*).
	// GLIBC_TUNABLES: CVE-2023-4911 ("Looney Tunables"), read by ld.so before
	// privilege drops. LOCALDOMAIN/HOSTALIASES/RES_OPTIONS: glibc resolver
	// file/option redirects. MALLOC_TRACE: glibc writes to the named file.
	// MALLOC_CONF: jemalloc analogue to GLIBC_TUNABLES / MALLOC_TRACE; allows
	// prof_prefix and lg_prof_sample (writes profile dumps to attacker-named
	// paths) and on some builds custom extent_hooks plugin loading.
	// NLSPATH: gettext/iconv locale-path file inclusion.
	"GLIBC_TUNABLES": true,
	"LOCALDOMAIN":    true,
	"HOSTALIASES":    true,
	"RES_OPTIONS":    true,
	"MALLOC_TRACE":   true,
	"MALLOC_CONF":    true,
	"NLSPATH":        true,

	// shell startup — sourced/executed before the shell processes any input.
	"PATH":           true,
	"IFS":            true,
	"HOME":           true,
	"SHELL":          true,
	"TERM":           true,
	"TMPDIR":         true,
	"TZ":             true,
	"BASH_ENV":       true,
	"ENV":            true,
	"PROMPT_COMMAND": true,

	// JVM ecosystem — all honored at JVM startup or by build tools before any
	// bytecode runs. MAVEN_OPTS / GRADLE_OPTS / SBT_OPTS accept JVM flags
	// including -javaagent: and -Djava.security.manager= paths.
	"JAVA_TOOL_OPTIONS": true,
	"_JAVA_OPTIONS":     true,
	"JDK_JAVA_OPTIONS":  true,
	"JAVA_HOME":         true,
	"CLASSPATH":         true,
	"MAVEN_OPTS":        true,
	"GRADLE_OPTS":       true,
	"SBT_OPTS":          true,

	// Python — PYTHONPATH / PYTHONHOME change the module search path;
	// PYTHONSTARTUP is a script executed at interpreter startup.
	"PYTHONPATH":    true,
	"PYTHONSTARTUP": true,
	"PYTHONHOME":    true,

	// Node.js / Bun — NODE_OPTIONS can inject --require / --import flags that
	// load arbitrary code. NODE_PATH extends module resolution. BUN_OPTIONS is
	// Bun's equivalent: prepended to every Bun invocation (docs: "makes
	// `bun run dev` behave like `bun --hot run dev`"); supports --preload.
	"NODE_OPTIONS": true,
	"NODE_PATH":    true,
	"BUN_OPTIONS":  true,

	// Ruby — RUBYOPT passes flags (e.g. -r) that require arbitrary files at
	// startup. RUBYLIB / GEM_HOME / GEM_PATH / BUNDLE_GEMFILE redirect code load.
	"RUBYOPT":        true,
	"RUBYLIB":        true,
	"GEM_HOME":       true,
	"GEM_PATH":       true,
	"BUNDLE_GEMFILE": true,

	// Perl — PERL5LIB / PERLLIB extend @INC; PERL5OPT passes flags including
	// -M (load module) and -I (add to @INC) at startup.
	"PERL5LIB": true,
	"PERL5OPT": true,
	"PERLLIB":  true,

	// Go — GOPROXY controls where `go` fetches modules (attacker-controlled
	// proxy can serve malicious code). GOFLAGS accepts -toolexec=program
	// which replaces every toolchain binary (compile, link, asm, etc.)
	// with an arbitrary executable.
	"GOPROXY": true,
	"GOFLAGS": true,

	// Rust / Cargo — RUSTC_WRAPPER and RUSTC_WORKSPACE_WRAPPER are executed
	// by Cargo directly in place of the compiler for every build invocation
	// (flagged by ANSSI secure-Rust guidelines as must-not-override). RUSTC
	// replaces the compiler binary; RUSTDOC replaces the doc tool.
	"RUSTC_WRAPPER":           true,
	"RUSTC_WORKSPACE_WRAPPER": true,
	"RUSTC":                   true,
	"RUSTDOC":                 true,

	// Lua — LUA_PATH / LUA_CPATH change the package search path for require().
	"LUA_PATH":  true,
	"LUA_CPATH": true,

	// R — R_LIBS / R_LIBS_USER extend the library search path; library() /
	// require() search these before system paths.
	"R_LIBS":      true,
	"R_LIBS_USER": true,

	// Julia — explicit names only (no prefix ban to avoid collateral damage
	// on user-invented vars like JULIA_TOKEN or JULIA_API_KEY).
	// JULIA_LOAD_PATH: module search. JULIA_DEPOT_PATH: packages + artifacts.
	// JULIA_PROJECT: activates a specific project/environment.
	// JULIA_PKG_DEVDIR / JULIA_PKG_SERVER: package dev dir and registry.
	"JULIA_LOAD_PATH":  true,
	"JULIA_DEPOT_PATH": true,
	"JULIA_PROJECT":    true,
	"JULIA_PKG_DEVDIR": true,
	"JULIA_PKG_SERVER": true,

	// Haskell / GHC — GHC_PACKAGE_PATH overrides the package database search
	// path, allowing substitution of arbitrary compiled Haskell code.
	"GHC_PACKAGE_PATH": true,

	// OCaml — OCAMLPATH extends the findlib/Dynlink search path;
	// CAML_LD_LIBRARY_PATH is the OCaml-specific ld path for .so stubs.
	"OCAMLPATH":            true,
	"CAML_LD_LIBRARY_PATH": true,

	// Erlang / OTP — see also blockedPrefixes (ERL_*).
	// ERL_FLAGS / ERL_AFLAGS / ERL_ZFLAGS are prepended/appended to every
	// erl invocation (can pass -pa / -pz to add code paths). ERL_LIBS adds
	// directories to the Erlang code-loading path.
	"ERL_FLAGS":  true,
	"ERL_LIBS":   true,
	"ERL_AFLAGS": true,
	"ERL_ZFLAGS": true,

	// Tcl — TCLLIBPATH is a list of directories prepended to auto_path;
	// package require searches these before standard locations.
	"TCLLIBPATH": true,

	// Guile (GNU Scheme) — GUILE_LOAD_PATH prepends directories to %load-path;
	// any (load ...) or (use-modules ...) will search here first.
	"GUILE_LOAD_PATH": true,

	// Nix — NIX_PATH is used by <nixpkgs> angle-bracket lookups and
	// nix-build / nix-shell to resolve channels and paths.
	"NIX_PATH": true,

	// Scheme (Chez) — CHEZSCHEMELIBDIRS extends the library search path for
	// (library ...) forms (the canonical Chez Scheme variable; also honored
	// by SLIB as SCHEME_LIBRARY_PATH).
	"CHEZSCHEMELIBDIRS":   true,
	"SCHEME_LIBRARY_PATH": true,

	// Clojure — CLOJURE_LOAD_PATH adds directories to the Clojure load path
	// searched by (load ...) and (require ...).
	"CLOJURE_LOAD_PATH": true,

	// Elixir / Mix — MIX_ARCHIVES points to a directory of compiled .ez
	// archives that Mix installs globally; overriding it redirects archive loads.
	"MIX_ARCHIVES": true,

	// editors / pagers — many tools (git commit, crontab -e, visudo, etc.) exec
	// $EDITOR / $VISUAL unconditionally via system(). Setting EDITOR to a shell
	// command string turns any such subprocess invocation into RCE. VISUAL is
	// functionally identical. SUDO_EDITOR: honored by sudoedit, equivalent risk.
	// GIT_EDITOR / GIT_SEQUENCE_EDITOR: git checks these before $EDITOR.
	// PAGER: git log, man, journalctl, and many others exec $PAGER. LESS: the
	// options string can enable shell-command execution inside less (! prefix).
	// LESSOPEN / LESSCLOSE: less executes these as shell commands to pre/post-
	// process files (CVE-2024-32487 exploited LESSOPEN for command injection).
	// GIT_PAGER / MANPAGER / SYSTEMD_PAGER: tool-specific $PAGER overrides.
	"EDITOR":              true,
	"VISUAL":              true,
	"PAGER":               true,
	"GIT_EDITOR":          true,
	"GIT_SEQUENCE_EDITOR": true,
	"LESS":                true,
	"LESSOPEN":            true,
	"LESSCLOSE":           true,
	"SUDO_EDITOR":         true,
	"GIT_PAGER":           true,
	"MANPAGER":            true,
	"SYSTEMD_PAGER":       true,

	// askpass programs — ssh / git / sudo execute these directly when they need
	// a passphrase and have no TTY. The value is the executable path, so any
	// injected secret that contains a path becomes an arbitrary exec.
	"SSH_ASKPASS":  true,
	"GIT_ASKPASS":  true,
	"SUDO_ASKPASS": true,

	// VCS / SSH — GIT_SSH / GIT_SSH_COMMAND replace the SSH binary git uses,
	// allowing arbitrary command execution on any git network operation.
	// GIT_EXEC_PATH replaces git's internal subcommand directory (e.g.
	// git-upload-pack). GIT_CONFIG_COUNT / GIT_CONFIG_KEY_* / GIT_CONFIG_VALUE_*
	// inject arbitrary git config entries (Git 2.31+); see also GIT_CONFIG_
	// prefix ban which covers unbounded KEY_N / VALUE_N suffixes.
	"GIT_SSH":          true,
	"GIT_SSH_COMMAND":  true,
	"GIT_EXEC_PATH":    true,
	"GIT_CONFIG_COUNT": true,

	// OpenSSL — OPENSSL_CONF points to a config file that can load arbitrary
	// engine .so modules, a well-known RCE vector in OpenSSL deployments.
	"OPENSSL_CONF": true,

	// downloader configs — CURL_HOME points curl at a directory whose .curlrc
	// is loaded at startup; .curlrc supports -K (include another config file)
	// and per-URL output paths, giving an attacker write-anywhere + read-from-
	// anywhere primitives during any curl invocation. WGETRC is the explicit
	// config-file path for wget; wget config supports post_file, exec, and
	// other shell-out directives. Both fall in the "config-file pointer"
	// class equivalent to OPENSSL_CONF.
	"CURL_HOME": true,
	"WGETRC":    true,

	// terminfo — TERMINFO points to a single compiled terminfo database file;
	// TERMINFO_DIRS is a colon-separated search path. ncurses parses these on
	// startup for every curses-using program (vim, less, top, mc, ...); the
	// terminfo parser has a long history of buffer-overflow CVEs and file-
	// inclusion bugs (e.g. CVE-2023-50495, CVE-2023-29491).
	"TERMINFO":      true,
	"TERMINFO_DIRS": true,

	// Kerberos — KRB5_CONFIG points to a krb5.conf that can specify plugin
	// modules (arbitrary .so loaded by libkrb5). KRB5CCNAME is the credential
	// cache path (FILE:/path or DIR:/path); pointing at an attacker-controlled
	// file lets the AI swap in forged tickets. KRB5_KTNAME is the keytab path
	// used for service authentication.
	"KRB5_CONFIG": true,
	"KRB5CCNAME":  true,
	"KRB5_KTNAME": true,

	// readline — INPUTRC is the readline init file path; readline parses it
	// at first init, supports do-uppercase-version-style bindings and shell
	// command sequences (CVE family in older readline). Affects bash
	// interactive line editor, gdb, python -i, psql, mysql, etc.
	"INPUTRC": true,

	// SSH agent socket — under SandboxNetAllowed (allow_network=true), an AI
	// that controls SSH_AUTH_SOCK can route ssh-add -l / ssh -A through the
	// operator's loaded keys and authenticate to remote hosts as the operator.
	// The private key bytes never leave the agent, but the AI gets to USE them,
	// which is sufficient to e.g. push to the operator's git remotes.
	"SSH_AUTH_SOCK": true,

	// container runtimes — DOCKER_HOST redirects docker CLI to an arbitrary
	// daemon socket/URL (defense-in-depth even after the v1.1.3 mask of host
	// container sockets, since the operator may legitimately mount a writable
	// docker bind under isolation="full"). DOCKER_TLS_VERIFY / DOCKER_CERT_PATH
	// together let the AI redirect to an attacker daemon with attacker-supplied
	// certs (Kimi joint-review). DOCKER_CONFIG redirects the CLI's plugin
	// directory (~/.docker), allowing alias/plugin RCE. BUILDKIT_HOST is the
	// BuildKit equivalent. CONTAINER_HOST is the generic podman/docker-variant
	// override. Exact-match (no prefix ban) preserves user-defined DOCKER_USER
	// / DOCKER_TOKEN style variables.
	"DOCKER_HOST":       true,
	"DOCKER_TLS_VERIFY": true,
	"DOCKER_CERT_PATH":  true,
	"DOCKER_CONFIG":     true,
	"BUILDKIT_HOST":     true,
	"CONTAINER_HOST":    true,

	// PHP — PHPRC is the path to a directory containing php.ini, which can
	// load arbitrary extensions via `extension=evil.so`. PHP_INI_SCAN_DIR is
	// an additional ini-scan directory honored at PHP startup. Both fit the
	// config-file pointer class (Kimi joint-review).
	"PHPRC":            true,
	"PHP_INI_SCAN_DIR": true,

	// Mercurial — HGRCPATH is a search-path list of hgrc files; hg config
	// supports [hooks] entries whose values are arbitrary shell commands run
	// on commit / push / etc. Equivalent class to GIT_CONFIG_* (Kimi).
	"HGRCPATH": true,

	// git diff helper — GIT_EXTERNAL_DIFF is executed as a subprocess by git
	// on every diff invocation (git diff, git log -p, git show); attacker
	// value becomes RCE on next git diff. Companion to GIT_SSH / GIT_PAGER
	// (Kimi).
	"GIT_EXTERNAL_DIFF": true,

	// CMake — CMAKE_TOOLCHAIN_FILE is loaded by every cmake invocation and
	// can contain arbitrary cmake commands including execute_process(), so
	// running `cmake .` after the AI sets this triggers the attacker payload
	// (Kimi).
	"CMAKE_TOOLCHAIN_FILE": true,

	// generic compiler replacement — make and most build systems honor $CC
	// and $CXX as the C / C++ compiler binary; setting either to an arbitrary
	// path is the same class as RUSTC_WRAPPER and GOFLAGS=-toolexec= (Kimi).
	"CC":  true,
	"CXX": true,

	// remote-shell command — rsync executes $RSYNC_RSH as the transport
	// command; borg executes $BORG_RSH. Both are direct equivalents of
	// GIT_SSH_COMMAND (Kimi).
	"RSYNC_RSH": true,
	"BORG_RSH":  true,

	// GTK modules — GTK_MODULES is a colon-separated list of shared-library
	// names; every GTK app dlopen()s them at startup. Functionally LD_PRELOAD
	// for any GTK program (Kimi).
	"GTK_MODULES": true,

	// Qt plugins — QT_PLUGIN_PATH is searched by Qt for plugin .so modules
	// loaded at QCoreApplication / QGuiApplication init; same class as
	// GTK_MODULES (Kimi gate-2).
	"QT_PLUGIN_PATH": true,

	// vim startup — VIMINIT is executed as Ex commands when vim starts
	// (commonly `!sh` and other shell-out forms are valid Ex commands);
	// vim is regularly invoked by git commit, crontab -e, etc. so this
	// is in the editors family (Kimi gate-2).
	"VIMINIT": true,

	// ripgrep preprocessor — RIPGREP_CONFIG_PATH is a config file whose
	// entries can include --pre PATH, which ripgrep then exec()s as a
	// preprocessor for every matched file (Kimi gate-2).
	"RIPGREP_CONFIG_PATH": true,

	// GnuPG home — GNUPGHOME is the gpg config directory containing
	// gpg.conf / gpg-agent.conf; both can specify helper executables
	// (e.g. pinentry-program). Sets up arbitrary exec on next gpg call
	// (Kimi gate-2).
	"GNUPGHOME": true,

	// git hooks / dir overrides — GIT_TEMPLATE_DIR is copied (including
	// executable hooks/) into every new repo created by git init or
	// git clone. GIT_DIR overrides the .git directory path so that the
	// AI can point git at a directory pre-seeded with malicious hooks
	// that fire on the next commit / push / rebase (Kimi gate-2).
	"GIT_TEMPLATE_DIR": true,
	"GIT_DIR":          true,

	// Gradle user home — GRADLE_USER_HOME redirects Gradle's init-script
	// directory; any *.gradle file under init.d/ runs Groovy code on
	// every Gradle invocation. Equivalent class to MAVEN_OPTS / GRADLE_OPTS
	// but via an init-script directory rather than JVM flags (Kimi gate-2).
	"GRADLE_USER_HOME": true,

	// Note: XDG_CONFIG_HOME and XDG_CONFIG_DIRS were considered but rejected
	// for the deny-list: they would redirect every XDG-compliant app's
	// config search, breaking legitimate workflows where the operator pins
	// a per-project config dir. The high-signal config pointers in this
	// category (CURL_HOME, WGETRC, KRB5_CONFIG, INPUTRC, PHPRC, HGRCPATH,
	// OPENSSL_CONF, CMAKE_TOOLCHAIN_FILE) are listed explicitly instead.
}

// Prefix bans — match is case-sensitive (env names are case-sensitive on
// POSIX); cf. validEnvName.
//
// LD_ / DYLD_: dynamic-linker preload paths (Linux/macOS).
// NSS_ / GIO_ / GCONV_: GLib / NSS escape hatches.
// ERL_: covers ERL_FLAGS, ERL_LIBS, ERL_AFLAGS, ERL_ZFLAGS, and any
//
//	future OTP env vars that control code loading.
//
// BASH_FUNC_: bash-exported-function namespace (post-Shellshock); bash
//
//	processes these at startup, enabling override of builtins
//	and command-not-found handlers. sudo strips these for this
//	exact reason.
//
// GIT_CONFIG_: covers GIT_CONFIG_KEY_N and GIT_CONFIG_VALUE_N (Git 2.31+)
//
//	which inject arbitrary config entries; an attacker can use
//	these to set alias.x = !/bin/sh, bypassing GIT_SSH blocks.
var blockedPrefixes = []string{
	"LD_",
	"DYLD_",
	"NSS_",
	"GIO_",
	"GCONV_",
	"ERL_",
	"BASH_FUNC_",
	"GIT_CONFIG_",
}

// isBlockedEnvName reports whether an env var name is on the
// injected-env deny-list. Returns true for any name in blockedEnv or
// starting with any prefix in blockedPrefixes.
func isBlockedEnvName(s string) bool {
	if blockedEnv[s] {
		return true
	}
	for _, p := range blockedPrefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}
