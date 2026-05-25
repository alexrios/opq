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
	// NLSPATH: gettext/iconv locale-path file inclusion.
	"GLIBC_TUNABLES": true,
	"LOCALDOMAIN":    true,
	"HOSTALIASES":    true,
	"RES_OPTIONS":    true,
	"MALLOC_TRACE":   true,
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
	"EDITOR":               true,
	"VISUAL":               true,
	"PAGER":                true,
	"GIT_EDITOR":           true,
	"GIT_SEQUENCE_EDITOR":  true,
	"LESS":                 true,
	"LESSOPEN":             true,
	"LESSCLOSE":            true,
	"SUDO_EDITOR":          true,
	"GIT_PAGER":            true,
	"MANPAGER":             true,
	"SYSTEMD_PAGER":        true,

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
}

// Prefix bans — match is case-sensitive (env names are case-sensitive on
// POSIX); cf. validEnvName.
//
// LD_ / DYLD_: dynamic-linker preload paths (Linux/macOS).
// NSS_ / GIO_ / GCONV_: GLib / NSS escape hatches.
// ERL_: covers ERL_FLAGS, ERL_LIBS, ERL_AFLAGS, ERL_ZFLAGS, and any
//       future OTP env vars that control code loading.
// BASH_FUNC_: bash-exported-function namespace (post-Shellshock); bash
//             processes these at startup, enabling override of builtins
//             and command-not-found handlers. sudo strips these for this
//             exact reason.
// GIT_CONFIG_: covers GIT_CONFIG_KEY_N and GIT_CONFIG_VALUE_N (Git 2.31+)
//              which inject arbitrary config entries; an attacker can use
//              these to set alias.x = !/bin/sh, bypassing GIT_SSH blocks.
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
