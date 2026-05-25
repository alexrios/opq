package main

import (
	"strings"
	"testing"
)

// TestValidSecretName_Table locks J-14: secret-name shape gate. Names
// outside [A-Za-z0-9_.-]{1,128} are rejected at the call site (CLI and
// MCP) before any caller-controlled bytes reach the operator-visible
// audit log.
func TestValidSecretName_Table(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		// accepted shapes
		{"typical_underscore", "openai_api_key", true},
		{"single_char", "a", true},
		{"all_classes", "Key.v2-9_x", true},
		{"dot_only_valid_inside", "key.v2", true},
		{"dash_only_valid_inside", "key-v2", true},
		{"digits", "123", true},
		{"max_len_128", strings.Repeat("a", 128), true},
		// rejected
		{"empty", "", false},
		{"len_129", strings.Repeat("a", 129), false},
		{"len_512", strings.Repeat("a", 512), false},
		{"space_inside", "key with space", false},
		{"slash", "key/slash", false},
		{"dollar", "key$dollar", false},
		{"equals", "key=value", false},
		{"newline", "key\nbad", false},
		{"nul", "key\x00bad", false},
		{"non_ascii", "kéy", false},
		{"colon", "key:v2", false},
		{"backslash", "key\\v2", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := validSecretName(c.in); got != c.want {
				t.Fatalf("validSecretName(%q) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

func TestIsBlockedEnvName_ExactMap(t *testing.T) {
	blocked := []string{
		// dynamic linker / libc
		"GLIBC_TUNABLES", "LOCALDOMAIN", "HOSTALIASES", "RES_OPTIONS",
		"MALLOC_TRACE", "NLSPATH",
		// shell startup
		"PATH", "IFS", "HOME", "SHELL", "TERM", "TMPDIR", "TZ",
		"BASH_ENV", "ENV", "PROMPT_COMMAND",
		// JVM ecosystem
		"JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS",
		"JAVA_HOME", "CLASSPATH",
		"MAVEN_OPTS", "GRADLE_OPTS", "SBT_OPTS",
		// Python
		"PYTHONPATH", "PYTHONSTARTUP", "PYTHONHOME",
		// Node.js / Bun
		"NODE_OPTIONS", "NODE_PATH", "BUN_OPTIONS",
		// Ruby
		"RUBYOPT", "RUBYLIB", "GEM_HOME", "GEM_PATH", "BUNDLE_GEMFILE",
		// Perl
		"PERL5LIB", "PERL5OPT", "PERLLIB",
		// Go
		"GOPROXY", "GOFLAGS",
		// Rust / Cargo
		"RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "RUSTC", "RUSTDOC",
		// Lua
		"LUA_PATH", "LUA_CPATH",
		// R
		"R_LIBS", "R_LIBS_USER",
		// Julia (explicit names only; no prefix ban to preserve JULIA_TOKEN etc.)
		"JULIA_LOAD_PATH", "JULIA_DEPOT_PATH", "JULIA_PROJECT",
		"JULIA_PKG_DEVDIR", "JULIA_PKG_SERVER",
		// Haskell / GHC
		"GHC_PACKAGE_PATH",
		// OCaml
		"OCAMLPATH", "CAML_LD_LIBRARY_PATH",
		// Erlang / OTP (also covered by ERL_ prefix)
		"ERL_FLAGS", "ERL_LIBS", "ERL_AFLAGS", "ERL_ZFLAGS",
		// Tcl
		"TCLLIBPATH",
		// Guile
		"GUILE_LOAD_PATH",
		// Nix
		"NIX_PATH",
		// Scheme (Chez / SLIB)
		"CHEZSCHEMELIBDIRS", "SCHEME_LIBRARY_PATH",
		// Clojure
		"CLOJURE_LOAD_PATH",
		// Elixir / Mix
		"MIX_ARCHIVES",
		// editors / pagers
		"EDITOR", "VISUAL", "PAGER",
		"GIT_EDITOR", "GIT_SEQUENCE_EDITOR", "GIT_PAGER",
		"MANPAGER", "SYSTEMD_PAGER",
		"LESS", "LESSOPEN", "LESSCLOSE",
		"SUDO_EDITOR",
		// askpass programs
		"SSH_ASKPASS", "GIT_ASKPASS", "SUDO_ASKPASS",
		// VCS / SSH / OpenSSL
		"GIT_SSH", "GIT_SSH_COMMAND", "GIT_EXEC_PATH", "GIT_CONFIG_COUNT",
		"OPENSSL_CONF",
	}
	for _, name := range blocked {
		t.Run(name, func(t *testing.T) {
			if !isBlockedEnvName(name) {
				t.Fatalf("isBlockedEnvName(%q) = false, want true", name)
			}
		})
	}
}

func TestIsBlockedEnvName_Prefixes(t *testing.T) {
	prefixed := []string{
		// dynamic linker
		"LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "LD_PROFILE",
		"DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH",
		// GLib / NSS
		"NSS_HOSTS", "GIO_USE_VFS", "GCONV_PATH",
		// BASH_FUNC_: bash-exported-function namespace (post-Shellshock);
		// bash processes these at startup, enabling override of builtins.
		"BASH_FUNC_command_not_found_handle%%",
		"BASH_FUNC_ls%%",
		// ERL_ prefix: covers ERL_FLAGS, ERL_LIBS, ERL_AFLAGS, ERL_ZFLAGS,
		// plus any future OTP env vars.
		"ERL_NEW_FUTURE_VAR",
		// GIT_CONFIG_ prefix: covers GIT_CONFIG_KEY_N / GIT_CONFIG_VALUE_N
		// (Git 2.31+) which inject arbitrary git config entries.
		"GIT_CONFIG_KEY_0",
		"GIT_CONFIG_VALUE_0",
		"GIT_CONFIG_KEY_99",
	}
	for _, name := range prefixed {
		t.Run(name, func(t *testing.T) {
			if !isBlockedEnvName(name) {
				t.Fatalf("isBlockedEnvName(%q) = false, want true", name)
			}
		})
	}
}

func TestIsBlockedEnvName_JuliaExplicitNames(t *testing.T) {
	// Julia uses explicit name entries only (no JULIA_ prefix ban) to avoid
	// blocking legitimate user vars like JULIA_TOKEN or JULIA_API_KEY.
	// Only the known code-load vars are blocked.
	blocked := []string{
		"JULIA_LOAD_PATH",
		"JULIA_DEPOT_PATH",
		"JULIA_PROJECT",
		"JULIA_PKG_DEVDIR",
		"JULIA_PKG_SERVER",
	}
	for _, name := range blocked {
		t.Run(name, func(t *testing.T) {
			if !isBlockedEnvName(name) {
				t.Fatalf("isBlockedEnvName(%q) = false, want true", name)
			}
		})
	}

	// JULIA_TOKEN and similar user-defined vars must NOT be blocked.
	notBlocked := []string{"JULIA_TOKEN", "JULIA_API_KEY", "JULIA_USER"}
	for _, name := range notBlocked {
		t.Run("not_blocked_"+name, func(t *testing.T) {
			if isBlockedEnvName(name) {
				t.Fatalf("isBlockedEnvName(%q) = true, want false (JULIA_ prefix was intentionally removed)", name)
			}
		})
	}
}

// TestIsBlockedEnvName_NewlyAddedRCEFamily documents the loader path for each
// newly added ecosystem family, one subtest per ecosystem.
func TestIsBlockedEnvName_NewlyAddedRCEFamily(t *testing.T) {
	tests := []struct {
		name   string
		vars   []string
		reason string
	}{
		{
			name: "JVM_build_tools",
			vars: []string{"MAVEN_OPTS", "GRADLE_OPTS", "SBT_OPTS"},
			// Maven / Gradle / SBT pass these as JVM flags before any
			// project code runs; -javaagent: or -Djava.security.manager=
			// paths can load arbitrary bytecode.
			reason: "JVM build tool option flags honored before project code",
		},
		{
			name: "Go_toolchain",
			vars: []string{"GOPROXY", "GOFLAGS"},
			// GOFLAGS supports -toolexec=program which replaces every
			// toolchain binary (compile/link/asm) with an arbitrary exec.
			// GOPROXY redirects module fetches to an attacker proxy.
			// GOEXPERIMENT is NOT blocked — it's a closed-set feature toggle,
			// not a code-load or exec path.
			reason: "GOFLAGS -toolexec= executes arbitrary program; GOPROXY supplies malicious modules",
		},
		{
			name: "Rust_Cargo_compiler_replacement",
			vars: []string{"RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "RUSTC", "RUSTDOC"},
			// Cargo executes RUSTC_WRAPPER in place of the compiler for
			// every build invocation. ANSSI secure-Rust guidelines flag
			// this as must-not-override.
			reason: "Cargo executes RUSTC_WRAPPER directly for every build step",
		},
		{
			name: "Bun_options",
			vars: []string{"BUN_OPTIONS"},
			// BUN_OPTIONS is prepended to every Bun invocation, equivalent
			// to NODE_OPTIONS. Supports --preload to load arbitrary modules.
			reason: "BUN_OPTIONS prepended to every bun invocation, supports --preload",
		},
		{
			name: "Lua_path",
			vars: []string{"LUA_PATH", "LUA_CPATH"},
			// LUA_PATH / LUA_CPATH override the search path for require()
			// before any Lua standard paths.
			reason: "LUA_PATH / LUA_CPATH searched by require() before system paths",
		},
		{
			name: "R_library_path",
			vars: []string{"R_LIBS", "R_LIBS_USER"},
			// R's library() and require() search R_LIBS / R_LIBS_USER
			// before system library paths.
			reason: "R library() searches R_LIBS before system paths",
		},
		{
			name: "Haskell_GHC_package_path",
			vars: []string{"GHC_PACKAGE_PATH"},
			// GHC_PACKAGE_PATH overrides the compiled-Haskell package
			// database, allowing substitution of arbitrary object code.
			reason: "GHC_PACKAGE_PATH overrides compiled package database",
		},
		{
			name: "OCaml_paths",
			vars: []string{"OCAMLPATH", "CAML_LD_LIBRARY_PATH"},
			// OCAMLPATH extends findlib / Dynlink search;
			// CAML_LD_LIBRARY_PATH is the OCaml-specific .so stub path.
			reason: "OCAMLPATH / CAML_LD_LIBRARY_PATH affect .cma / .so code loading",
		},
		{
			name: "Erlang_OTP_flags",
			vars: []string{"ERL_FLAGS", "ERL_LIBS", "ERL_AFLAGS", "ERL_ZFLAGS"},
			// ERL_FLAGS / ERL_AFLAGS / ERL_ZFLAGS are prepended/appended
			// to every erl invocation; -pa and -pz add code paths.
			reason: "ERL_FLAGS -pa/-pz prepended to erl, adding attacker code to load path",
		},
		{
			name: "Tcl_library_path",
			vars: []string{"TCLLIBPATH"},
			// TCLLIBPATH is prepended to Tcl's auto_path; package require
			// searches it before standard library directories.
			reason: "TCLLIBPATH prepended to auto_path, searched by package require",
		},
		{
			name: "Guile_load_path",
			vars: []string{"GUILE_LOAD_PATH"},
			// GUILE_LOAD_PATH prepends to %load-path; use-modules searches
			// it before standard system paths.
			reason: "GUILE_LOAD_PATH prepended to %load-path, searched by use-modules",
		},
		{
			name: "Nix_path",
			vars: []string{"NIX_PATH"},
			// NIX_PATH resolves <nixpkgs> and channel lookups used by
			// nix-build and nix-shell; attacker-controlled value redirects
			// the entire build dependency graph.
			reason: "NIX_PATH resolves <nixpkgs> channels in nix-build / nix-shell",
		},
		{
			name: "Scheme_Chez_path",
			vars: []string{"CHEZSCHEMELIBDIRS", "SCHEME_LIBRARY_PATH"},
			// CHEZSCHEMELIBDIRS is the canonical Chez Scheme library path var.
			// SCHEME_LIBRARY_PATH is used by SLIB (portable Scheme library).
			reason: "CHEZSCHEMELIBDIRS / SCHEME_LIBRARY_PATH searched by (library ...) before system paths",
		},
		{
			name: "Clojure_load_path",
			vars: []string{"CLOJURE_LOAD_PATH"},
			reason: "CLOJURE_LOAD_PATH added to Clojure load path for (load ...) / (require ...)",
		},
		{
			name: "Elixir_Mix_archives",
			vars: []string{"MIX_ARCHIVES"},
			// MIX_ARCHIVES points to a directory of compiled .ez archives
			// that Mix loads globally on startup.
			reason: "MIX_ARCHIVES redirects Mix global archive directory loaded at startup",
		},
		{
			name: "editors_pagers",
			vars: []string{
				"EDITOR", "VISUAL", "PAGER",
				"GIT_EDITOR", "GIT_SEQUENCE_EDITOR", "GIT_PAGER",
				"MANPAGER", "SYSTEMD_PAGER",
				"LESS", "LESSOPEN", "LESSCLOSE",
				"SUDO_EDITOR",
			},
			// git commit, crontab -e, visudo, etc. exec $EDITOR via
			// system(). LESSOPEN / LESSCLOSE are executed as shell commands
			// by less (CVE-2024-32487). GIT_EDITOR / GIT_SEQUENCE_EDITOR
			// are checked by git before $EDITOR. MANPAGER / SYSTEMD_PAGER
			// are tool-specific $PAGER overrides.
			reason: "EDITOR/VISUAL/PAGER executed via system(); LESSOPEN is a shell command (CVE-2024-32487)",
		},
		{
			name: "git_config_injection",
			vars: []string{"GIT_EXEC_PATH", "GIT_CONFIG_COUNT"},
			// GIT_EXEC_PATH replaces git's internal subcommand directory.
			// GIT_CONFIG_COUNT / GIT_CONFIG_KEY_N / GIT_CONFIG_VALUE_N
			// inject arbitrary git config; an attacker can use alias.x=!/bin/sh.
			// GIT_CONFIG_ prefix (in blockedPrefixes) covers KEY_N / VALUE_N.
			reason: "GIT_EXEC_PATH replaces git subcommands; GIT_CONFIG_* injects alias RCE",
		},
		{
			name: "openssl_engine",
			vars: []string{"OPENSSL_CONF"},
			// OPENSSL_CONF points to a config file that can load arbitrary
			// engine .so modules — a well-known RCE vector in OpenSSL.
			reason: "OPENSSL_CONF can load arbitrary engine .so modules",
		},
		{
			name: "askpass_programs",
			vars: []string{"SSH_ASKPASS", "GIT_ASKPASS", "SUDO_ASKPASS"},
			// ssh / git / sudo exec the value of these vars directly when
			// they need a passphrase and have no TTY.
			reason: "SSH_ASKPASS / GIT_ASKPASS / SUDO_ASKPASS executed directly as a program",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			for _, v := range tc.vars {
				if !isBlockedEnvName(v) {
					t.Errorf("isBlockedEnvName(%q) = false, want true — reason: %s", v, tc.reason)
				}
			}
		})
	}
}

func TestIsBlockedEnvName_PrefixAtStartOnly(t *testing.T) {
	// LD_-prefixed names are blocked regardless of suffix; substring
	// matches mid-name are not, because the dynamic linker only honors
	// the canonical prefix at the start of the env var name.
	if !isBlockedEnvName("LD_PRELOAD_FOO") {
		t.Errorf("LD_PRELOAD_FOO should be blocked (prefix at start)")
	}
	if isBlockedEnvName("MY_LD_PRELOAD") {
		t.Errorf("MY_LD_PRELOAD should NOT be blocked (LD_ is mid-string)")
	}
}

func TestIsBlockedEnvName_CaseSensitive(t *testing.T) {
	// POSIX env names are case-sensitive and so is our deny-list. The
	// real loader only honors the canonical case, so an attacker cannot
	// bypass anything by lowercasing.
	cases := []string{"path", "ld_preload", "bash_env", "Path", "Ld_Preload"}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			if isBlockedEnvName(name) {
				t.Fatalf("isBlockedEnvName(%q) = true, want false (case-sensitive)", name)
			}
		})
	}
}

func TestIsBlockedEnvName_NormalNamesPass(t *testing.T) {
	// None of the new deny-list entries should accidentally block
	// legitimate user-defined secret env var names.
	ok := []string{
		"OPENAI_API_KEY", "STRIPE_SECRET_KEY", "FOO_TOKEN",
		"MY_VAR", "A", "X_Y_Z",
		// Go prefix is NOT blocked (GOOS, GOARCH, GOPATH are legitimate).
		"GOPATH", "GOOS", "GOARCH",
		// GOEXPERIMENT is a closed-set feature toggle, not a code-load path.
		"GOEXPERIMENT",
		// R_ prefix is NOT blocked.
		"R_API_TOKEN",
		// RUSTFLAGS is not blocked (not direct RCE by itself).
		"RUSTFLAGS",
		// JULIA_ prefix was intentionally NOT added; user-defined vars pass.
		"JULIA_TOKEN", "JULIA_API_KEY",
	}
	for _, name := range ok {
		t.Run(name, func(t *testing.T) {
			if isBlockedEnvName(name) {
				t.Fatalf("isBlockedEnvName(%q) = true, want false", name)
			}
		})
	}
}

func TestIsBlockedEnvName_EmptyString(t *testing.T) {
	// Empty string is rejected by validEnvName upstream; assert that
	// the deny-list itself is silent about it so the two layers don't
	// double-error or mask each other.
	if isBlockedEnvName("") {
		t.Fatal("isBlockedEnvName(\"\") = true, want false")
	}
}
