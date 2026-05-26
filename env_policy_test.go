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
		"MALLOC_TRACE", "MALLOC_CONF", "NLSPATH",
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
		// downloader configs (joint-review 2026-05 P2-1)
		"CURL_HOME", "WGETRC",
		// terminfo (joint-review 2026-05 P2-1)
		"TERMINFO", "TERMINFO_DIRS",
		// Kerberos (joint-review 2026-05 P2-1)
		"KRB5_CONFIG", "KRB5CCNAME", "KRB5_KTNAME",
		// readline (joint-review 2026-05 P2-1)
		"INPUTRC",
		// SSH agent socket (joint-review 2026-05 P2-4)
		"SSH_AUTH_SOCK",
		// container runtimes (joint-review 2026-05 P2-5 + Kimi)
		"DOCKER_HOST", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH", "DOCKER_CONFIG",
		"BUILDKIT_HOST", "CONTAINER_HOST",
		// PHP (Kimi gate-1)
		"PHPRC", "PHP_INI_SCAN_DIR",
		// Mercurial (Kimi gate-1)
		"HGRCPATH",
		// git diff helper (Kimi gate-1)
		"GIT_EXTERNAL_DIFF",
		// CMake (Kimi gate-1)
		"CMAKE_TOOLCHAIN_FILE",
		// generic compilers (Kimi gate-1)
		"CC", "CXX",
		// remote-shell command (Kimi gate-1)
		"RSYNC_RSH", "BORG_RSH",
		// GTK modules (Kimi gate-1)
		"GTK_MODULES",
		// Qt plugins (Kimi gate-2)
		"QT_PLUGIN_PATH",
		// vim startup (Kimi gate-2)
		"VIMINIT",
		// ripgrep preprocessor (Kimi gate-2)
		"RIPGREP_CONFIG_PATH",
		// GnuPG home (Kimi gate-2)
		"GNUPGHOME",
		// git hooks / dir overrides (Kimi gate-2)
		"GIT_TEMPLATE_DIR", "GIT_DIR",
		// Gradle user home (Kimi gate-2)
		"GRADLE_USER_HOME",
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
			name:   "Clojure_load_path",
			vars:   []string{"CLOJURE_LOAD_PATH"},
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

// TestIsBlockedEnvName_JointReview2026_05_Additions documents the loader/exec
// path for each cluster added during the joint Claude+Kimi review (2026-05).
func TestIsBlockedEnvName_JointReview2026_05_Additions(t *testing.T) {
	tests := []struct {
		name   string
		vars   []string
		reason string
	}{
		{
			name: "downloader_configs",
			vars: []string{"CURL_HOME", "WGETRC"},
			// curl reads $CURL_HOME/.curlrc at startup; .curlrc -K includes
			// further config and supports per-URL output redirection. wget
			// reads $WGETRC as its config-file path; wgetrc supports
			// post_file and exec directives.
			reason: "curl .curlrc / wget wgetrc are loaded at startup and shell out",
		},
		{
			name: "terminfo",
			vars: []string{"TERMINFO", "TERMINFO_DIRS"},
			// ncurses parses the compiled terminfo file on startup for every
			// curses-using program; long CVE history of parser overflows.
			reason: "ncurses parses TERMINFO at startup (CVE family)",
		},
		{
			name: "kerberos",
			vars: []string{"KRB5_CONFIG", "KRB5CCNAME", "KRB5_KTNAME"},
			// KRB5_CONFIG can load plugin .so modules. KRB5CCNAME points the
			// credential cache; KRB5_KTNAME points the keytab.
			reason: "krb5 honors these for config/credentials/keytab paths",
		},
		{
			name: "readline_init",
			vars: []string{"INPUTRC"},
			// readline parses $INPUTRC on first init across bash, gdb,
			// python -i, psql, mysql, etc.
			reason: "readline parses INPUTRC at first init",
		},
		{
			name: "jemalloc_tunables",
			vars: []string{"MALLOC_CONF"},
			// jemalloc analogue to MALLOC_TRACE / GLIBC_TUNABLES; supports
			// prof_prefix (writes profile dumps) and extent_hooks plugin
			// loading on some builds.
			reason: "MALLOC_CONF drives jemalloc init: prof_prefix writes, extent_hooks loads",
		},
		{
			name: "ssh_agent_socket",
			vars: []string{"SSH_AUTH_SOCK"},
			// With allow_network=true the AI can authenticate to remote
			// hosts using the operator's loaded keys (cannot extract the
			// key, but can use it).
			reason: "SSH_AUTH_SOCK lets the AI use operator's loaded keys under allow_network",
		},
		{
			name: "container_runtimes",
			vars: []string{
				"DOCKER_HOST", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH",
				"DOCKER_CONFIG", "BUILDKIT_HOST", "CONTAINER_HOST",
			},
			// Redirect docker / buildkit / podman CLI to an attacker-chosen
			// daemon (DOCKER_HOST) or attacker certs (DOCKER_TLS_VERIFY +
			// DOCKER_CERT_PATH). DOCKER_CONFIG redirects the CLI plugin dir.
			reason: "container CLIs honor *_HOST and DOCKER_CONFIG to redirect daemon/plugins",
		},
		{
			name: "php_config",
			vars: []string{"PHPRC", "PHP_INI_SCAN_DIR"},
			// PHPRC is the php.ini directory; php.ini can `extension=evil.so`.
			// PHP_INI_SCAN_DIR adds another ini-scan directory.
			reason: "PHP loads php.ini extensions from PHPRC / PHP_INI_SCAN_DIR",
		},
		{
			name: "mercurial_hgrc",
			vars: []string{"HGRCPATH"},
			// hg config supports [hooks] entries that are arbitrary shell
			// commands run on commit / push / etc.
			reason: "HGRCPATH can register arbitrary hg [hooks] shell commands",
		},
		{
			name: "git_external_diff",
			vars: []string{"GIT_EXTERNAL_DIFF"},
			// git executes $GIT_EXTERNAL_DIFF as a subprocess on every diff
			// invocation; companion to GIT_SSH / GIT_PAGER.
			reason: "git exec()s GIT_EXTERNAL_DIFF on every diff",
		},
		{
			name: "cmake_toolchain",
			vars: []string{"CMAKE_TOOLCHAIN_FILE"},
			// CMake runs arbitrary commands inside the toolchain file
			// (execute_process(), file(WRITE), etc.).
			reason: "CMAKE_TOOLCHAIN_FILE is loaded by cmake and runs arbitrary commands",
		},
		{
			name: "generic_compilers",
			vars: []string{"CC", "CXX"},
			// make and most build systems honor $CC / $CXX as the C / C++
			// compiler binary; same class as RUSTC_WRAPPER.
			reason: "make / configure honor CC / CXX as compiler binaries",
		},
		{
			name: "remote_shell",
			vars: []string{"RSYNC_RSH", "BORG_RSH"},
			// rsync runs $RSYNC_RSH as its transport; borg runs $BORG_RSH.
			reason: "rsync / borg exec RSH var as transport command",
		},
		{
			name: "gtk_modules",
			vars: []string{"GTK_MODULES"},
			// Every GTK app dlopen()s the modules listed here at startup.
			reason: "GTK dlopen()s GTK_MODULES entries on every GTK program startup",
		},
		{
			name: "qt_plugins",
			vars: []string{"QT_PLUGIN_PATH"},
			// Qt searches QT_PLUGIN_PATH for plugin .so modules loaded at
			// QCoreApplication / QGuiApplication init.
			reason: "Qt loads plugin .so modules from QT_PLUGIN_PATH at app init",
		},
		{
			name: "vim_init",
			vars: []string{"VIMINIT"},
			// VIMINIT is executed as Ex commands at vim startup; `!sh` is a
			// valid Ex command. vim is invoked transitively by git commit /
			// crontab -e / visudo.
			reason: "VIMINIT runs as Ex commands at vim startup (shell-out via !)",
		},
		{
			name: "ripgrep_preprocessor",
			vars: []string{"RIPGREP_CONFIG_PATH"},
			// ripgrep config file can include `--pre PATH`, which ripgrep
			// exec()s as a preprocessor for every matched file.
			reason: "ripgrep config --pre path is exec()d as a preprocessor",
		},
		{
			name: "gnupg_home",
			vars: []string{"GNUPGHOME"},
			// gpg.conf / gpg-agent.conf can specify helper executables
			// (pinentry-program etc.); GNUPGHOME redirects both.
			reason: "GNUPGHOME redirects gpg.conf which can name helper binaries",
		},
		{
			name: "git_dir_overrides",
			vars: []string{"GIT_TEMPLATE_DIR", "GIT_DIR"},
			// GIT_TEMPLATE_DIR seeds hooks/ into every new repo (init/clone).
			// GIT_DIR points git at a directory whose hooks/ fires on commit.
			reason: "GIT_TEMPLATE_DIR / GIT_DIR seed or activate git hooks",
		},
		{
			name: "gradle_user_home",
			vars: []string{"GRADLE_USER_HOME"},
			// Gradle runs init.d/*.gradle Groovy scripts on every build.
			reason: "GRADLE_USER_HOME init.d/*.gradle runs on every Gradle invocation",
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

// TestIsBlockedEnvName_JointReview2026_05_Negatives asserts that similar-
// looking names that are NOT the loader-honored canonical form remain
// unblocked, so the new entries don't create friction for legitimate
// user-defined secret env vars.
func TestIsBlockedEnvName_JointReview2026_05_Negatives(t *testing.T) {
	notBlocked := []string{
		// CURL_HOME is the canonical curl config dir; CURL_API_KEY etc. are
		// user-defined application secrets and must pass.
		"CURL_API_KEY", "CURL_TOKEN", "CURL_USER",
		// WGETRC is exact-match; WGET_USER / WGET_TOKEN are user-defined.
		"WGET_USER", "WGET_TOKEN",
		// KRB5_CONFIG / KRB5CCNAME / KRB5_KTNAME are exact-match; no KRB5_
		// prefix ban (would block KRB5_TRACE etc. that don't load code).
		"KRB5_BACKEND", "KRB5_TRACE", "KRB5_USER",
		// TERMINFO / TERMINFO_DIRS are exact-match; TERMINFO_USER is fine.
		"TERMINFO_USER",
		// MALLOC_CONF is exact-match; MALLOC_USER is fine. MALLOC_ARENA_MAX
		// is a glibc tunable in the GLIBC_TUNABLES era but not directly
		// honored as a code-load path; not on the deny-list.
		"MALLOC_USER", "MALLOC_ARENA_MAX",
		// SSH_AUTH_SOCK is exact-match. SSH_CONNECTION / SSH_CLIENT etc.
		// are informational and not honored as exec paths.
		"SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY", "SSH_USER", "SSH_API_KEY",
		// DOCKER_HOST is exact-match; DOCKER_USER / DOCKER_TOKEN are
		// user-defined secret names.
		"DOCKER_USER", "DOCKER_TOKEN", "DOCKER_PASSWORD",
		// BUILDKIT_HOST is exact-match; other BUILDKIT_ vars are config.
		"BUILDKIT_PROGRESS", "BUILDKIT_USER",
		// CONTAINER_HOST is exact-match; CONTAINER_NAME / CONTAINER_USER pass.
		"CONTAINER_NAME", "CONTAINER_USER",
		// PHPRC / PHP_INI_SCAN_DIR are exact-match; PHP_USER / PHP_API_KEY pass.
		"PHP_USER", "PHP_API_KEY",
		// HGRCPATH is exact-match; HG_USER / HG_API_KEY pass.
		"HG_USER", "HG_API_KEY",
		// CC / CXX are exact-match. Substring "CC" in another name is fine.
		"CCACHE_DIR", "CCT_USER", "MY_CC", "CXXFLAGS",
		// INPUTRC is exact-match; INPUT_USER and similar pass.
		"INPUT_USER", "INPUT_API_KEY",
		// CMAKE_TOOLCHAIN_FILE is exact-match; other CMAKE_ flags pass
		// (CMAKE_BUILD_TYPE, CMAKE_PREFIX_PATH are config knobs, not exec).
		"CMAKE_BUILD_TYPE", "CMAKE_PREFIX_PATH", "CMAKE_USER",
		// RSYNC_RSH / BORG_RSH exact-match; RSYNC_USER and BORG_PASSPHRASE pass.
		"RSYNC_USER", "BORG_PASSPHRASE", "BORG_REPO",
		// GTK_MODULES is exact-match; GTK_THEME / GTK_USER pass.
		"GTK_THEME", "GTK_USER",
		// QT_PLUGIN_PATH is exact-match; QT_QPA_PLATFORM / QT_USER pass
		// (Qt's platform integration plugin name is configuration, not a
		// plugin search path).
		"QT_QPA_PLATFORM", "QT_USER",
		// VIMINIT is exact-match; VIM_USER / VIMRUNTIME pass (VIMRUNTIME
		// is a path but only honored if not overridden by an installed vim;
		// the realistic exec-RCE path is VIMINIT itself).
		"VIM_USER", "VIMRUNTIME",
		// RIPGREP_CONFIG_PATH is exact-match; RIPGREP_USER passes.
		"RIPGREP_USER",
		// GNUPGHOME is exact-match; GPG_TTY / GPG_AGENT_INFO are not
		// honored as code-load paths.
		"GPG_TTY", "GPG_AGENT_INFO", "GNUPG_USER",
		// GIT_DIR / GIT_TEMPLATE_DIR are exact-match. GIT_AUTHOR_NAME /
		// GIT_COMMITTER_EMAIL etc. are user identity strings and must pass.
		"GIT_AUTHOR_NAME", "GIT_COMMITTER_EMAIL", "GIT_USER",
		// GRADLE_USER_HOME is exact-match; GRADLE_USER (a token/login) passes.
		"GRADLE_USER",
	}
	for _, name := range notBlocked {
		t.Run(name, func(t *testing.T) {
			if isBlockedEnvName(name) {
				t.Fatalf("isBlockedEnvName(%q) = true, want false (exact-match only, no overbroad prefix)", name)
			}
		})
	}
}

// TestIsBlockedEnvName_GitConfigGlobalSystemViaPrefix proves that
// GIT_CONFIG_GLOBAL and GIT_CONFIG_SYSTEM (Git 2.32+ override paths) are
// already caught by the existing GIT_CONFIG_ prefix in blockedPrefixes;
// no explicit entries are needed for them. Documented as part of the
// joint-review 2026-05 verification step.
func TestIsBlockedEnvName_GitConfigGlobalSystemViaPrefix(t *testing.T) {
	cases := []string{
		"GIT_CONFIG_GLOBAL",
		"GIT_CONFIG_SYSTEM",
		// future GIT_CONFIG_* vars are also pre-covered.
		"GIT_CONFIG_NOSYSTEM",
		"GIT_CONFIG_PARAMETERS",
	}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			if !isBlockedEnvName(name) {
				t.Fatalf("isBlockedEnvName(%q) = false, want true — should be caught by GIT_CONFIG_ prefix in blockedPrefixes", name)
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
