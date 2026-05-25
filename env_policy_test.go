package main

import "testing"

func TestIsBlockedEnvName_ExactMap(t *testing.T) {
	blocked := []string{
		"PATH", "IFS", "HOME", "SHELL", "TERM", "TMPDIR", "TZ",
		"BASH_ENV", "ENV", "PROMPT_COMMAND",
		"PYTHONPATH", "PYTHONSTARTUP",
		"NODE_OPTIONS", "NODE_PATH",
		"PERL5LIB", "PERL5OPT", "PERLLIB",
		"RUBYOPT", "RUBYLIB",
		"GEM_HOME", "GEM_PATH", "BUNDLE_GEMFILE",
		"JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS",
		"JAVA_HOME", "CLASSPATH",
		"PYTHONHOME",
		"GIT_SSH", "GIT_SSH_COMMAND",
		"GLIBC_TUNABLES",
		"LOCALDOMAIN", "HOSTALIASES", "RES_OPTIONS",
		"MALLOC_TRACE", "NLSPATH",
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
		"LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "LD_PROFILE",
		"DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH",
		"NSS_HOSTS", "GIO_USE_VFS", "GCONV_PATH",
	}
	for _, name := range prefixed {
		t.Run(name, func(t *testing.T) {
			if !isBlockedEnvName(name) {
				t.Fatalf("isBlockedEnvName(%q) = false, want true", name)
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
	ok := []string{
		"OPENAI_API_KEY", "STRIPE_SECRET_KEY", "FOO_TOKEN",
		"MY_VAR", "A", "X_Y_Z",
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
