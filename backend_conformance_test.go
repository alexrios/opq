package main

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
)

// backendContractTest exercises the Backend contract every implementation must
// honor so policy.go's errors.Is chains and the list/meta enumeration work
// uniformly across backends. Writable backends round-trip values and coexist
// with meta/ companion keys; read-only backends refuse writes with
// ErrBackendReadOnly. Run it against each concrete backend below.
func backendContractTest(t *testing.T, b Backend, writable bool) {
	t.Helper()
	ctx := context.Background()

	// Get of an absent key is always ErrSecretNotFound, on every backend.
	if _, err := b.Get(ctx, "definitely_absent_key"); !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("%s: Get(absent): want ErrSecretNotFound, got %v", b.Name(), err)
	}

	if !writable {
		buf, err := NewBufferFromBytes([]byte("x"))
		if err != nil {
			t.Fatal(err)
		}
		defer buf.Destroy()
		if err := b.Set(ctx, "k", buf); !errors.Is(err, ErrBackendReadOnly) {
			t.Fatalf("%s: Set on read-only backend: want ErrBackendReadOnly, got %v", b.Name(), err)
		}
		if err := b.Delete(ctx, "k"); !errors.Is(err, ErrBackendReadOnly) {
			t.Fatalf("%s: Delete on read-only backend: want ErrBackendReadOnly, got %v", b.Name(), err)
		}
		return
	}

	// Round-trip a secret and its companion meta/ item.
	mustSet(t, b, "alpha", "v-alpha")
	mustSet(t, b, "meta/alpha", `{"v":1}`)
	if got := getBackendValue(t, b, "alpha"); got != "v-alpha" {
		t.Fatalf("%s: round-trip: got %q", b.Name(), got)
	}

	// List must return the raw keyspace INCLUDING the meta/ companion (the
	// CLI/list_secrets layer filters meta/, not the backend).
	keys, err := b.List(ctx)
	if err != nil {
		t.Fatalf("%s: List: %v", b.Name(), err)
	}
	if !slices.Contains(keys, "alpha") || !slices.Contains(keys, "meta/alpha") {
		t.Fatalf("%s: List must include the secret and its meta/ companion: %v", b.Name(), keys)
	}

	// Delete removes the value; a second Delete reports ErrSecretNotFound.
	if err := b.Delete(ctx, "alpha"); err != nil {
		t.Fatalf("%s: Delete: %v", b.Name(), err)
	}
	if _, err := b.Get(ctx, "alpha"); !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("%s: Get after Delete: want ErrSecretNotFound, got %v", b.Name(), err)
	}
	if err := b.Delete(ctx, "alpha"); !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("%s: Delete(absent): want ErrSecretNotFound, got %v", b.Name(), err)
	}
}

func TestBackendContract_Mem(t *testing.T) {
	backendContractTest(t, newMemBackend(), true)
}

func TestBackendContract_Vault(t *testing.T) {
	b, _ := newFakeVaultBackend(t)
	backendContractTest(t, b, true)
}

func TestBackendContract_Proton(t *testing.T) {
	// Read-only contract: Get(absent) lists first, so provide an empty listing.
	b := newFakeProton(t, map[string]fakeResp{
		listCall: {out: []byte(`{"items":[]}`)},
	})
	backendContractTest(t, b, false)
}

// TestFilterParentEnv_ScrubsBackendCredentials locks the credential-hygiene
// invariant: a CLI exec child never inherits opq's own backend secrets, while
// non-secret backend config and unrelated vars pass through.
func TestFilterParentEnv_ScrubsBackendCredentials(t *testing.T) {
	in := []string{
		"PATH=/usr/bin",
		"HOME=/home/u",
		"VAULT_ADDR=https://vault:8200",
		"VAULT_TOKEN=s.secret",
		"PROTON_PASS_PERSONAL_ACCESS_TOKEN=pst_x",
		"PROTON_PASS_ENCRYPTION_KEY=k",
		"PROTON_PASS_PASSWORD=hunter2",
		"PROTON_PASS_EXTRA_PASSWORD=second",
		"PROTON_PASS_TOTP=123456",
		"PROTON_PASS_SSH_KEY_PASSWORD=sshpw",
		"PROTON_PASS_PASSWORD_FILE=/run/secrets/pw",
		"PROTON_PASS_SESSION_DIR=/run/x",
		"OPQ_BACKEND=vault",
		"MY_APP_TOKEN=keep",
	}
	// The entire PROTON_PASS_ namespace is scrubbed (pass-cli reads many
	// credential vars there); VAULT_TOKEN is scrubbed by exact match.
	dropped := map[string]bool{
		"VAULT_TOKEN":                       true,
		"PROTON_PASS_PERSONAL_ACCESS_TOKEN": true,
		"PROTON_PASS_ENCRYPTION_KEY":        true,
		"PROTON_PASS_PASSWORD":              true,
		"PROTON_PASS_EXTRA_PASSWORD":        true,
		"PROTON_PASS_TOTP":                  true,
		"PROTON_PASS_SSH_KEY_PASSWORD":      true,
		"PROTON_PASS_PASSWORD_FILE":         true,
		"PROTON_PASS_SESSION_DIR":           true, // non-secret config, but in the scrubbed namespace
		"OPQ_BACKEND":                       true,
	}
	kept := map[string]bool{
		"PATH":         true,
		"HOME":         true,
		"VAULT_ADDR":   true, // non-secret Vault config stays
		"MY_APP_TOKEN": true,
	}

	seen := map[string]bool{}
	for _, e := range filterParentEnv(in) {
		name, _, _ := strings.Cut(e, "=")
		seen[name] = true
		if dropped[name] {
			t.Fatalf("filterParentEnv kept a scrubbed credential: %q", e)
		}
	}
	for k := range kept {
		if !seen[k] {
			t.Fatalf("filterParentEnv dropped a var it should keep: %q", k)
		}
	}
}
