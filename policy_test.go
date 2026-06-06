package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

// memBackend is an in-memory Backend for exercising the policy layer without a
// real keyring. It stores raw bytes per key and mirrors the keyringBackend's
// ErrSecretNotFound contract.
type memBackend struct {
	data map[string][]byte
}

func newMemBackend() *memBackend { return &memBackend{data: map[string][]byte{}} }

func (b *memBackend) Name() string { return "mem" }

func (b *memBackend) Get(_ context.Context, name string) (*Buffer, error) {
	v, ok := b.data[name]
	if !ok {
		return nil, ErrSecretNotFound
	}
	cp := make([]byte, len(v))
	copy(cp, v)
	return NewBufferFromBytes(cp)
}

func (b *memBackend) Set(_ context.Context, name string, value *Buffer) error {
	cp := make([]byte, value.Size())
	copy(cp, value.Bytes())
	b.data[name] = cp
	return nil
}

func (b *memBackend) Delete(_ context.Context, name string) error {
	if _, ok := b.data[name]; !ok {
		return ErrSecretNotFound
	}
	delete(b.data, name)
	return nil
}

func (b *memBackend) List(_ context.Context) ([]string, error) {
	out := make([]string, 0, len(b.data))
	for k := range b.data {
		out = append(out, k)
	}
	return out, nil
}

func mustSet(t *testing.T, b Backend, name, val string) {
	t.Helper()
	buf, err := NewBufferFromBytes([]byte(val))
	if err != nil {
		t.Fatalf("NewBufferFromBytes(%q): %v", val, err)
	}
	defer buf.Destroy()
	if err := b.Set(context.Background(), name, buf); err != nil {
		t.Fatalf("Set(%q): %v", name, err)
	}
}

// --- key namespacing / collision safety ---

func TestMetaKey_CannotCollideWithSecretName(t *testing.T) {
	// metaKey uses '/', which validSecretName forbids, so no valid secret
	// name can ever produce a key that looks like a metadata key.
	for _, name := range []string{"a", "openai_api_key", "x.y-z_1", "A123"} {
		if !validSecretName(name) {
			t.Fatalf("test precondition: %q should be a valid secret name", name)
		}
		mk := metaKey(name)
		if !isMetaKey(mk) {
			t.Errorf("metaKey(%q)=%q not recognized by isMetaKey", name, mk)
		}
		if validSecretName(mk) {
			t.Errorf("metaKey(%q)=%q must NOT be a valid secret name (would collide)", name, mk)
		}
		got, ok := secretNameFromMetaKey(mk)
		if !ok || got != name {
			t.Errorf("secretNameFromMetaKey(%q)=(%q,%v), want (%q,true)", mk, got, ok, name)
		}
	}
	if _, ok := secretNameFromMetaKey("plain_secret"); ok {
		t.Error("secretNameFromMetaKey on a non-meta key returned ok=true")
	}
}

func TestFilterVisibleSecretNames_DropsMetaKeys(t *testing.T) {
	in := []string{"alpha", metaKey("alpha"), metaKey("ghost"), "beta"}
	got := filterVisibleSecretNames(in)
	for _, n := range got {
		if isMetaKey(n) {
			t.Fatalf("meta key %q leaked through filter", n)
		}
	}
	if len(got) != 2 || got[0] != "alpha" || got[1] != "beta" {
		t.Fatalf("got %v, want [alpha beta]", got)
	}
}

// --- SecretMeta predicates ---

func TestSecretMeta_NilReceiverIsNoPolicy(t *testing.T) {
	var m *SecretMeta
	if m.IsRevoked() || m.HasExpiry() || m.IsExpiredAt(time.Now()) {
		t.Fatal("nil SecretMeta must report no revocation, no expiry, not expired")
	}
}

func TestSecretMeta_IsExpiredAt_BoundaryInclusive(t *testing.T) {
	exp := time.Date(2026, 6, 6, 12, 0, 0, 0, time.UTC)
	m := &SecretMeta{V: 1, ExpiresAt: exp}
	if m.IsExpiredAt(exp.Add(-time.Second)) {
		t.Error("not expired one second before deadline")
	}
	if !m.IsExpiredAt(exp) {
		t.Error("expiry boundary must be inclusive (now == ExpiresAt is expired)")
	}
	if !m.IsExpiredAt(exp.Add(time.Second)) {
		t.Error("expired after deadline")
	}
}

// --- meta round-trip ---

func TestStoreLoadMeta_RoundTrip(t *testing.T) {
	b := newMemBackend()
	ctx := context.Background()
	exp := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	in := &SecretMeta{V: secretMetaVersion, CreatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), ExpiresAt: exp}
	if err := storeMeta(ctx, b, "k", in); err != nil {
		t.Fatalf("storeMeta: %v", err)
	}
	// Metadata must live under the reserved key, not the secret key.
	if _, ok := b.data[metaKey("k")]; !ok {
		t.Fatal("storeMeta did not write to the meta key")
	}
	if _, ok := b.data["k"]; ok {
		t.Fatal("storeMeta polluted the secret key")
	}
	out, err := loadMeta(ctx, b, "k")
	if err != nil {
		t.Fatalf("loadMeta: %v", err)
	}
	if out == nil || !out.ExpiresAt.Equal(exp) || out.V != secretMetaVersion {
		t.Fatalf("round-trip mismatch: %+v", out)
	}
}

func TestLoadMeta_MissingIsNilNil(t *testing.T) {
	b := newMemBackend()
	m, err := loadMeta(context.Background(), b, "absent")
	if err != nil {
		t.Fatalf("loadMeta on missing should not error: %v", err)
	}
	if m != nil {
		t.Fatalf("loadMeta on missing should return nil meta, got %+v", m)
	}
}

// --- resolveSecret enforcement ---

func TestResolveSecret_NoPolicyReturnsValue(t *testing.T) {
	b := newMemBackend()
	mustSet(t, b, "k", "topsecret")
	buf, err := resolveSecret(context.Background(), b, "k", time.Now().UTC())
	if err != nil {
		t.Fatalf("resolveSecret: %v", err)
	}
	defer buf.Destroy()
	if string(buf.Bytes()) != "topsecret" {
		t.Fatalf("got %q", buf.Bytes())
	}
}

func TestResolveSecret_ExpiredRefused(t *testing.T) {
	b := newMemBackend()
	ctx := context.Background()
	mustSet(t, b, "k", "v")
	past := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := storeMeta(ctx, b, "k", &SecretMeta{V: 1, ExpiresAt: past}); err != nil {
		t.Fatal(err)
	}
	_, err := resolveSecret(ctx, b, "k", time.Now().UTC())
	if !errors.Is(err, ErrSecretExpired) {
		t.Fatalf("want ErrSecretExpired, got %v", err)
	}
}

func TestResolveSecret_NotYetExpiredReturnsValue(t *testing.T) {
	b := newMemBackend()
	ctx := context.Background()
	mustSet(t, b, "k", "v")
	future := time.Now().UTC().Add(time.Hour)
	if err := storeMeta(ctx, b, "k", &SecretMeta{V: 1, ExpiresAt: future}); err != nil {
		t.Fatal(err)
	}
	buf, err := resolveSecret(ctx, b, "k", time.Now().UTC())
	if err != nil {
		t.Fatalf("resolveSecret: %v", err)
	}
	buf.Destroy()
}

func TestResolveSecret_RevokedRefused(t *testing.T) {
	b := newMemBackend()
	ctx := context.Background()
	// Revoke wipes the value but leaves the tombstone — model that exactly.
	if err := storeMeta(ctx, b, "k", &SecretMeta{V: 1, RevokedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	_, err := resolveSecret(ctx, b, "k", time.Now().UTC())
	if !errors.Is(err, ErrSecretRevoked) {
		t.Fatalf("want ErrSecretRevoked, got %v", err)
	}
}

func TestResolveSecret_RevokedBeatsExpired(t *testing.T) {
	b := newMemBackend()
	ctx := context.Background()
	past := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	// Both revoked AND past-expiry: revoked must win so the operator-facing
	// taxonomy reports the deliberate action, not an incidental TTL lapse.
	if err := storeMeta(ctx, b, "k", &SecretMeta{V: 1, ExpiresAt: past, RevokedAt: past}); err != nil {
		t.Fatal(err)
	}
	_, err := resolveSecret(ctx, b, "k", time.Now().UTC())
	if !errors.Is(err, ErrSecretRevoked) {
		t.Fatalf("revoked must take precedence over expired, got %v", err)
	}
}

func TestResolveSecret_NotFound(t *testing.T) {
	b := newMemBackend()
	_, err := resolveSecret(context.Background(), b, "absent", time.Now().UTC())
	if !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("want ErrSecretNotFound, got %v", err)
	}
}

// --- audit taxonomy ---

func TestSanitizePolicyErr_Taxonomy(t *testing.T) {
	cases := map[error]string{
		ErrSecretRevoked:   "secret_revoked",
		ErrSecretExpired:   "secret_expired",
		ErrSecretNotFound:  "not_found",
		errors.New("boom"): "backend_error",
	}
	for err, want := range cases {
		if got := sanitizePolicyErr(err); got != want {
			t.Errorf("sanitizePolicyErr(%v)=%q, want %q", err, got, want)
		}
	}
}

// --- TTL parsing ---

func TestParseTTL(t *testing.T) {
	ok := map[string]time.Duration{
		"24h":    24 * time.Hour,
		"90m":    90 * time.Minute,
		"1h30m":  90 * time.Minute,
		"7d":     7 * 24 * time.Hour,
		"2w":     14 * 24 * time.Hour,
		"0.5d":   12 * time.Hour,
		"  3d  ": 3 * 24 * time.Hour,
	}
	for in, want := range ok {
		got, err := parseTTL(in)
		if err != nil {
			t.Errorf("parseTTL(%q) errored: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("parseTTL(%q)=%v, want %v", in, got, want)
		}
	}

	bad := []string{"", "0", "0h", "-5m", "-1d", "abc", "10x", "d", "w", "1.2.3d"}
	for _, in := range bad {
		if d, err := parseTTL(in); err == nil {
			t.Errorf("parseTTL(%q) should have errored, got %v", in, d)
		}
	}
}

func TestParseTTL_RejectsOverflowAndNonFinite(t *testing.T) {
	// The day/week path computes in float64; huge or non-finite values must be
	// rejected before the int64 conversion wraps into a tiny/negative duration
	// that would make now.Add(ttl) overflow into the past.
	for _, in := range []string{"99999999999w", "1e308d", "1e400w", "nand", "infd"} {
		if d, err := parseTTL(in); err == nil {
			t.Errorf("parseTTL(%q) should reject overflow/non-finite, got %v", in, d)
		}
	}
}

func TestResolveSecret_RejectsInvalidName(t *testing.T) {
	b := newMemBackend()
	// A name containing '/' could otherwise address the reserved meta/
	// namespace; resolveSecret must fail closed as not-found before any lookup.
	for _, name := range []string{"meta/evil", "../escape", "has space"} {
		if _, err := resolveSecret(context.Background(), b, name, time.Now().UTC()); !errors.Is(err, ErrSecretNotFound) {
			t.Errorf("resolveSecret(%q) = %v, want ErrSecretNotFound", name, err)
		}
	}
}
