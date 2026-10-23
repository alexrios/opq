package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// memBackend is an in-memory Backend for exercising the policy layer without a
// real keyring. It stores raw bytes per key and mirrors the keyringBackend's
// ErrSecretNotFound contract.
type memBackend struct {
	mu   sync.Mutex
	data map[string][]byte
}

func newMemBackend(t *testing.T) *memBackend {
	t.Helper()
	root := t.TempDir()
	t.Setenv("XDG_STATE_HOME", root)
	setPolicyHomeForTest(t, root)
	return &memBackend{data: map[string][]byte{}}
}

// setPolicyHomeForTest keeps every policy-lock file inside its test fixture.
// Tests do not run this fixture concurrently with changes to the global lookup.
func setPolicyHomeForTest(t *testing.T, home string) {
	t.Helper()
	previous := policyHomeDir
	policyHomeDir = func() (string, error) { return home, nil }
	t.Cleanup(func() { policyHomeDir = previous })
}

func (b *memBackend) Name() string { return "mem" }

func (b *memBackend) Get(_ context.Context, name string) (*Buffer, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	v, ok := b.data[name]
	if !ok {
		return nil, ErrSecretNotFound
	}
	cp := make([]byte, len(v))
	copy(cp, v)
	return NewBufferFromBytes(cp)
}

func (b *memBackend) Set(_ context.Context, name string, value *Buffer) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	cp := make([]byte, value.Size())
	copy(cp, value.Bytes())
	b.data[name] = cp
	return nil
}

func (b *memBackend) Delete(_ context.Context, name string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.data[name]; !ok {
		return ErrSecretNotFound
	}
	delete(b.data, name)
	return nil
}

func (b *memBackend) List(_ context.Context) ([]string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
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
	b := newMemBackend(t)
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
	b := newMemBackend(t)
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
	b := newMemBackend(t)
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
	b := newMemBackend(t)
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
	b := newMemBackend(t)
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
	b := newMemBackend(t)
	ctx := context.Background()
	// Revoke wipes the value but leaves the tombstone; model that exactly.
	if err := storeMeta(ctx, b, "k", &SecretMeta{V: 1, RevokedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	_, err := resolveSecret(ctx, b, "k", time.Now().UTC())
	if !errors.Is(err, ErrSecretRevoked) {
		t.Fatalf("want ErrSecretRevoked, got %v", err)
	}
}

func TestResolveSecret_RevokedBeatsExpired(t *testing.T) {
	b := newMemBackend(t)
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
	b := newMemBackend(t)
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
	b := newMemBackend(t)
	// A name containing '/' could otherwise address the reserved meta/
	// namespace; resolveSecret must fail closed as not-found before any lookup.
	for _, name := range []string{"meta/evil", "../escape", "has space"} {
		if _, err := resolveSecret(context.Background(), b, name, time.Now().UTC()); !errors.Is(err, ErrSecretNotFound) {
			t.Errorf("resolveSecret(%q) = %v, want ErrSecretNotFound", name, err)
		}
	}
}

// policyFaultBackend fails a specific update phase or pauses after the value is
// written. All values are synthetic and the lock directory is test-local.
type policyFaultBackend struct {
	*memBackend
	setCount     int
	failSetAt    int
	wroteValue   chan struct{}
	releaseValue chan struct{}
}

func (b *policyFaultBackend) Set(ctx context.Context, name string, value *Buffer) error {
	b.setCount++
	if b.setCount == b.failSetAt {
		return errors.New("synthetic write failure")
	}
	if err := b.memBackend.Set(ctx, name, value); err != nil {
		return err
	}
	if name == "k" && b.wroteValue != nil {
		close(b.wroteValue)
		<-b.releaseValue
	}
	return nil
}

func TestStoreSecret_IncompleteUpdatesFailClosed(t *testing.T) {
	for _, phase := range []int{1, 2, 3} {
		t.Run(fmt.Sprint(phase), func(t *testing.T) {
			b := &policyFaultBackend{memBackend: newMemBackend(t), failSetAt: phase}
			mustSet(t, b.memBackend, "k", "old-synthetic")
			v, _ := NewBufferFromBytes([]byte("new-synthetic"))
			defer v.Destroy()
			err := storeSecret(context.Background(), b, "k", v, &SecretMeta{V: secretMetaVersion, ExpiresAt: time.Now().Add(time.Hour)})
			if err == nil {
				t.Fatal("expected update failure")
			}
			got, err := resolveSecret(context.Background(), b, "k", time.Now())
			if phase == 1 {
				if err != nil {
					t.Fatal(err)
				}
				defer got.Destroy()
				if string(got.Bytes()) != "old-synthetic" {
					t.Fatal("prepare failure changed existing value")
				}
			} else if !errors.Is(err, ErrSecretUpdatePending) {
				if got != nil {
					got.Destroy()
				}
				t.Fatalf("incomplete update returned value: %v", err)
			}
		})
	}
}

func TestStoreSecret_ReaderCannotObserveValueBeforeTTL(t *testing.T) {
	b := &policyFaultBackend{memBackend: newMemBackend(t), wroteValue: make(chan struct{}), releaseValue: make(chan struct{})}
	v, _ := NewBufferFromBytes([]byte("synthetic"))
	defer v.Destroy()
	done := make(chan error, 1)
	go func() {
		done <- storeSecret(context.Background(), b, "k", v, &SecretMeta{V: secretMetaVersion, ExpiresAt: time.Now().Add(-time.Hour)})
	}()
	<-b.wroteValue
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	got, err := resolveSecret(ctx, b, "k", time.Now())
	cancel()
	close(b.releaseValue)
	if storeErr := <-done; storeErr != nil {
		t.Fatal(storeErr)
	}
	if got != nil {
		got.Destroy()
		t.Fatal("reader observed value during update")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waiting reader: %v", err)
	}
	if _, err := resolveSecret(context.Background(), b, "k", time.Now()); !errors.Is(err, ErrSecretExpired) {
		t.Fatalf("TTL not enforced after update: %v", err)
	}
}

func TestStoreSecret_PendingCrashRecovery(t *testing.T) {
	b := newMemBackend(t)
	ctx := context.Background()
	mustSet(t, b, "k", "synthetic-interrupted-value")
	if err := storeMeta(ctx, b, "k", &SecretMeta{V: secretMetaVersion, Pending: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveSecret(ctx, b, "k", time.Now()); !errors.Is(err, ErrSecretUpdatePending) {
		t.Fatalf("pending marker accepted: %v", err)
	}
	v, _ := NewBufferFromBytes([]byte("synthetic-recovery"))
	defer v.Destroy()
	if err := storeSecret(ctx, b, "k", v, nil); err != nil {
		t.Fatal(err)
	}
	got, err := resolveSecret(ctx, b, "k", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	got.Destroy()
	if m, err := loadMeta(ctx, b, "k"); err != nil || m != nil {
		t.Fatalf("plain set retained pending policy: %+v %v", m, err)
	}
}

func TestPolicy_RejectsUnknownVersionAndAllowsDeleteRecovery(t *testing.T) {
	b := newMemBackend(t)
	ctx := context.Background()
	mustSet(t, b, "k", "synthetic")
	mustSet(t, b, metaKey("k"), `{"v":999}`)
	if got, err := resolveSecret(ctx, b, "k", time.Now()); err == nil {
		got.Destroy()
		t.Fatal("unknown metadata version accepted")
	}
	if err := deleteSecret(ctx, b, "k"); err != nil {
		t.Fatalf("explicit delete could not recover unknown metadata: %v", err)
	}
	if len(b.data) != 0 {
		t.Fatal("delete left records")
	}
}

func TestPolicy_RevokeThenSetAndPruneCurrentGeneration(t *testing.T) {
	b := newMemBackend(t)
	ctx := context.Background()
	v, _ := NewBufferFromBytes([]byte("synthetic"))
	defer v.Destroy()
	if err := storeSecret(ctx, b, "k", v, &SecretMeta{V: secretMetaVersion, ExpiresAt: time.Now().Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := revokeSecret(ctx, b, "k", time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, pruned, err := pruneSecret(ctx, b, "k", time.Now(), false); err != nil || pruned {
		t.Fatalf("prune removed tombstone: %t %v", pruned, err)
	}
	if err := storeSecret(ctx, b, "k", v, &SecretMeta{V: secretMetaVersion, ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if _, pruned, err := pruneSecret(ctx, b, "k", time.Now(), false); err != nil || pruned {
		t.Fatalf("prune removed replacement generation: %t %v", pruned, err)
	}
	got, err := resolveSecret(ctx, b, "k", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	got.Destroy()
}

func TestPolicyLock_CrossProcessAndCancellation(t *testing.T) {
	if os.Getenv("OPQ_TEST_POLICY_LOCK_READER") == "1" {
		setPolicyHomeForTest(t, os.Getenv("OPQ_TEST_POLICY_HOME"))
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
		defer cancel()
		unlock, err := lockPolicy(ctx, false)
		if unlock != nil {
			unlock()
			t.Fatal("reader acquired lock held by another process")
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("wanted deadline: %v", err)
		}
		return
	}
	newMemBackend(t)
	unlock, err := lockPolicy(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	c := exec.Command(os.Args[0], "-test.run=^TestPolicyLock_CrossProcessAndCancellation$")
	home, err := policyHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	c.Env = append(os.Environ(), "OPQ_TEST_POLICY_LOCK_READER=1", "OPQ_TEST_POLICY_HOME="+home, "HOME="+t.TempDir(), "XDG_STATE_HOME="+t.TempDir())
	if out, err := c.CombinedOutput(); err != nil {
		t.Fatalf("reader process: %v %s", err, out)
	}
}

func TestPolicyLock_RefusesSymlink(t *testing.T) {
	root := t.TempDir()
	t.Setenv("XDG_STATE_HOME", root)
	setPolicyHomeForTest(t, root)
	dir, err := policyLockDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "policy.lock")); err != nil {
		t.Fatal(err)
	}
	if unlock, err := lockPolicy(context.Background(), true); err == nil {
		unlock()
		t.Fatal("symlink lock accepted")
	}
}

type policyDeleteFaultBackend struct {
	*memBackend
	failName string
}

func (b *policyDeleteFaultBackend) Delete(ctx context.Context, name string) error {
	if name == b.failName {
		return errors.New("synthetic delete failure")
	}
	return b.memBackend.Delete(ctx, name)
}

func TestPolicy_DeleteFailureRetainsExpiry(t *testing.T) {
	b := &policyDeleteFaultBackend{memBackend: newMemBackend(t), failName: "k"}
	ctx := context.Background()
	mustSet(t, b, "k", "synthetic")
	if err := storeMeta(ctx, b, "k", &SecretMeta{V: secretMetaVersion, ExpiresAt: time.Now().Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := deleteSecret(ctx, b, "k"); err == nil {
		t.Fatal("expected deletion failure")
	}
	if _, err := resolveSecret(ctx, b, "k", time.Now()); !errors.Is(err, ErrSecretExpired) {
		t.Fatalf("failed deletion cleared policy: %v", err)
	}
}

func TestStoreSecret_FinalMetadataDeleteFailureRemainsBlocked(t *testing.T) {
	b := &policyDeleteFaultBackend{memBackend: newMemBackend(t), failName: metaKey("k")}
	v, _ := NewBufferFromBytes([]byte("synthetic"))
	defer v.Destroy()
	if err := storeSecret(context.Background(), b, "k", v, nil); err == nil {
		t.Fatal("expected final metadata deletion failure")
	}
	if _, err := resolveSecret(context.Background(), b, "k", time.Now()); !errors.Is(err, ErrSecretUpdatePending) {
		t.Fatalf("failed commit permitted read: %v", err)
	}
}

type policyReadGateBackend struct {
	*memBackend
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

func (b *policyReadGateBackend) Get(ctx context.Context, name string) (*Buffer, error) {
	buf, err := b.memBackend.Get(ctx, name)
	if name == metaKey("k") {
		b.once.Do(func() { close(b.entered); <-b.release })
	}
	return buf, err
}

func TestPolicy_MutationsCannotInterleaveWithSet(t *testing.T) {
	for _, action := range []string{"revoke", "prune"} {
		t.Run(action, func(t *testing.T) {
			b := &policyReadGateBackend{memBackend: newMemBackend(t), entered: make(chan struct{}), release: make(chan struct{})}
			ctx := context.Background()
			mustSet(t, b, "k", "old-synthetic")
			if err := storeMeta(ctx, b, "k", &SecretMeta{V: secretMetaVersion, ExpiresAt: time.Now().Add(-time.Hour)}); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				if action == "revoke" {
					done <- revokeSecret(ctx, b, "k", time.Now())
				} else {
					_, _, err := pruneSecret(ctx, b, "k", time.Now(), false)
					done <- err
				}
			}()
			<-b.entered
			v, _ := NewBufferFromBytes([]byte("replacement-synthetic"))
			defer v.Destroy()
			writeCtx, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
			err := storeSecret(writeCtx, b, "k", v, nil)
			cancel()
			close(b.release)
			if mutationErr := <-done; mutationErr != nil {
				t.Fatal(mutationErr)
			}
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("set interleaved with %s: %v", action, err)
			}
			if err := storeSecret(ctx, b, "k", v, nil); err != nil {
				t.Fatal(err)
			}
			got, err := resolveSecret(ctx, b, "k", time.Now())
			if err != nil {
				t.Fatal(err)
			}
			defer got.Destroy()
			if string(got.Bytes()) != "replacement-synthetic" {
				t.Fatal("old generation replaced the successful set")
			}
		})
	}
}

type policySlowValueBackend struct{ *memBackend }

func (b *policySlowValueBackend) Get(ctx context.Context, name string) (*Buffer, error) {
	if name == "k" {
		time.Sleep(20 * time.Millisecond)
	}
	return b.memBackend.Get(ctx, name)
}
func TestResolveSecret_ExpiryDuringValueFetchIsRefused(t *testing.T) {
	b := &policySlowValueBackend{newMemBackend(t)}
	mustSet(t, b, "k", "synthetic")
	now := time.Now()
	if err := storeMeta(context.Background(), b, "k", &SecretMeta{V: secretMetaVersion, ExpiresAt: now.Add(10 * time.Millisecond)}); err != nil {
		t.Fatal(err)
	}
	if got, err := resolveSecret(context.Background(), b, "k", now); !errors.Is(err, ErrSecretExpired) {
		if got != nil {
			got.Destroy()
		}
		t.Fatalf("expired value returned after fetch: %v", err)
	}
}

func TestPolicyLock_IdentityIndependentOfEnvironment(t *testing.T) {
	root := t.TempDir()
	setPolicyHomeForTest(t, root)
	expected, err := policyLockDir()
	if err != nil {
		t.Fatal(err)
	}
	unlock, err := lockPolicy(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	got, err := policyLockDir()
	if err != nil {
		t.Fatal(err)
	}
	if got != expected {
		t.Fatalf("environment split lock identity: %q != %q", got, expected)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if unlock, err := lockPolicy(ctx, false); !errors.Is(err, context.DeadlineExceeded) {
		if unlock != nil {
			unlock()
		}
		t.Fatalf("changed environment bypassed held lock: %v", err)
	}
}

func TestPolicyHomeDir_UsesOSAccountDatabase(t *testing.T) {
	// Only resolve the path; this test never creates the real user's lock files.
	expected, err := policyHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	got, err := policyHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	if got != expected {
		t.Fatalf("OS account lookup followed caller environment: %q != %q", got, expected)
	}
}

func TestRevokeSecret_UnreadableMetadataStillWipesValue(t *testing.T) {
	for _, raw := range []string{`{"v":`, `{"v":999}`} {
		t.Run(raw, func(t *testing.T) {
			b := newMemBackend(t)
			ctx := context.Background()
			mustSet(t, b, "k", "synthetic-live-value")
			mustSet(t, b, metaKey("k"), raw)
			if buf, err := resolveSecret(ctx, b, "k", time.Now()); err == nil {
				buf.Destroy()
				t.Fatal("unreadable policy permitted a read")
			}
			if err := revokeSecret(ctx, b, "k", time.Now()); err != nil {
				t.Fatalf("emergency revocation failed: %v", err)
			}
			if buf, err := b.Get(ctx, "k"); !errors.Is(err, ErrSecretNotFound) {
				if buf != nil {
					buf.Destroy()
				}
				t.Fatalf("value survived revocation: %v", err)
			}
			meta, err := loadMeta(ctx, b, "k")
			if err != nil || !meta.IsRevoked() || meta.V != secretMetaVersion {
				t.Fatalf("missing valid tombstone: meta=%+v err=%v", meta, err)
			}
			if buf, err := resolveSecret(ctx, b, "k", time.Now()); !errors.Is(err, ErrSecretRevoked) {
				if buf != nil {
					buf.Destroy()
				}
				t.Fatalf("revoked read error=%v", err)
			}
		})
	}
}

type policyMetaReadFaultBackend struct{ *memBackend }

func (b *policyMetaReadFaultBackend) Get(ctx context.Context, name string) (*Buffer, error) {
	if name == metaKey("k") {
		return nil, errors.New("synthetic metadata transport error")
	}
	return b.memBackend.Get(ctx, name)
}
func TestRevokeSecret_MetadataBackendFailureStillAttemptsWipe(t *testing.T) {
	base := newMemBackend(t)
	mustSet(t, base, "k", "synthetic-live-value")
	backend := &policyMetaReadFaultBackend{base}
	if err := revokeSecret(context.Background(), backend, "k", time.Now()); err != nil {
		t.Fatal(err)
	}
	if buf, err := base.Get(context.Background(), "k"); !errors.Is(err, ErrSecretNotFound) {
		if buf != nil {
			buf.Destroy()
		}
		t.Fatalf("value survived revocation: %v", err)
	}
	meta, err := loadMeta(context.Background(), base, "k")
	if err != nil || !meta.IsRevoked() {
		t.Fatalf("tombstone missing: %v", err)
	}
}
func TestRevokeSecret_AbsentValuePreservesUnreadableMetadataError(t *testing.T) {
	b := newMemBackend(t)
	mustSet(t, b, metaKey("k"), `{"v":`)
	if err := revokeSecret(context.Background(), b, "k", time.Now()); err == nil || errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("lost useful metadata error: %v", err)
	}
}
