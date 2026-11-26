package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/awnumar/memguard"
)

type memMasterKeyProvider struct {
	mu        sync.Mutex
	key       []byte
	getErr    error
	createErr error
	gets      int
	creates   int
	// createRaceKey, if non-nil, simulates another process winning the Create race:
	// Create installs createRaceKey and returns ErrMasterKeyExists.
	createRaceKey []byte
}

func (m *memMasterKeyProvider) Get(ctx context.Context) (*memguard.LockedBuffer, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gets++
	if m.getErr != nil {
		return nil, m.getErr
	}
	if m.key == nil {
		return nil, ErrMasterKeyNotFound
	}
	cp := bytes.Clone(m.key)
	lb := memguard.NewBuffer(len(cp))
	lb.Move(cp)
	return lb, nil
}

func (m *memMasterKeyProvider) Create(ctx context.Context, key *memguard.LockedBuffer) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.creates++
	if m.createErr != nil {
		return m.createErr
	}
	if m.createRaceKey != nil {
		m.key = bytes.Clone(m.createRaceKey)
		m.createRaceKey = nil
		return ErrMasterKeyExists
	}
	if m.key != nil {
		return ErrMasterKeyExists
	}
	m.key = bytes.Clone(key.Bytes())
	return nil
}

func newTestVaultBackend(t *testing.T, kp *memMasterKeyProvider) (*vaultBackend, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "opq-vault")
	if kp == nil {
		kp = &memMasterKeyProvider{}
	}
	return newVaultBackend("keychain-vault", func() (string, error) { return dir, nil }, kp), dir
}

func TestVaultBackend_ReadOnlyOnFreshInstall(t *testing.T) {
	kp := &memMasterKeyProvider{}
	vb, dir := newTestVaultBackend(t, kp)
	ctx := t.Context()

	keys, err := vb.List(ctx)
	if err != nil {
		t.Fatalf("List on missing vault: %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("List = %v, want empty", keys)
	}
	if _, err := vb.Get(ctx, "missing"); !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("Get on missing vault = %v, want ErrSecretNotFound", err)
	}
	if err := vb.Delete(ctx, "missing"); !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("Delete on missing vault = %v, want ErrSecretNotFound", err)
	}
	if _, err := os.Lstat(dir); !os.IsNotExist(err) {
		t.Fatalf("read-only operations must not create vault dir, stat err = %v", err)
	}
	if kp.gets != 0 || kp.creates != 0 {
		t.Fatalf("read-only operations on missing vault must not touch Keychain, got gets=%d creates=%d", kp.gets, kp.creates)
	}
}

func TestVaultBackend_RoundTripAndPermissions(t *testing.T) {
	kp := &memMasterKeyProvider{}
	vb, dir := newTestVaultBackend(t, kp)
	ctx := t.Context()

	mustSet(t, vb, "api_key", "sk-secret-value-123")
	mustSet(t, vb, "meta/api_key", `{"v":2,"expires_at":"2030-01-01T00:00:00Z"}`)

	// Verify directory 0700 and vault.enc 0600, and plaintext never appears on disk.
	dirInfo, err := os.Lstat(dir)
	if err != nil {
		t.Fatalf("stat vault dir: %v", err)
	}
	if got := dirInfo.Mode().Perm(); got != 0o700 {
		t.Errorf("vault dir mode = %04o, want 0700", got)
	}
	vaultPath := filepath.Join(dir, vaultFileName)
	fileInfo, err := os.Lstat(vaultPath)
	if err != nil {
		t.Fatalf("stat vault.enc: %v", err)
	}
	if got := fileInfo.Mode().Perm(); got != 0o600 {
		t.Errorf("vault.enc mode = %04o, want 0600", got)
	}
	rawDisk, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatalf("read vault.enc: %v", err)
	}
	if bytes.Contains(rawDisk, []byte("sk-secret-value-123")) || bytes.Contains(rawDisk, []byte("api_key")) {
		t.Fatalf("SECURITY VIOLATION: plaintext secret or key name appeared in vault.enc")
	}

	got, err := vb.Get(ctx, "api_key")
	if err != nil {
		t.Fatalf("Get api_key: %v", err)
	}
	if string(got.Bytes()) != "sk-secret-value-123" {
		t.Errorf("Get = %q, want sk-secret-value-123", got.Bytes())
	}
	got.Destroy()

	// Overwrite rotates ciphertext (fresh nonce) and updates value.
	mustSet(t, vb, "api_key", "sk-rotated-456")
	rawDisk2, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(rawDisk, rawDisk2) {
		t.Error("vault.enc bytes unchanged across write; nonce may be reused")
	}
	got2, err := vb.Get(ctx, "api_key")
	if err != nil {
		t.Fatalf("Get after overwrite: %v", err)
	}
	if string(got2.Bytes()) != "sk-rotated-456" {
		t.Errorf("Get after overwrite = %q, want sk-rotated-456", got2.Bytes())
	}
	got2.Destroy()

	keys, err := vb.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	wantKeys := []string{"api_key", "meta/api_key"}
	if !slices.Equal(keys, wantKeys) {
		t.Errorf("List = %v, want %v", keys, wantKeys)
	}

	if err := vb.Delete(ctx, "api_key"); err != nil {
		t.Fatalf("Delete api_key: %v", err)
	}
	if _, err := vb.Get(ctx, "api_key"); !errors.Is(err, ErrSecretNotFound) {
		t.Errorf("Get after Delete = %v, want ErrSecretNotFound", err)
	}
	if err := vb.Delete(ctx, "api_key"); !errors.Is(err, ErrSecretNotFound) {
		t.Errorf("Delete missing = %v, want ErrSecretNotFound", err)
	}
	if kp.creates != 1 {
		t.Errorf("master key created %d times, want 1", kp.creates)
	}
}

func TestVaultBackend_FailsClosedWhenMasterKeyMissingForExistingVault(t *testing.T) {
	kp := &memMasterKeyProvider{}
	vb, _ := newTestVaultBackend(t, kp)
	ctx := t.Context()

	mustSet(t, vb, "existing", "val-1")

	// Simulate master key deleted from Keychain while vault.enc remains on disk.
	kp.mu.Lock()
	kp.key = nil
	kp.mu.Unlock()

	if _, err := vb.Get(ctx, "existing"); err == nil || !strings.Contains(err.Error(), "master key is missing") {
		t.Fatalf("Get with missing key = %v, want missing master key error", err)
	}
	if _, err := vb.List(ctx); err == nil || !strings.Contains(err.Error(), "master key is missing") {
		t.Fatalf("List with missing key = %v, want missing master key error", err)
	}
	buf, err := NewBufferFromBytes([]byte("new-val"))
	if err != nil {
		t.Fatal(err)
	}
	defer buf.Destroy()
	if err := vb.Set(ctx, "other", buf); err == nil || !strings.Contains(err.Error(), "refusing to generate a new key") {
		t.Fatalf("Set with missing key = %v, want fail-closed refusal", err)
	}
	if kp.creates != 1 {
		t.Fatalf("must not create a replacement key when vault.enc exists; creates=%d", kp.creates)
	}
}

func TestVaultBackend_TamperedOrWrongKeyFailsClosed(t *testing.T) {
	kp := &memMasterKeyProvider{}
	vb, dir := newTestVaultBackend(t, kp)
	ctx := t.Context()

	mustSet(t, vb, "token", "secret-token")
	vaultPath := filepath.Join(dir, vaultFileName)
	orig, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatal(err)
	}

	// Flip a byte in ciphertext -> GCM authentication must fail.
	tampered := bytes.Clone(orig)
	tampered[len(tampered)-1] ^= 0xff
	if err := os.WriteFile(vaultPath, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := vb.Get(ctx, "token"); err == nil {
		t.Fatal("Get succeeded on tampered ciphertext")
	}

	// Flip header version byte (AAD) -> GCM authentication must fail.
	tamperedAAD := bytes.Clone(orig)
	tamperedAAD[len(vaultMagic)] = 99
	if err := os.WriteFile(vaultPath, tamperedAAD, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := vb.Get(ctx, "token"); err == nil {
		t.Fatal("Get succeeded on tampered version header")
	}

	// Restore valid file and swap master key -> must fail.
	if err := os.WriteFile(vaultPath, orig, 0o600); err != nil {
		t.Fatal(err)
	}
	wrongKey := make([]byte, vaultKeyLen)
	_, _ = rand.Read(wrongKey)
	kp.mu.Lock()
	kp.key = wrongKey
	kp.mu.Unlock()
	if _, err := vb.Get(ctx, "token"); err == nil {
		t.Fatal("Get succeeded with wrong master key")
	}
}

func TestVaultBackend_MasterKeyCreateRaceRecovers(t *testing.T) {
	raceKey := make([]byte, vaultKeyLen)
	if _, err := rand.Read(raceKey); err != nil {
		t.Fatal(err)
	}
	kp := &memMasterKeyProvider{createRaceKey: raceKey}
	vb, _ := newTestVaultBackend(t, kp)
	ctx := t.Context()

	mustSet(t, vb, "race_secret", "winner-value")

	got, err := vb.Get(ctx, "race_secret")
	if err != nil {
		t.Fatalf("Get after create race: %v", err)
	}
	defer got.Destroy()
	if string(got.Bytes()) != "winner-value" {
		t.Fatalf("got %q, want winner-value", got.Bytes())
	}
}

func TestVaultBackend_RefusesSymlinks(t *testing.T) {
	ctx := t.Context()

	// Symlink vault directory.
	root := t.TempDir()
	realDir := filepath.Join(root, "real")
	if err := os.MkdirAll(realDir, 0o700); err != nil {
		t.Fatal(err)
	}
	linkDir := filepath.Join(root, "link-dir")
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Fatal(err)
	}
	vbDir := newVaultBackend("keychain-vault", func() (string, error) { return linkDir, nil }, &memMasterKeyProvider{})
	buf, err := NewBufferFromBytes([]byte("val"))
	if err != nil {
		t.Fatal(err)
	}
	defer buf.Destroy()
	if err := vbDir.Set(ctx, "k", buf); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("Set into symlink vault dir = %v, want symlink error", err)
	}

	// Symlink vault.enc file.
	vbFile, dir := newTestVaultBackend(t, &memMasterKeyProvider{})
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "decoy")
	if err := os.WriteFile(target, []byte("decoy"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, vaultFileName)); err != nil {
		t.Fatal(err)
	}
	if _, err := vbFile.Get(ctx, "k"); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("Get from symlink vault.enc = %v, want symlink error", err)
	}
	if err := vbFile.Set(ctx, "k", buf); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("Set to symlink vault.enc = %v, want symlink error", err)
	}
}

func TestVaultBackend_ConcurrentAccess(t *testing.T) {
	kp := &memMasterKeyProvider{}
	dir := filepath.Join(t.TempDir(), "concurrent")
	ctx := t.Context()

	const writers = 6
	var wg sync.WaitGroup
	errs := make(chan error, writers*2)

	for i := range writers {
		wg.Go(func() {
			// Separate vaultBackend instance per goroutine to exercise flock
			// across distinct fds in addition to the in-process RWMutex.
			vb := newVaultBackend("keychain-vault", func() (string, error) { return dir, nil }, kp)
			name := fmt.Sprintf("secret_%d", i)
			val := fmt.Sprintf("value_%d", i)
			b, err := NewBufferFromBytes([]byte(val))
			if err != nil {
				errs <- err
				return
			}
			defer b.Destroy()
			if err := vb.Set(ctx, name, b); err != nil {
				errs <- err
				return
			}
			got, err := vb.Get(ctx, name)
			if err != nil {
				errs <- err
				return
			}
			defer got.Destroy()
			if string(got.Bytes()) != val {
				errs <- fmt.Errorf("got %q for %s, want %q", got.Bytes(), name, val)
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent vault error: %v", err)
	}

	vb := newVaultBackend("keychain-vault", func() (string, error) { return dir, nil }, kp)
	keys, err := vb.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(keys) != writers {
		t.Fatalf("List count = %d (%v), want %d", len(keys), keys, writers)
	}
}
