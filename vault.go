package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"syscall"
	"time"

	"github.com/awnumar/memguard"
)

const (
	vaultFileName = "vault.enc"
	vaultLockName = "vault.lock"

	vaultMagic           = "OPQVLT"
	vaultFormatVersion   = byte(1)
	vaultCipherAES256GCM = byte(1)
	vaultHeaderLen       = len(vaultMagic) + 2 // 6 magic + 1 version + 1 cipher
	vaultNonceLen        = 12                  // standard AES-GCM 96-bit nonce
	vaultKeyLen          = 32                  // AES-256 key length
	vaultPayloadVersion  = 1

	// vaultMaxFileSize bounds vault.enc reads to defend against an externally
	// planted or corrupt huge file exhausting memory. Matches auditReadCap.
	vaultMaxFileSize = 32 * 1024 * 1024
)

var (
	// ErrMasterKeyNotFound is returned by masterKeyProvider.Get when no vault
	// master key has been provisioned yet.
	ErrMasterKeyNotFound = errors.New("vault master key not found")

	// ErrMasterKeyExists is returned by masterKeyProvider.Create when a master
	// key already exists (e.g. a concurrent process provisioned it first).
	ErrMasterKeyExists = errors.New("vault master key already exists")
)

// masterKeyProvider supplies the 32-byte AES-256 master key used to encrypt and
// authenticate vault.enc. On macOS this is backed by a single open-ACL item in
// the login Keychain; tests inject an in-memory provider.
type masterKeyProvider interface {
	Get(ctx context.Context) (*memguard.LockedBuffer, error)
	Create(ctx context.Context, key *memguard.LockedBuffer) error
}

// vaultPayload is the plaintext JSON document encrypted inside vault.enc.
// Entries holds both secret values and companion "meta/<name>" policy items so
// every Backend invariant (including List returning raw keys) holds unchanged.
type vaultPayload struct {
	V       int               `json:"v"`
	Entries map[string][]byte `json:"entries"`
}

func wipeVaultPayload(p *vaultPayload) {
	if p == nil {
		return
	}
	for k, v := range p.Entries {
		memguard.WipeBytes(v)
		delete(p.Entries, k)
	}
}

// vaultDir resolves <OS-account-home>/.local/share/opq using policyHomeDir (the
// OS account database, never HOME or XDG_DATA_HOME), so CLI and MCP clients
// with different environments always address the exact same vault and lock.
func vaultDir() (string, error) {
	home, err := policyHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".local", "share", "opq"), nil
}

// vaultBackend implements Backend over a single AES-256-GCM encrypted local
// file (vault.enc) whose 32-byte master key comes from masterKeyProvider.
//
// Locking order: callers holding policy.lock (outer) may invoke vaultBackend
// methods which acquire vault.lock (inner). vaultBackend never touches
// policy.lock, so the lock hierarchy is strictly acyclic.
//
// Read-only guarantee: Get, List, and Delete on a missing vault never create
// directories, lock files, vault.enc, or a master key in the Keychain.
type vaultBackend struct {
	name    string
	dirFunc func() (string, error)
	keys    masterKeyProvider
	mu      sync.RWMutex
}

func newVaultBackend(name string, dirFunc func() (string, error), keys masterKeyProvider) *vaultBackend {
	if dirFunc == nil {
		dirFunc = vaultDir
	}
	return &vaultBackend{
		name:    name,
		dirFunc: dirFunc,
		keys:    keys,
	}
}

func (b *vaultBackend) Name() string { return b.name }

func (b *vaultBackend) Get(ctx context.Context, name string) (*Buffer, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	dir, err := b.dirFunc()
	if err != nil {
		return nil, err
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	unlock, err := tryReadOnlyVaultLock(ctx, dir)
	if err != nil {
		return nil, err
	}
	defer unlock()

	payload, exists, err := b.loadPayloadLocked(ctx, filepath.Join(dir, vaultFileName))
	if err != nil {
		return nil, err
	}
	defer wipeVaultPayload(payload)
	if !exists {
		return nil, ErrSecretNotFound
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	raw, ok := payload.Entries[name]
	if !ok {
		return nil, ErrSecretNotFound
	}
	// Move into a locked Buffer (which wipes raw in place).
	delete(payload.Entries, name)
	buf, err := NewBufferFromBytes(raw)
	if err != nil {
		return nil, fmt.Errorf("vault get: %w", err)
	}
	return buf, nil
}

func (b *vaultBackend) List(ctx context.Context) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	dir, err := b.dirFunc()
	if err != nil {
		return nil, err
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	unlock, err := tryReadOnlyVaultLock(ctx, dir)
	if err != nil {
		return nil, err
	}
	defer unlock()

	payload, exists, err := b.loadPayloadLocked(ctx, filepath.Join(dir, vaultFileName))
	if err != nil {
		return nil, err
	}
	defer wipeVaultPayload(payload)
	if !exists {
		return []string{}, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	keys := slices.Sorted(maps.Keys(payload.Entries))
	if keys == nil {
		return []string{}, nil
	}
	return keys, nil
}

func (b *vaultBackend) Set(ctx context.Context, name string, value *Buffer) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if value == nil || !value.IsAlive() {
		return errors.New("set: empty value")
	}
	dir, err := b.dirFunc()
	if err != nil {
		return err
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	unlock, err := lockVaultExclusive(ctx, dir)
	if err != nil {
		return err
	}
	defer unlock()

	vaultPath := filepath.Join(dir, vaultFileName)
	ciphertext, exists, err := readVaultFile(vaultPath)
	if err != nil {
		return err
	}

	key, err := b.ensureMasterKeyLocked(ctx, vaultPath, exists)
	if err != nil {
		return err
	}
	defer key.Destroy()

	var payload *vaultPayload
	if exists {
		payload, err = decryptVault(key.Bytes(), ciphertext)
		if err != nil {
			return err
		}
	} else {
		payload = &vaultPayload{
			V:       vaultPayloadVersion,
			Entries: make(map[string][]byte),
		}
	}
	defer wipeVaultPayload(payload)

	if err := ctx.Err(); err != nil {
		return err
	}

	if old, ok := payload.Entries[name]; ok {
		memguard.WipeBytes(old)
	}
	payload.Entries[name] = bytes.Clone(value.Bytes())

	sealed, err := encryptVault(key.Bytes(), payload)
	if err != nil {
		return err
	}
	if err := writeVaultFileAtomic(dir, vaultPath, sealed); err != nil {
		return err
	}
	return ctx.Err()
}

func (b *vaultBackend) Delete(ctx context.Context, name string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	dir, err := b.dirFunc()
	if err != nil {
		return err
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	vaultPath := filepath.Join(dir, vaultFileName)
	// Fast read-only check so Delete on a missing vault never creates dirs or locks.
	if _, err := os.Lstat(vaultPath); os.IsNotExist(err) {
		return ErrSecretNotFound
	}

	unlock, err := lockVaultExclusive(ctx, dir)
	if err != nil {
		return err
	}
	defer unlock()

	ciphertext, exists, err := readVaultFile(vaultPath)
	if err != nil {
		return err
	}
	if !exists {
		return ErrSecretNotFound
	}

	key, err := b.keys.Get(ctx)
	if err != nil {
		if errors.Is(err, ErrMasterKeyNotFound) {
			return fmt.Errorf("vault file %q exists but its Keychain master key is missing", vaultPath)
		}
		return fmt.Errorf("load vault master key: %w", err)
	}
	defer key.Destroy()
	if key.Size() != vaultKeyLen {
		return fmt.Errorf("vault master key has invalid length %d (want %d)", key.Size(), vaultKeyLen)
	}

	payload, err := decryptVault(key.Bytes(), ciphertext)
	if err != nil {
		return err
	}
	defer wipeVaultPayload(payload)

	old, ok := payload.Entries[name]
	if !ok {
		return ErrSecretNotFound
	}
	memguard.WipeBytes(old)
	delete(payload.Entries, name)

	if err := ctx.Err(); err != nil {
		return err
	}

	sealed, err := encryptVault(key.Bytes(), payload)
	if err != nil {
		return err
	}
	if err := writeVaultFileAtomic(dir, vaultPath, sealed); err != nil {
		return err
	}
	return ctx.Err()
}

// loadPayloadLocked reads and decrypts vault.enc. Returns (nil, false, nil) if
// vault.enc does not exist yet (never touching Keychain on a fresh install).
func (b *vaultBackend) loadPayloadLocked(ctx context.Context, vaultPath string) (*vaultPayload, bool, error) {
	ciphertext, exists, err := readVaultFile(vaultPath)
	if err != nil {
		return nil, false, err
	}
	if !exists {
		return nil, false, nil
	}

	key, err := b.keys.Get(ctx)
	if err != nil {
		if errors.Is(err, ErrMasterKeyNotFound) {
			return nil, true, fmt.Errorf("vault file %q exists but its Keychain master key is missing", vaultPath)
		}
		return nil, true, fmt.Errorf("load vault master key: %w", err)
	}
	defer key.Destroy()
	if key.Size() != vaultKeyLen {
		return nil, true, fmt.Errorf("vault master key has invalid length %d (want %d)", key.Size(), vaultKeyLen)
	}

	payload, err := decryptVault(key.Bytes(), ciphertext)
	if err != nil {
		return nil, true, err
	}
	return payload, true, nil
}

// ensureMasterKeyLocked fetches the existing master key or creates a fresh
// 256-bit key if no vault exists yet. If vault.enc already exists on disk while
// the Keychain master key is absent, it fails closed instead of silently
// overwriting the key and stranding existing secrets.
func (b *vaultBackend) ensureMasterKeyLocked(ctx context.Context, vaultPath string, vaultExisted bool) (*memguard.LockedBuffer, error) {
	key, err := b.keys.Get(ctx)
	if err == nil {
		if key.Size() != vaultKeyLen {
			key.Destroy()
			return nil, fmt.Errorf("vault master key has invalid length %d (want %d)", key.Size(), vaultKeyLen)
		}
		return key, nil
	}
	if !errors.Is(err, ErrMasterKeyNotFound) {
		return nil, fmt.Errorf("load vault master key: %w", err)
	}
	if vaultExisted {
		return nil, fmt.Errorf("vault file %q exists but its Keychain master key is missing; refusing to generate a new key and overwrite existing secrets", vaultPath)
	}

	raw := make([]byte, vaultKeyLen)
	if _, err := rand.Read(raw); err != nil {
		memguard.WipeBytes(raw)
		return nil, fmt.Errorf("generate vault master key: %w", err)
	}
	fresh := memguard.NewBuffer(vaultKeyLen)
	fresh.Move(raw) // copies raw into mlocked pages and zeroes raw

	if err := b.keys.Create(ctx, fresh); err != nil {
		fresh.Destroy()
		if errors.Is(err, ErrMasterKeyExists) {
			// Another process created the key concurrently; load it.
			existing, gerr := b.keys.Get(ctx)
			if gerr != nil {
				return nil, fmt.Errorf("reload vault master key after race: %w", gerr)
			}
			if existing.Size() != vaultKeyLen {
				existing.Destroy()
				return nil, fmt.Errorf("vault master key has invalid length %d (want %d)", existing.Size(), vaultKeyLen)
			}
			return existing, nil
		}
		return nil, fmt.Errorf("store vault master key: %w", err)
	}
	return fresh, nil
}

func encryptVault(key []byte, payload *vaultPayload) ([]byte, error) {
	if len(key) != vaultKeyLen {
		return nil, fmt.Errorf("vault encrypt: invalid key length %d", len(key))
	}
	if payload.V == 0 {
		payload.V = vaultPayloadVersion
	}
	if payload.Entries == nil {
		payload.Entries = map[string][]byte{}
	}

	plain, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal vault payload: %w", err)
	}
	defer memguard.WipeBytes(plain)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("init vault cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("init vault gcm: %w", err)
	}

	header := make([]byte, vaultHeaderLen)
	copy(header, vaultMagic)
	header[len(vaultMagic)] = vaultFormatVersion
	header[len(vaultMagic)+1] = vaultCipherAES256GCM

	nonce := make([]byte, vaultNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate vault nonce: %w", err)
	}

	out := make([]byte, 0, vaultHeaderLen+vaultNonceLen+len(plain)+gcm.Overhead())
	out = append(out, header...)
	out = append(out, nonce...)
	out = gcm.Seal(out, nonce, plain, header)
	return out, nil
}

func decryptVault(key, data []byte) (*vaultPayload, error) {
	if len(key) != vaultKeyLen {
		return nil, fmt.Errorf("vault decrypt: invalid key length %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("init vault cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("init vault gcm: %w", err)
	}

	minLen := vaultHeaderLen + vaultNonceLen + gcm.Overhead()
	if len(data) < minLen {
		return nil, errors.New("corrupt vault file: truncated")
	}
	header := data[:vaultHeaderLen]
	if string(header[:len(vaultMagic)]) != vaultMagic {
		return nil, errors.New("corrupt vault file: invalid header magic")
	}
	if header[len(vaultMagic)] != vaultFormatVersion {
		return nil, fmt.Errorf("unsupported vault format version %d", header[len(vaultMagic)])
	}
	if header[len(vaultMagic)+1] != vaultCipherAES256GCM {
		return nil, fmt.Errorf("unsupported vault cipher %d", header[len(vaultMagic)+1])
	}

	nonce := data[vaultHeaderLen : vaultHeaderLen+vaultNonceLen]
	ciphertext := data[vaultHeaderLen+vaultNonceLen:]

	plain, err := gcm.Open(nil, nonce, ciphertext, header)
	if err != nil {
		return nil, fmt.Errorf("decrypt vault failed (wrong master key or tampered file): %w", err)
	}
	defer memguard.WipeBytes(plain)

	var payload vaultPayload
	if err := json.Unmarshal(plain, &payload); err != nil {
		return nil, fmt.Errorf("parse vault payload: %w", err)
	}
	if payload.V != vaultPayloadVersion {
		wipeVaultPayload(&payload)
		return nil, fmt.Errorf("unsupported vault payload version %d", payload.V)
	}
	if payload.Entries == nil {
		payload.Entries = map[string][]byte{}
	}
	return &payload, nil
}

// prepareVaultDir creates dir with 0700 permissions and verifies via an
// O_DIRECTORY|O_NOFOLLOW fd that it is a real directory, not a symlink.
func prepareVaultDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("mkdir vault dir: %w", err)
	}
	if li, err := os.Lstat(dir); err == nil && li.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("vault dir %q is a symlink, refusing", dir)
	}
	fd, err := syscall.Open(dir, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return fmt.Errorf("vault dir %q is a symlink, refusing", dir)
		}
		if errors.Is(err, syscall.ENOTDIR) {
			return fmt.Errorf("vault dir %q is not a directory, refusing", dir)
		}
		return fmt.Errorf("open vault dir: %w", err)
	}
	defer syscall.Close(fd)
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return fmt.Errorf("fstat vault dir: %w", err)
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		return fmt.Errorf("vault dir %q is not a directory, refusing", dir)
	}
	if err := syscall.Fchmod(fd, 0o700); err != nil {
		return fmt.Errorf("fchmod vault dir: %w", err)
	}
	return nil
}

func readVaultFile(path string) ([]byte, bool, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		if errors.Is(err, syscall.ELOOP) {
			return nil, false, fmt.Errorf("vault file %q is a symlink, refusing", path)
		}
		return nil, false, fmt.Errorf("open vault file: %w", err)
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return nil, false, fmt.Errorf("stat vault file: %w", err)
	}
	if !st.Mode().IsRegular() {
		return nil, false, fmt.Errorf("vault file %q is not a regular file", path)
	}
	if st.Size() > vaultMaxFileSize {
		return nil, false, fmt.Errorf("vault file exceeds %d byte limit", vaultMaxFileSize)
	}

	data, err := io.ReadAll(io.LimitReader(f, vaultMaxFileSize+1))
	if err != nil {
		return nil, false, fmt.Errorf("read vault file: %w", err)
	}
	if int64(len(data)) > vaultMaxFileSize {
		return nil, false, fmt.Errorf("vault file exceeds %d byte limit", vaultMaxFileSize)
	}
	return data, true, nil
}

func writeVaultFileAtomic(dir, path string, data []byte) error {
	if err := prepareVaultDir(dir); err != nil {
		return err
	}
	if li, err := os.Lstat(path); err == nil {
		if li.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("vault file %q is a symlink, refusing", path)
		}
		if !li.Mode().IsRegular() {
			return fmt.Errorf("vault file %q is not a regular file", path)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat vault file: %w", err)
	}

	tmp, err := os.CreateTemp(dir, ".vault.enc.tmp-*")
	if err != nil {
		return fmt.Errorf("create temp vault file: %w", err)
	}
	tmpPath := tmp.Name()
	cleanupTmp := true
	defer func() {
		if cleanupTmp {
			_ = os.Remove(tmpPath)
		}
	}()

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp vault file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp vault file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("fsync temp vault file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp vault file: %w", err)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("replace vault file: %w", err)
	}
	cleanupTmp = false

	// Best-effort parent directory sync for rename durability.
	if dfd, err := syscall.Open(dir, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0); err == nil {
		_ = syscall.Fsync(dfd)
		_ = syscall.Close(dfd)
	}
	return nil
}

// lockVaultExclusive creates dir and vault.lock if needed and acquires LOCK_EX
// on a fresh fd so concurrent callers (across processes or vaultBackend
// instances) serialize writes safely.
func lockVaultExclusive(ctx context.Context, dir string) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := prepareVaultDir(dir); err != nil {
		return nil, err
	}
	lockPath := filepath.Join(dir, vaultLockName)
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("vault lock %q is a symlink, refusing", lockPath)
		}
		return nil, fmt.Errorf("open vault lock: %w", err)
	}
	fail := func(err error) (func(), error) { _ = f.Close(); return nil, err }
	st, err := f.Stat()
	if err != nil {
		return fail(err)
	}
	if !st.Mode().IsRegular() {
		return fail(errors.New("vault lock is not a regular file"))
	}
	if err := f.Chmod(0o600); err != nil {
		return fail(err)
	}
	if err := flockVaultContext(ctx, int(f.Fd()), syscall.LOCK_EX); err != nil {
		return fail(err)
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}

// tryReadOnlyVaultLock acquires LOCK_SH on vault.lock if it already exists,
// without creating directories or lock files on a fresh install.
func tryReadOnlyVaultLock(ctx context.Context, dir string) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	lockPath := filepath.Join(dir, vaultLockName)
	f, err := os.OpenFile(lockPath, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return func() {}, nil
		}
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("vault lock %q is a symlink, refusing", lockPath)
		}
		return nil, fmt.Errorf("open vault lock: %w", err)
	}
	fail := func(err error) (func(), error) { _ = f.Close(); return nil, err }
	st, err := f.Stat()
	if err != nil {
		return fail(err)
	}
	if !st.Mode().IsRegular() {
		return fail(errors.New("vault lock is not a regular file"))
	}
	if err := flockVaultContext(ctx, int(f.Fd()), syscall.LOCK_SH); err != nil {
		return fail(err)
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}

func flockVaultContext(ctx context.Context, fd, mode int) error {
	for {
		err := syscall.Flock(fd, mode|syscall.LOCK_NB)
		if err == nil {
			return nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) && !errors.Is(err, syscall.EINTR) {
			return fmt.Errorf("flock vault lock: %w", err)
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
