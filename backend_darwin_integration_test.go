//go:build darwin && integration

package main

import (
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	gokeychain "github.com/99designs/go-keychain"
	"github.com/99designs/keyring"
)

// newTestKeychainFile creates a hermetic, unlocked throwaway keychain file in
// t.TempDir() so integration tests exercise real macOS Security.framework paths
// without ever touching the user's login keychain.
func newTestKeychainFile(t *testing.T) (path, password string) {
	t.Helper()
	path = filepath.Join(t.TempDir(), "opq-test.keychain")
	password = "opq-test-pw"
	if _, err := gokeychain.NewKeychain(path, password); err != nil {
		t.Fatalf("create throwaway keychain: %v", err)
	}
	if err := gokeychain.UnlockAtPath(path, password); err != nil {
		t.Fatalf("unlock throwaway keychain: %v", err)
	}
	return path, password
}

// newTestLegacyKeychainBackend builds a legacy keyringBackend over a throwaway
// keychain file in a temp dir. Run with: go test -tags integration -run Keychain.
func newTestLegacyKeychainBackend(t *testing.T) (*keyringBackend, string) {
	t.Helper()
	base := filepath.Join(t.TempDir(), "opq-legacy-test")
	kr, err := keyring.Open(keyring.Config{
		ServiceName:                    serviceName,
		AllowedBackends:                []keyring.BackendType{keyring.KeychainBackend},
		KeychainName:                   base, // absolute -> <base>.keychain
		KeychainTrustApplication:       true,
		KeychainAccessibleWhenUnlocked: true,
		KeychainPasswordFunc:           func(string) (string, error) { return "opq-test-pw", nil },
	})
	if err != nil {
		t.Fatalf("open test legacy keychain: %v", err)
	}
	return &keyringBackend{kr: kr, name: "keychain-legacy-test"}, base + ".keychain"
}

func TestKeychainLegacyBackend_RoundTrip(t *testing.T) {
	ctx := t.Context()
	b, _ := newTestLegacyKeychainBackend(t)

	if _, err := b.Get(ctx, "api_key"); !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("Get before Set: err = %v, want ErrSecretNotFound", err)
	}

	val, err := NewBufferFromBytes([]byte("sk-secret-123"))
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Set(ctx, "api_key", val); err != nil {
		t.Fatalf("Set: %v", err)
	}
	val.Destroy()

	got, err := b.Get(ctx, "api_key")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got.Bytes()) != "sk-secret-123" {
		t.Errorf("Get returned %q, want sk-secret-123", got.Bytes())
	}
	got.Destroy()

	if err := b.Delete(ctx, "api_key"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := b.Get(ctx, "api_key"); !errors.Is(err, ErrSecretNotFound) {
		t.Errorf("Get after Delete: err = %v, want ErrSecretNotFound", err)
	}
}

func TestKeychainVaultBackend_RoundTrip(t *testing.T) {
	ctx := t.Context()
	kcPath, _ := newTestKeychainFile(t)
	vDir := filepath.Join(t.TempDir(), "vault")

	store := &keychainMasterKeyStore{
		keychainPath: kcPath,
		service:      vaultMasterKeyService,
		account:      vaultMasterKeyAccount,
	}
	vb := newVaultBackend("keychain-vault-test", func() (string, error) { return vDir, nil }, store)

	if _, err := vb.Get(ctx, "api_key"); !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("Get before Set: err = %v, want ErrSecretNotFound", err)
	}

	val, err := NewBufferFromBytes([]byte("sk-vault-secret-123"))
	if err != nil {
		t.Fatal(err)
	}
	if err := vb.Set(ctx, "api_key", val); err != nil {
		t.Fatalf("Set: %v", err)
	}
	val.Destroy()

	got, err := vb.Get(ctx, "api_key")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got.Bytes()) != "sk-vault-secret-123" {
		t.Errorf("Get returned %q, want sk-vault-secret-123", got.Bytes())
	}
	got.Destroy()

	// Duplicate Create must report ErrMasterKeyExists.
	key, err := store.Get(ctx)
	if err != nil {
		t.Fatalf("store.Get: %v", err)
	}
	defer key.Destroy()
	if err := store.Create(ctx, key); !errors.Is(err, ErrMasterKeyExists) {
		t.Fatalf("duplicate Create = %v, want ErrMasterKeyExists", err)
	}

	keys, err := vb.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(keys) != 1 || keys[0] != "api_key" {
		t.Errorf("List = %v, want [api_key]", keys)
	}

	if err := vb.Delete(ctx, "api_key"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := vb.Get(ctx, "api_key"); !errors.Is(err, ErrSecretNotFound) {
		t.Errorf("Get after Delete: err = %v, want ErrSecretNotFound", err)
	}
}

// TestKeychainVault_CrossBinaryZeroPrompt proves empirically on macOS that:
//  1. A separately compiled binary with a DIFFERENT ad-hoc CDHash (simulating
//     `brew upgrade opq` or `go build`) reads the open-ACL master key from the
//     keychain with SecKeychainSetUserInteractionAllowed(false) -> ZERO prompts.
//  2. Negative control: the exact same separate binary reading a legacy
//     per-app-ACL item from the same keychain with user interaction disabled
//     fails with errSecInteractionNotAllowed (-25308), proving macOS would have
//     popped a password dialog under the old design.
func TestKeychainVault_CrossBinaryZeroPrompt(t *testing.T) {
	ctx := t.Context()
	kcPath, kcPass := newTestKeychainFile(t)
	vDir := filepath.Join(t.TempDir(), "vault")

	// 1. Write a vault secret via the test binary (creates open-ACL master key).
	store := &keychainMasterKeyStore{
		keychainPath: kcPath,
		service:      vaultMasterKeyService,
		account:      vaultMasterKeyAccount,
	}
	vb := newVaultBackend("keychain-vault-test", func() (string, error) { return vDir, nil }, store)
	val, err := NewBufferFromBytes([]byte("sk-cross-binary-ok"))
	if err != nil {
		t.Fatal(err)
	}
	if err := vb.Set(ctx, "api_key", val); err != nil {
		t.Fatalf("vault Set: %v", err)
	}
	val.Destroy()

	masterKey, err := store.Get(ctx)
	if err != nil {
		t.Fatalf("master key Get: %v", err)
	}
	wantHex := hex.EncodeToString(masterKey.Bytes())
	masterKey.Destroy()

	// 2. Write a legacy per-binary-ACL item into the exact same throwaway keychain
	//    as a negative control.
	legacyItem := gokeychain.NewItem()
	legacyItem.SetSecClass(gokeychain.SecClassGenericPassword)
	legacyItem.SetService(serviceName)
	legacyItem.SetAccount("legacy_only")
	legacyItem.SetLabel("opq:legacy_only")
	legacyItem.SetData([]byte("legacy-secret"))
	legacyItem.UseKeychain(gokeychain.NewWithPath(kcPath))
	legacyItem.SetAccessible(gokeychain.AccessibleWhenUnlocked)
	legacyItem.SetAccess(&gokeychain.Access{Label: "opq:legacy_only", TrustedApplications: nil})
	if err := gokeychain.AddItem(legacyItem); err != nil {
		t.Fatalf("add legacy control item: %v", err)
	}

	// 3. Compile a brand-new standalone binary with a distinct ad-hoc CDHash.
	helperDir := t.TempDir()
	helperSrc := filepath.Join(helperDir, "main.go")
	helperBin := filepath.Join(helperDir, "reader-bin")
	const src = `package main

/*
#cgo LDFLAGS: -framework CoreFoundation -framework Security
#cgo CFLAGS: -Wno-deprecated-declarations
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdlib.h>
#include <string.h>

static OSStatus read_item_noninteractive(
	const char *kcPath, const char *pw, const char *service, const char *account,
	void **outData, CFIndex *outLen
) {
	// Forbid ALL GUI prompts: if an ACL check would prompt, macOS returns
	// errSecInteractionNotAllowed (-25308) immediately.
	OSStatus st = SecKeychainSetUserInteractionAllowed(false);
	if (st != errSecSuccess) return st;

	SecKeychainRef kc = NULL;
	st = SecKeychainOpen(kcPath, &kc);
	if (st != errSecSuccess) return st;
	st = SecKeychainUnlock(kc, (UInt32)strlen(pw), pw, true);
	if (st != errSecSuccess) { CFRelease(kc); return st; }

	const void *vals[1] = { kc };
	CFArrayRef list = CFArrayCreate(kCFAllocatorDefault, vals, 1, &kCFTypeArrayCallBacks);
	CFStringRef cfSvc = CFStringCreateWithCString(kCFAllocatorDefault, service, kCFStringEncodingUTF8);
	CFStringRef cfAcc = CFStringCreateWithCString(kCFAllocatorDefault, account, kCFStringEncodingUTF8);
	CFMutableDictionaryRef q = CFDictionaryCreateMutable(
		kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks
	);
	CFDictionarySetValue(q, kSecClass, kSecClassGenericPassword);
	CFDictionarySetValue(q, kSecAttrService, cfSvc);
	CFDictionarySetValue(q, kSecAttrAccount, cfAcc);
	CFDictionarySetValue(q, kSecMatchLimit, kSecMatchLimitOne);
	CFDictionarySetValue(q, kSecReturnData, kCFBooleanTrue);
	CFDictionarySetValue(q, kSecMatchSearchList, list);

	CFTypeRef res = NULL;
	st = SecItemCopyMatching(q, &res);
	if (st == errSecSuccess && res != NULL && CFGetTypeID(res) == CFDataGetTypeID()) {
		CFIndex n = CFDataGetLength((CFDataRef)res);
		void *buf = malloc((size_t)n);
		memcpy(buf, CFDataGetBytePtr((CFDataRef)res), (size_t)n);
		*outData = buf;
		*outLen = n;
	}
	if (res) CFRelease(res);
	CFRelease(q);
	CFRelease(cfSvc);
	CFRelease(cfAcc);
	CFRelease(list);
	CFRelease(kc);
	return st;
}
*/
import "C"
import (
	"fmt"
	"os"
	"unsafe"
)

func main() {
	cPath := C.CString(os.Args[1])
	cPw := C.CString(os.Args[2])
	cSvc := C.CString(os.Args[3])
	cAcc := C.CString(os.Args[4])
	defer C.free(unsafe.Pointer(cPath))
	defer C.free(unsafe.Pointer(cPw))
	defer C.free(unsafe.Pointer(cSvc))
	defer C.free(unsafe.Pointer(cAcc))

	var data unsafe.Pointer
	var n C.CFIndex
	st := C.read_item_noninteractive(cPath, cPw, cSvc, cAcc, &data, &n)
	if data != nil {
		defer C.free(data)
	}
	if st != C.errSecSuccess {
		fmt.Fprintf(os.Stderr, "OSStatus=%d\n", int(st))
		os.Exit(2)
	}
	os.Stdout.Write(C.GoBytes(data, C.int(n)))
}
`
	if err := os.WriteFile(helperSrc, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	build := exec.CommandContext(ctx, "go", "build", "-o", helperBin, helperSrc)
	build.Env = append(os.Environ(), "CGO_ENABLED=1")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("compile helper binary: %v\n%s", err, out)
	}

	// 4. Positive control: separate binary reads open-ACL vault master key with ZERO prompts!
	out, err := exec.CommandContext(ctx, helperBin, kcPath, kcPass, vaultMasterKeyService, vaultMasterKeyAccount).CombinedOutput()
	if err != nil {
		t.Fatalf("separate binary failed to read open-ACL master key without prompts: %v\noutput: %s", err, out)
	}
	if string(out) != wantHex {
		t.Fatalf("separate binary returned unexpected master key bytes (len=%d, want %d)", len(out), len(wantHex))
	}

	// 5. Negative control: separate binary reading the legacy per-binary-ACL item
	//    MUST fail with errSecAuthFailed (-25293) or errSecInteractionNotAllowed
	//    (-25308), proving prompts were genuinely disabled and the old design
	//    would have prompted here.
	negOut, negErr := exec.CommandContext(ctx, helperBin, kcPath, kcPass, serviceName, "legacy_only").CombinedOutput()
	if negErr == nil {
		t.Fatalf("expected legacy per-app-ACL item to reject a different binary when user interaction is disabled")
	}
	if !strings.Contains(string(negOut), "OSStatus=-25293") && !strings.Contains(string(negOut), "OSStatus=-25308") {
		t.Fatalf("negative control failed with unexpected output %q (want OSStatus=-25293 or -25308)", string(negOut))
	}
}
