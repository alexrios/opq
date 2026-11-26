//go:build darwin && cgo

package main

/*
#cgo LDFLAGS: -framework CoreFoundation -framework Security
#cgo CFLAGS: -Wno-deprecated-declarations

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdlib.h>
#include <string.h>

// opq_create_open_access creates a SecAccessRef whose decrypt ACL allows all
// applications running in the user's unlocked login session without triggering
// per-binary CDHash prompts (equivalent to `security add-generic-password -A`).
// This gives macOS parity with Linux Secret Service: upgrades and rebuilds of
// unsigned/ad-hoc opq binaries never invalidate access, while sandboxed child
// processes remain blocked from reading vault.enc by Seatbelt.
static OSStatus opq_create_open_access(CFStringRef label, SecAccessRef *outAccess) {
	SecAccessRef access = NULL;
	OSStatus status = SecAccessCreate(label, NULL, &access);
	if (status != errSecSuccess) {
		return status;
	}

	CFArrayRef acls = SecAccessCopyMatchingACLList(access, kSecACLAuthorizationDecrypt);
	if (acls != NULL) {
		CFIndex count = CFArrayGetCount(acls);
		for (CFIndex i = 0; i < count; i++) {
			SecACLRef acl = (SecACLRef)CFArrayGetValueAtIndex(acls, i);
			// Act bits set with Unsigned/Invalid bits clear: override system
			// defaults so ad-hoc/unsigned/rebuilt binaries never prompt.
			SecKeychainPromptSelector selector =
				kSecKeychainPromptUnsignedAct | kSecKeychainPromptInvalidAct;
			status = SecACLSetContents(acl, NULL, label, selector);
			if (status != errSecSuccess) {
				CFRelease(acls);
				CFRelease(access);
				return status;
			}
		}
		CFRelease(acls);
	}

	*outAccess = access;
	return errSecSuccess;
}

static OSStatus opq_keychain_add_master_key(
	const char *keychainPath,
	const char *service,
	const char *account,
	const char *label,
	const char *desc,
	const void *data,
	CFIndex dataLen
) {
	CFStringRef cfService = CFStringCreateWithCString(kCFAllocatorDefault, service, kCFStringEncodingUTF8);
	CFStringRef cfAccount = CFStringCreateWithCString(kCFAllocatorDefault, account, kCFStringEncodingUTF8);
	CFStringRef cfLabel   = CFStringCreateWithCString(kCFAllocatorDefault, label, kCFStringEncodingUTF8);
	CFStringRef cfDesc    = CFStringCreateWithCString(kCFAllocatorDefault, desc, kCFStringEncodingUTF8);
	CFDataRef   cfData    = CFDataCreate(kCFAllocatorDefault, (const UInt8 *)data, dataLen);

	if (!cfService || !cfAccount || !cfLabel || !cfDesc || !cfData) {
		if (cfService) CFRelease(cfService);
		if (cfAccount) CFRelease(cfAccount);
		if (cfLabel)   CFRelease(cfLabel);
		if (cfDesc)    CFRelease(cfDesc);
		if (cfData)    CFRelease(cfData);
		return errSecAllocate;
	}

	SecAccessRef access = NULL;
	OSStatus status = opq_create_open_access(cfLabel, &access);
	if (status != errSecSuccess) {
		CFRelease(cfService);
		CFRelease(cfAccount);
		CFRelease(cfLabel);
		CFRelease(cfDesc);
		CFRelease(cfData);
		return status;
	}

	SecKeychainRef kcRef = NULL;
	if (keychainPath != NULL && keychainPath[0] != '\0') {
		status = SecKeychainOpen(keychainPath, &kcRef);
		if (status != errSecSuccess) {
			CFRelease(access);
			CFRelease(cfService);
			CFRelease(cfAccount);
			CFRelease(cfLabel);
			CFRelease(cfDesc);
			CFRelease(cfData);
			return status;
		}
	}

	CFMutableDictionaryRef dict = CFDictionaryCreateMutable(
		kCFAllocatorDefault, 0,
		&kCFTypeDictionaryKeyCallBacks,
		&kCFTypeDictionaryValueCallBacks
	);
	if (!dict) {
		if (kcRef) CFRelease(kcRef);
		CFRelease(access);
		CFRelease(cfService);
		CFRelease(cfAccount);
		CFRelease(cfLabel);
		CFRelease(cfDesc);
		CFRelease(cfData);
		return errSecAllocate;
	}

	CFDictionarySetValue(dict, kSecClass, kSecClassGenericPassword);
	CFDictionarySetValue(dict, kSecAttrService, cfService);
	CFDictionarySetValue(dict, kSecAttrAccount, cfAccount);
	CFDictionarySetValue(dict, kSecAttrLabel, cfLabel);
	CFDictionarySetValue(dict, kSecAttrDescription, cfDesc);
	CFDictionarySetValue(dict, kSecValueData, cfData);
	CFDictionarySetValue(dict, kSecAttrAccessible, kSecAttrAccessibleWhenUnlocked);
	CFDictionarySetValue(dict, kSecAttrAccess, access);
	if (kcRef != NULL) {
		CFDictionarySetValue(dict, kSecUseKeychain, kcRef);
	}

	status = SecItemAdd(dict, NULL);

	CFRelease(dict);
	if (kcRef) CFRelease(kcRef);
	CFRelease(access);
	CFRelease(cfService);
	CFRelease(cfAccount);
	CFRelease(cfLabel);
	CFRelease(cfDesc);
	CFRelease(cfData);
	return status;
}

static OSStatus opq_keychain_get_master_key(
	const char *keychainPath,
	const char *service,
	const char *account,
	void **outData,
	CFIndex *outLen
) {
	*outData = NULL;
	*outLen = 0;

	CFStringRef cfService = CFStringCreateWithCString(kCFAllocatorDefault, service, kCFStringEncodingUTF8);
	CFStringRef cfAccount = CFStringCreateWithCString(kCFAllocatorDefault, account, kCFStringEncodingUTF8);
	if (!cfService || !cfAccount) {
		if (cfService) CFRelease(cfService);
		if (cfAccount) CFRelease(cfAccount);
		return errSecAllocate;
	}

	SecKeychainRef kcRef = NULL;
	CFArrayRef searchList = NULL;
	OSStatus status = errSecSuccess;
	if (keychainPath != NULL && keychainPath[0] != '\0') {
		status = SecKeychainOpen(keychainPath, &kcRef);
		if (status != errSecSuccess) {
			CFRelease(cfService);
			CFRelease(cfAccount);
			return status;
		}
		const void *values[1] = { kcRef };
		searchList = CFArrayCreate(kCFAllocatorDefault, values, 1, &kCFTypeArrayCallBacks);
		if (!searchList) {
			CFRelease(kcRef);
			CFRelease(cfService);
			CFRelease(cfAccount);
			return errSecAllocate;
		}
	}

	CFMutableDictionaryRef query = CFDictionaryCreateMutable(
		kCFAllocatorDefault, 0,
		&kCFTypeDictionaryKeyCallBacks,
		&kCFTypeDictionaryValueCallBacks
	);
	if (!query) {
		if (searchList) CFRelease(searchList);
		if (kcRef) CFRelease(kcRef);
		CFRelease(cfService);
		CFRelease(cfAccount);
		return errSecAllocate;
	}

	CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
	CFDictionarySetValue(query, kSecAttrService, cfService);
	CFDictionarySetValue(query, kSecAttrAccount, cfAccount);
	CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitOne);
	CFDictionarySetValue(query, kSecReturnData, kCFBooleanTrue);
	if (searchList != NULL) {
		CFDictionarySetValue(query, kSecMatchSearchList, searchList);
	}

	CFTypeRef result = NULL;
	status = SecItemCopyMatching(query, &result);
	if (status == errSecSuccess && result != NULL) {
		if (CFGetTypeID(result) == CFDataGetTypeID()) {
			CFDataRef dataRef = (CFDataRef)result;
			CFIndex len = CFDataGetLength(dataRef);
			if (len > 0) {
				void *buf = malloc((size_t)len);
				if (buf != NULL) {
					memcpy(buf, CFDataGetBytePtr(dataRef), (size_t)len);
					*outData = buf;
					*outLen = len;
				} else {
					status = errSecAllocate;
				}
			}
		} else {
			status = errSecDecode;
		}
		CFRelease(result);
	}

	CFRelease(query);
	if (searchList) CFRelease(searchList);
	if (kcRef) CFRelease(kcRef);
	CFRelease(cfService);
	CFRelease(cfAccount);
	return status;
}

static void opq_zero_and_free(void *ptr, CFIndex len) {
	if (ptr != NULL) {
		if (len > 0) {
			memset_s(ptr, (size_t)len, 0, (size_t)len);
		}
		free(ptr);
	}
}

// opq_keychain_delete_item removes a generic-password item by fetching its
// SecKeychainItemRef (attributes/ref only, never decrypting data) and calling
// SecKeychainItemDelete. Unlike SecItemDelete—which fails with
// errSecInvalidOwnerEdit (-25244) on legacy items created by an older binary
// CDHash—SecKeychainItemDelete succeeds across binaries with zero prompts,
// matching Apple's `/usr/bin/security delete-generic-password`.
static OSStatus opq_keychain_delete_item(
	const char *keychainPath,
	const char *service,
	const char *account
) {
	CFStringRef cfService = CFStringCreateWithCString(kCFAllocatorDefault, service, kCFStringEncodingUTF8);
	CFStringRef cfAccount = CFStringCreateWithCString(kCFAllocatorDefault, account, kCFStringEncodingUTF8);
	if (!cfService || !cfAccount) {
		if (cfService) CFRelease(cfService);
		if (cfAccount) CFRelease(cfAccount);
		return errSecAllocate;
	}

	SecKeychainRef kcRef = NULL;
	CFArrayRef searchList = NULL;
	OSStatus status = errSecSuccess;
	if (keychainPath != NULL && keychainPath[0] != '\0') {
		status = SecKeychainOpen(keychainPath, &kcRef);
		if (status != errSecSuccess) {
			CFRelease(cfService);
			CFRelease(cfAccount);
			return status;
		}
		const void *values[1] = { kcRef };
		searchList = CFArrayCreate(kCFAllocatorDefault, values, 1, &kCFTypeArrayCallBacks);
		if (!searchList) {
			CFRelease(kcRef);
			CFRelease(cfService);
			CFRelease(cfAccount);
			return errSecAllocate;
		}
	}

	CFMutableDictionaryRef query = CFDictionaryCreateMutable(
		kCFAllocatorDefault, 0,
		&kCFTypeDictionaryKeyCallBacks,
		&kCFTypeDictionaryValueCallBacks
	);
	if (!query) {
		if (searchList) CFRelease(searchList);
		if (kcRef) CFRelease(kcRef);
		CFRelease(cfService);
		CFRelease(cfAccount);
		return errSecAllocate;
	}

	CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
	CFDictionarySetValue(query, kSecAttrService, cfService);
	CFDictionarySetValue(query, kSecAttrAccount, cfAccount);
	CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitOne);
	CFDictionarySetValue(query, kSecReturnRef, kCFBooleanTrue);
	if (searchList != NULL) {
		CFDictionarySetValue(query, kSecMatchSearchList, searchList);
	}

	CFTypeRef ref = NULL;
	status = SecItemCopyMatching(query, &ref);
	if (status == errSecSuccess && ref != NULL) {
		status = SecKeychainItemDelete((SecKeychainItemRef)ref);
		CFRelease(ref);
	}

	CFRelease(query);
	if (searchList) CFRelease(searchList);
	if (kcRef) CFRelease(kcRef);
	CFRelease(cfService);
	CFRelease(cfAccount);
	return status;
}
*/
import "C"

import (
	"context"
	"encoding/hex"
	"fmt"
	"unsafe"

	"github.com/awnumar/memguard"
)

const (
	vaultMasterKeyService     = "opq-vault"
	vaultMasterKeyAccount     = "master-key"
	vaultMasterKeyLabel       = "opq vault master key"
	vaultMasterKeyDescription = "master encryption key for opq local vault"
)

type keychainMasterKeyStore struct {
	keychainPath string // empty = user's default login keychain
	service      string
	account      string
}

func defaultKeychainMasterKeyStore() (masterKeyProvider, error) {
	return &keychainMasterKeyStore{
		service: vaultMasterKeyService,
		account: vaultMasterKeyAccount,
	}, nil
}

func (s *keychainMasterKeyStore) Get(ctx context.Context) (*memguard.LockedBuffer, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	cService := C.CString(s.service)
	defer C.free(unsafe.Pointer(cService))
	cAccount := C.CString(s.account)
	defer C.free(unsafe.Pointer(cAccount))

	var cPath *C.char
	if s.keychainPath != "" {
		cPath = C.CString(s.keychainPath)
		defer C.free(unsafe.Pointer(cPath))
	}

	var outData unsafe.Pointer
	var outLen C.CFIndex
	status := C.opq_keychain_get_master_key(cPath, cService, cAccount, &outData, &outLen)
	defer C.opq_zero_and_free(outData, outLen)

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if status == C.errSecItemNotFound {
		return nil, ErrMasterKeyNotFound
	}
	if status != C.errSecSuccess {
		return nil, fmt.Errorf("macOS Keychain master key lookup failed (OSStatus %d)", int(status))
	}
	if outData == nil || outLen <= 0 {
		return nil, fmt.Errorf("macOS Keychain master key is empty")
	}

	hexBytes := C.GoBytes(outData, C.int(outLen))
	defer memguard.WipeBytes(hexBytes)

	raw := make([]byte, hex.DecodedLen(len(hexBytes)))
	n, err := hex.Decode(raw, hexBytes)
	if err != nil {
		memguard.WipeBytes(raw)
		return nil, fmt.Errorf("decode vault master key: %w", err)
	}
	if n != vaultKeyLen {
		memguard.WipeBytes(raw)
		return nil, fmt.Errorf("vault master key has invalid length %d (want %d)", n, vaultKeyLen)
	}

	lb := memguard.NewBuffer(vaultKeyLen)
	lb.Move(raw[:n]) // moves into mlocked pages and zeroes raw
	return lb, nil
}

func (s *keychainMasterKeyStore) Create(ctx context.Context, key *memguard.LockedBuffer) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if key == nil || !key.IsAlive() || key.Size() != vaultKeyLen {
		return fmt.Errorf("create vault master key: invalid key")
	}

	hexBuf := make([]byte, hex.EncodedLen(vaultKeyLen))
	hex.Encode(hexBuf, key.Bytes())
	defer memguard.WipeBytes(hexBuf)

	cService := C.CString(s.service)
	defer C.free(unsafe.Pointer(cService))
	cAccount := C.CString(s.account)
	defer C.free(unsafe.Pointer(cAccount))
	cLabel := C.CString(vaultMasterKeyLabel)
	defer C.free(unsafe.Pointer(cLabel))
	cDesc := C.CString(vaultMasterKeyDescription)
	defer C.free(unsafe.Pointer(cDesc))

	var cPath *C.char
	if s.keychainPath != "" {
		cPath = C.CString(s.keychainPath)
		defer C.free(unsafe.Pointer(cPath))
	}

	status := C.opq_keychain_add_master_key(
		cPath, cService, cAccount, cLabel, cDesc,
		unsafe.Pointer(&hexBuf[0]), C.CFIndex(len(hexBuf)),
	)
	if status == C.errSecDuplicateItem {
		return ErrMasterKeyExists
	}
	if status != C.errSecSuccess {
		return fmt.Errorf("macOS Keychain store master key failed (OSStatus %d)", int(status))
	}
	return ctx.Err()
}

// deleteKeychainGenericPassword removes a generic-password item from the macOS
// Keychain using SecKeychainItemDelete so cross-binary cleanup succeeds with
// zero password prompts (avoiding SecItemDelete's -25244 error across CDHashes).
func deleteKeychainGenericPassword(ctx context.Context, keychainPath, service, account string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	cService := C.CString(service)
	defer C.free(unsafe.Pointer(cService))
	cAccount := C.CString(account)
	defer C.free(unsafe.Pointer(cAccount))

	var cPath *C.char
	if keychainPath != "" {
		cPath = C.CString(keychainPath)
		defer C.free(unsafe.Pointer(cPath))
	}

	status := C.opq_keychain_delete_item(cPath, cService, cAccount)
	if status == C.errSecItemNotFound {
		return ErrSecretNotFound
	}
	if status != C.errSecSuccess {
		return fmt.Errorf("macOS Keychain delete item failed (OSStatus %d)", int(status))
	}
	return ctx.Err()
}
