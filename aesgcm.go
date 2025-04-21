package aesgcm

/*
#cgo CFLAGS: -Wall -Werror
// Specific AES key size flags are set by build tags (defined in cflags_*.go files)
// We assume aes.c and aes.h are in the same directory or accessible via include paths
#include <stdlib.h> // For C.free
#include "aes.h"
*/
import "C" // Enables Cgo
import (
	"errors"
	"runtime"
	"unsafe"
)

// Define constants matching C header (or derive if needed)
const (
	// KeySize is determined at compile time by build tags (see CompiledKeySize func)
	// KeySize   = 32 // AES-256 key size in bytes (Matches CFLAGS -DAES256=1)
	TagSize   = C.AES_GCM_TAG_LEN
	BlockSize = C.AES_BLOCKLEN
)

// Go errors
var (
	ErrInvalidKeySize   = errors.New("aesgcm: invalid key size for compiled version") // Modified error message
	ErrAuthFailed       = errors.New("aesgcm: authentication failed (tag mismatch)")
	ErrEncrypt          = errors.New("aesgcm: encryption error from C library")
	ErrDecrypt          = errors.New("aesgcm: decryption error from C library (other than auth fail)")
	ErrInvalidArguments = errors.New("aesgcm: invalid arguments provided")
)

// Context wraps the C AES context.
type Context struct {
	cCtx *C.struct_AES_ctx
}

/*
// CompiledKeySize returns the key size in bytes (16, 24, 32, or 64)
// that this package was compiled to support, based on build tags.
// The actual implementation resides in tag-specific files (e.g., cflags_128.go).
func CompiledKeySize() int
*/

// NewContext initializes a new AES-GCM context with the given key.
// The key length must match the size the package was compiled for
// (e.g., 32 bytes if compiled with -tags aes256, or by default).
func NewContext(key []byte) (*Context, error) {
	expectedKeySize := CompiledKeySize() // Get size based on build tag
	if len(key) != expectedKeySize {
		return nil, ErrInvalidKeySize
	}

	// Allocate C context struct on the C heap
	// C.malloc returns unsafe.Pointer, which needs casting.
	cCtxPtr := C.malloc(C.sizeof_struct_AES_ctx)
	if cCtxPtr == nil {
		// Should not happen often, but check C malloc failure
		panic("C.malloc failed to allocate AES_ctx")
	}
	cCtx := (*C.struct_AES_ctx)(cCtxPtr)

	// Get a C pointer to the key slice's underlying data.
	// This is safe because AES_init_ctx/KeyExpansion reads the key immediately
	// and doesn't store the pointer itself long-term.
	// Check for empty key slice, although length check above should prevent this.
	var keyPtr *C.uint8_t
	if len(key) > 0 {
		keyPtr = (*C.uint8_t)(unsafe.Pointer(&key[0]))
	} // else keyPtr remains nil, but AES_init_ctx probably doesn't handle that nicely.

	// Call the C initialization function
	C.AES_init_ctx(cCtx, keyPtr)

	// Create the Go wrapper struct
	goCtx := &Context{cCtx: cCtx}

	// Set a finalizer to free the C memory when the Go object is garbage collected.
	runtime.SetFinalizer(goCtx, freeContext)

	return goCtx, nil
}

// freeContext is called by the Go runtime garbage collector.
func freeContext(ctx *Context) {
	if ctx.cCtx != nil {
		C.free(unsafe.Pointer(ctx.cCtx))
		ctx.cCtx = nil // Prevent double free
	}
}

// Encrypt performs AES-GCM authenticated encryption.
// iv: Initialization Vector (nonce). Recommended size is 12 bytes, but other lengths are handled by the C lib. Must not be reused with the same key.
// aad: Additional Authenticated Data (can be nil or empty).
// plaintext: The data to encrypt.
// Returns ciphertext and authentication tag, or an error.
func (ctx *Context) Encrypt(iv, aad, plaintext []byte) (ciphertext []byte, tag []byte, err error) {
	if ctx == nil || ctx.cCtx == nil {
		return nil, nil, errors.New("aesgcm: context is nil")
	}
	// Note: C library checks for pt=NULL if pt_len>0, aad=NULL if aad_len>0, etc.
	// We might add Go-level checks too if desired.

	// Allocate output buffers in Go
	ciphertext = make([]byte, len(plaintext))
	tag = make([]byte, TagSize)

	// Get C pointers to Go slice data. Handle empty slices gracefully by passing NULL.
	var ivPtr *C.uint8_t
	if len(iv) > 0 {
		ivPtr = (*C.uint8_t)(unsafe.Pointer(&iv[0]))
	}
	var aadPtr *C.uint8_t
	if len(aad) > 0 {
		aadPtr = (*C.uint8_t)(unsafe.Pointer(&aad[0]))
	}
	var ptPtr *C.uint8_t
	if len(plaintext) > 0 {
		ptPtr = (*C.uint8_t)(unsafe.Pointer(&plaintext[0]))
	}
	var ctPtr *C.uint8_t
	if len(ciphertext) > 0 {
		ctPtr = (*C.uint8_t)(unsafe.Pointer(&ciphertext[0]))
	}
	tagPtr := (*C.uint8_t)(unsafe.Pointer(&tag[0])) // Tag buffer always allocated

	// Convert lengths to C.size_t
	ivLenC := C.size_t(len(iv))
	aadLenC := C.size_t(len(aad))
	ptLenC := C.size_t(len(plaintext))

	// Call the C encryption function
	ret := C.AES_GCM_encrypt(ctx.cCtx, ivPtr, ivLenC, aadPtr, aadLenC, ptPtr, ctPtr, ptLenC, tagPtr)

	if ret != 0 {
		// Map C errors to Go errors
		if ret == -1 {
			return nil, nil, ErrInvalidArguments // Or be more specific if C provides more codes
		}
		// Add other error code mappings if C lib returns more specific errors
		return nil, nil, ErrEncrypt
	}

	return ciphertext, tag, nil
}

// Decrypt performs AES-GCM authenticated decryption.
// iv, aad: Must match the values used during encryption.
// ciphertext: The encrypted data.
// tag: The authentication tag received alongside the ciphertext. Must be TagSize bytes.
// Returns the original plaintext, or an error if decryption or authentication fails.
func (ctx *Context) Decrypt(iv, aad, ciphertext, tag []byte) (plaintext []byte, err error) {
	if ctx == nil || ctx.cCtx == nil {
		return nil, errors.New("aesgcm: context is nil")
	}
	if len(tag) != TagSize {
		return nil, errors.New("aesgcm: invalid tag size")
	}
	// Note: C library checks for ct=NULL if ct_len>0, aad=NULL if aad_len>0, etc.

	// Allocate output buffer in Go
	plaintext = make([]byte, len(ciphertext))

	// Get C pointers, handling empty slices.
	var ivPtr *C.uint8_t
	if len(iv) > 0 {
		ivPtr = (*C.uint8_t)(unsafe.Pointer(&iv[0]))
	}
	var aadPtr *C.uint8_t
	if len(aad) > 0 {
		aadPtr = (*C.uint8_t)(unsafe.Pointer(&aad[0]))
	}
	var ctPtr *C.uint8_t
	if len(ciphertext) > 0 {
		ctPtr = (*C.uint8_t)(unsafe.Pointer(&ciphertext[0]))
	}
	var ptPtr *C.uint8_t
	if len(plaintext) > 0 {
		ptPtr = (*C.uint8_t)(unsafe.Pointer(&plaintext[0]))
	}
	tagPtr := (*C.uint8_t)(unsafe.Pointer(&tag[0]))

	// Convert lengths
	ivLenC := C.size_t(len(iv))
	aadLenC := C.size_t(len(aad))
	ctLenC := C.size_t(len(ciphertext))

	// Call the C decryption function
	ret := C.AES_GCM_decrypt(ctx.cCtx, ivPtr, ivLenC, aadPtr, aadLenC, ctPtr, ptPtr, ctLenC, tagPtr)

	if ret != 0 {
		// Map C errors to Go errors
		if ret == -3 {
			return nil, ErrAuthFailed
		}
		if ret == -1 {
			return nil, ErrInvalidArguments
		}
		// Add other error code mappings if C lib returns more specific errors
		return nil, ErrDecrypt
	}

	return plaintext, nil
}
