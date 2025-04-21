package aesgcm

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"testing"
)

// TestAesGcmDefaultEncryptDecrypt tests basic encryption and decryption cycle
// using the default key size compiled into the package (expected to be AES-256
// if no build tags like aes128, aes192, aes512 are used).
func TestAesGcmDefaultEncryptDecrypt(t *testing.T) {
	// Determine expected key size based on build
	expectedKeySize := CompiledKeySize()
	t.Logf("Testing with compiled key size: %d bytes", expectedKeySize)

	// 1. Generate Key
	key := make([]byte, expectedKeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// 2. Create Context
	ctx, err := NewContext(key)
	if err != nil {
		t.Fatalf("NewContext failed: %v", err)
	}
	// Note: Finalizer should handle freeing ctx.cCtx

	// 3. Prepare Data
	plaintext := []byte("This is a test message for AES-GCM encryption/decryption.")
	aad := []byte("Optional Associated Data")

	// Generate IV (using recommended 12 bytes for efficiency, though others work)
	iv := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		t.Fatalf("Failed to generate IV: %v", err)
	}

	// 4. Encrypt
	ciphertext, tag, err := ctx.Encrypt(iv, aad, plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	if len(ciphertext) != len(plaintext) {
		t.Errorf("Ciphertext length (%d) does not match plaintext length (%d)", len(ciphertext), len(plaintext))
	}
	if len(tag) != TagSize {
		t.Errorf("Tag length (%d) does not match expected TagSize (%d)", len(tag), TagSize)
	}

	t.Logf("Plaintext:  %s", string(plaintext))
	t.Logf("AAD:        %s", string(aad))
	t.Logf("IV:         %x", iv)
	t.Logf("Ciphertext: %x", ciphertext)
	t.Logf("Tag:        %x", tag)

	// 5. Decrypt (Good case)
	decryptedText, err := ctx.Decrypt(iv, aad, ciphertext, tag)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	// 6. Verify
	if !bytes.Equal(plaintext, decryptedText) {
		t.Errorf("Decrypted text does not match original plaintext.\nOriginal: %s\nDecrypted:%s", string(plaintext), string(decryptedText))
	}
	t.Logf("Decrypted:  %s", string(decryptedText))
	t.Logf("Decrypt Verify: SUCCESS")

	// 7. Test Authentication Failure (Corrupted Tag)
	corruptedTag := make([]byte, len(tag))
	copy(corruptedTag, tag)
	corruptedTag[0] ^= 0xff // Flip first byte

	_, err = ctx.Decrypt(iv, aad, ciphertext, corruptedTag)
	if err == nil {
		t.Errorf("Decrypt succeeded with corrupted tag, but should have failed.")
	} else if !errors.Is(err, ErrAuthFailed) {
		t.Errorf("Decrypt failed with wrong error type. Expected ErrAuthFailed, got: %v", err)
	} else {
		t.Logf("Decrypt correctly failed with corrupted tag: %v", err)
		t.Logf("Auth Fail Test: SUCCESS")
	}

	// 8. Test Authentication Failure (Corrupted Ciphertext)
	corruptedCiphertext := make([]byte, len(ciphertext))
	copy(corruptedCiphertext, ciphertext)
	if len(corruptedCiphertext) > 0 { // Avoid panic on empty ciphertext
		corruptedCiphertext[0] ^= 0xff // Flip first byte
	} else {
		t.Log("Skipping ciphertext corruption test as ciphertext is empty")
	}
	if len(corruptedCiphertext) > 0 {
		_, err = ctx.Decrypt(iv, aad, corruptedCiphertext, tag) // Use original tag
		if err == nil {
			t.Errorf("Decrypt succeeded with corrupted ciphertext, but should have failed.")
		} else if !errors.Is(err, ErrAuthFailed) {
			t.Errorf("Decrypt failed with wrong error type. Expected ErrAuthFailed, got: %v", err)
		} else {
			t.Logf("Decrypt correctly failed with corrupted ciphertext: %v", err)
			t.Logf("Ciphertext Corruption Test: SUCCESS")
		}
	}

	// 9. Test Authentication Failure (Corrupted AAD)
	corruptedAad := make([]byte, len(aad))
	copy(corruptedAad, aad)
	if len(corruptedAad) > 0 {
		corruptedAad[0] ^= 0xff // Flip first byte
	} else {
		// If AAD was empty, create non-empty AAD for test
		corruptedAad = []byte("different aad")
	}

	_, err = ctx.Decrypt(iv, corruptedAad, ciphertext, tag) // Use original ct/tag
	if err == nil {
		t.Errorf("Decrypt succeeded with corrupted AAD, but should have failed.")
	} else if !errors.Is(err, ErrAuthFailed) {
		t.Errorf("Decrypt failed with wrong error type. Expected ErrAuthFailed, got: %v", err)
	} else {
		t.Logf("Decrypt correctly failed with corrupted AAD: %v", err)
		t.Logf("AAD Corruption Test: SUCCESS")
	}
}

// TODO: Add tests for different key sizes using build tags
// Example: func TestAesGcm128(t *testing.T) { //go:build aes128 ... }

// TODO: Add tests for different IV lengths

// TODO: Add tests using known test vectors (e.g., from aes.c)
// Requires parsing hex strings and comparing results.
