# AES-GCM-512 (Fork of tiny-AES-c)

[![Go Reference](https://pkg.go.dev/badge/github.com/TheMapleseed/AES-GCM-512-.svg)](https://pkg.go.dev/github.com/TheMapleseed/AES-GCM-512-)

This repository provides a C implementation of the AES-GCM authenticated encryption algorithm, derived from the `tiny-AES-c` project (<https://github.com/kokke/tiny-AES-c>), with modifications to support AES-128, AES-192, AES-256, and a non-standard AES-512 variant.

It includes Go language bindings (`aesgcm` package) for easy integration into Go projects, leveraging Cgo.

The implementation aims for correctness and includes architecture-specific optimizations (AES-NI for x86_64, ARM Crypto for AArch64) where available and enabled at compile time.

## Features

*   AES-GCM Authenticated Encryption and Decryption.
*   Supports AES key sizes: 128, 192, 256, and non-standard 512 bits.
*   Supports standard 12-byte (96-bit) IVs and other IV lengths via GHASH per NIST SP 800-38D.
*   C library core (`aes.c`, `aes.h`).
*   Go package wrapper (`aesgcm`) using Cgo.
*   Architecture-specific optimizations (AES-NI, ARM Crypto) via intrinsics.
*   Multiple build system options (Go, CMake, Make, GCC script).

## Building

There are several ways to build this project, depending on your needs:

### 1. Go Package (Recommended for Go Users)

If you intend to use this library within a Go project, simply import the package. The Go build system (using Cgo) will automatically compile the necessary C source files (`aes.c`) along with the Go wrapper.

```bash
go get github.com/TheMapleseed/AES-GCM-512-
```

The build process automatically selects the appropriate C flags based on the build tags (e.g., `aes128`, `aes192`, `aes256`, `aes512` - default is usually AES-256 if none specified) and attempts to enable architecture-specific optimizations.

Run tests:
```bash
go test -v
```

### 2. CMake (For C Library Deployment / Cgo)

The `CMakeLists.txt` file supports two modes controlled by the `BUILD_C_DEPLOY_ARTIFACTS` option:

*   **Cgo Mode (Default):** `cmake . && make`
    *   Configures an `INTERFACE` library suitable for Cgo to consume.
*   **C Library Deployment Mode:** `cmake . -DBUILD_C_DEPLOY_ARTIFACTS=ON && make`
    *   Builds static (`libtiny_aes_gcm.a`) and shared (`libtiny_aes_gcm.so`/`.dylib`) C libraries.
    *   Enables architecture-specific optimizations (`-maes -mpclmul` or `-march=armv8-a+crypto`) if detected.
    *   Optionally builds the C test executable: `cmake . -DBUILD_C_DEPLOY_ARTIFACTS=ON -DBUILD_C_TEST_EXECUTABLE=ON && make`
    *   Installs libraries and header: `sudo make install` (uses `/usr/local` prefix by default)

### 3. Make (Traditional C Build)

Use the provided `Makefile` for a standard C build process:

*   Build static and shared libraries: `make`
*   Build only the C test executable: `make test_exe`
*   Install libraries and header: `sudo make install`
*   Clean build files: `make clean`

The Makefile also attempts to detect the architecture and enable optimizations.

### 4. Direct GCC (Example Script)

The `build_with_gcc.sh` script provides a basic example of compiling the shared C library directly using GCC.

```bash
# Make executable (if needed)
chmod +x build_with_gcc.sh
# Run build
./build_with_gcc.sh
```
This script also attempts architecture detection for optimization flags.

## Go Package Usage (`aesgcm`)

```go
package main

import (
	"fmt"
	"log"
	"crypto/rand"
	"github.com/TheMapleseed/AES-GCM-512-" // Adjust import path if necessary
)

func main() {
	// Key must match the compiled key size (check aesgcm.CompiledKeySize())
	// Example for AES-256
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		log.Fatalf("Failed to generate key: %v", err)
	}

	// Create context
	ctx, err := aesgcm.NewContext(key)
	if err != nil {
		log.Fatalf("NewContext failed: %v", err)
	}

	// Prepare data
	plaintext := []byte("This is a secret message.")
	aad := []byte("Optional authenticated data")
	iv := make([]byte, 12) // 12-byte IV recommended
	if _, err := rand.Read(iv); err != nil {
		log.Fatalf("Failed to generate IV: %v", err)
	}

	// Encrypt
	ciphertext, tag, err := ctx.Encrypt(iv, aad, plaintext)
	if err != nil {
		log.Fatalf("Encrypt failed: %v", err)
	}
	fmt.Printf("Ciphertext: %x\n", ciphertext)
	fmt.Printf("Tag: %x\n", tag)

	// Decrypt
	decryptedText, err := ctx.Decrypt(iv, aad, ciphertext, tag)
	if err != nil {
		// Important: Check for authentication failure!
		if err == aesgcm.ErrAuthFailed {
			log.Fatalf("DECRYPTION FAILED: AUTHENTICATION ERROR")
		} else {
			log.Fatalf("Decrypt failed: %v", err)
		}
	}

	fmt.Printf("Decrypted: %s\n", string(decryptedText))
}
```

## Original Project

This project is a fork and modification of the `tiny-AES-c` project by `kokke`:
<https://github.com/kokke/tiny-AES-c>

The original code provided implementations for AES (ECB, CBC, CTR) modes.

## License

This modified project is licensed under the GNU General Public License v3.0. See the `LICENSE` file for details.
