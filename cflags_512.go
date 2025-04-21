//go:build aes512

package aesgcm

/*
#cgo CFLAGS: -DAES512=1
*/
import "C"

// CompiledKeySize returns the key size (64 bytes) for the AES-512 build.
func CompiledKeySize() int {
	return 64
}
