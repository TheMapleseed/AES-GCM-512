//go:build !aes128 && !aes192 && !aes512

package aesgcm

/*
#cgo CFLAGS: -DAES256=1
*/
import "C"

// CompiledKeySize returns the key size (32 bytes) for the default AES-256 build.
func CompiledKeySize() int {
	return 32
}
