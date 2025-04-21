//go:build aes192

package aesgcm

/*
#cgo CFLAGS: -DAES192=1
*/
import "C"

// CompiledKeySize returns the key size (24 bytes) for the AES-192 build.
func CompiledKeySize() int {
	return 24
}
