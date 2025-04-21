//go:build aes128

package aesgcm

/*
#cgo CFLAGS: -DAES128=1
*/
import "C"

// CompiledKeySize returns the key size (16 bytes) for the AES-128 build.
func CompiledKeySize() int {
	return 16
}
