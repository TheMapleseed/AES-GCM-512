#!/bin/sh

# Exit immediately if a command exits with a non-zero status.
set -e

# Compiler and Flags
CC=gcc

# Detect Architecture and OS
UNAME_M=$(uname -m)
UNAME_S=$(uname -s)

# Base CFLAGS
BASE_CFLAGS="-Wall -Wextra -O2 -fPIC -I."
ARCH_FLAGS=""

# Set Architecture-Specific Flags
if [ "$UNAME_M" = "x86_64" ]; then
    ARCH_FLAGS="-maes -mpclmul"
elif [ "$UNAME_M" = "aarch64" ]; then
    # Assuming ARMv8 with Crypto extensions. Adjust if needed.
    ARCH_FLAGS="-march=armv8-a+crypto"
fi

# Combine CFLAGS
CFLAGS="$BASE_CFLAGS $ARCH_FLAGS"

# Shared Library Flags and Suffix
LDFLAGS="-shared"
SHARED_LIB_SUFFIX=".so" # Default for Linux
if [ "$UNAME_S" = "Darwin" ]; then
    SHARED_LIB_SUFFIX=".dylib"
fi

# Library source file
LIB_SRC="aes.c"

# Output shared library
TARGET="libtiny_aes_gcm${SHARED_LIB_SUFFIX}"

# Compile and Link Shared Library
echo "Compiling shared library: $TARGET"
echo "Using CFLAGS: $CFLAGS"
$CC $CFLAGS $LIB_SRC $LDFLAGS -o $TARGET

echo "Build complete: $TARGET"

# Optional: Add commands here to build static library or test executable if desired
# echo "Building static library..."
# $CC $CFLAGS -c $LIB_SRC -o aes.o # Note: Static lib doesn't strictly need -fPIC but it doesn't hurt
# ar rcs libtiny_aes_gcm.a aes.o
# echo "Building test executable..."
# TEST_CFLAGS="$(echo $CFLAGS | sed 's/-fPIC //') -DAES_GCM_STANDALONE_TEST" # Remove -fPIC for test
# $CC $TEST_CFLAGS aes.c test_c_standalone.c -o aes_gcm_test_c 