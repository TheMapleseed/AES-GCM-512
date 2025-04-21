# Compiler and Flags
CC = gcc

# Detect Architecture and OS
UNAME_M := $(shell uname -m)
UNAME_S := $(shell uname -s)

# Base CFLAGS
BASE_CFLAGS = -Wall -Wextra -O2

# Architecture-Specific Flags
ARCH_FLAGS =
ifeq ($(UNAME_M), x86_64)
	ARCH_FLAGS += -maes -mpclmul
endif
ifeq ($(UNAME_M), aarch64)
	# Assuming ARMv8 with Crypto extensions. Adjust if needed for specific targets.
	ARCH_FLAGS += -march=armv8-a+crypto
endif

# CFLAGS for library objects (Position Independent Code)
LIB_CFLAGS = $(BASE_CFLAGS) -fPIC -I. $(ARCH_FLAGS)
# CFLAGS for test executable objects
TEST_CFLAGS = $(BASE_CFLAGS) -I. -DAES_GCM_STANDALONE_TEST $(ARCH_FLAGS)

# Shared Library Flags and Suffix
LDFLAGS = -shared
SHARED_LIB_SUFFIX = .so # Default for Linux
ifeq ($(UNAME_S), Darwin)
	SHARED_LIB_SUFFIX = .dylib
endif

AR = ar
ARFLAGS = rcs

# Installation Prefix
PREFIX ?= /usr/local

# Library Files
LIB_NAME = tiny_aes_gcm
LIB_SRCS = aes.c
LIB_OBJS = $(LIB_SRCS:.c=.o)
# SHARED_LIB_SUFFIX = .so # Adjust for macOS (.dylib) or Windows (.dll) if needed <-- Now set dynamically
SHARED_LIB = lib$(LIB_NAME)$(SHARED_LIB_SUFFIX)
STATIC_LIB = lib$(LIB_NAME).a

# Test Executable Files
TEST_SRCS = test_c_standalone.c
TEST_OBJS = $(TEST_SRCS:.c=.o)
TEST_TARGET = aes_gcm_test_c
# Test executable needs aes.o compiled without -fPIC if linking statically, or can link shared.
# Simplest for now: build test objects separately.
TEST_AES_OBJ = aes_test.o # Use a different object name for the test version of aes.c
TEST_ALL_OBJS = $(TEST_AES_OBJ) $(TEST_OBJS)

# Build Rules
all: $(SHARED_LIB) $(STATIC_LIB)

# --- Library Build --- 
$(SHARED_LIB): $(LIB_OBJS)
	$(CC) $(LDFLAGS) $^ -o $@

$(STATIC_LIB): $(LIB_OBJS)
	$(AR) $(ARFLAGS) $@ $^

# Rule to compile library object files (with -fPIC)
# Use specific target for library aes.o to distinguish from test aes.o
$(LIB_OBJS): %.o: %.c aes.h Makefile
	@echo "Compiling library object $@ with flags: $(LIB_CFLAGS)"
	$(CC) $(LIB_CFLAGS) -c $< -o $@

# --- Test Executable Build --- 
test_exe: $(TEST_TARGET)

$(TEST_TARGET): $(TEST_ALL_OBJS) # Use separate objects for test
	@echo "Linking test executable $(TEST_TARGET) with flags: $(TEST_CFLAGS)"
	$(CC) $(TEST_CFLAGS) $^ -o $@ # Link test executable

# Rule to compile test executable object files (without -fPIC, with define)
$(TEST_OBJS): %.o: %.c aes.h Makefile
	@echo "Compiling test object $@ with flags: $(TEST_CFLAGS)"
	$(CC) $(TEST_CFLAGS) -c $< -o $@

# Need aes.o specifically for the test executable (no -fPIC needed here)
# Use a distinct object file name (aes_test.o) to avoid conflicts with the library's aes.o
$(TEST_AES_OBJ): aes.c aes.h Makefile
	@echo "Compiling test object $@ with flags: $(TEST_CFLAGS)"
	$(CC) $(TEST_CFLAGS) -c $< -o $@

# --- Installation --- 
install:
	install -d $(DESTDIR)$(PREFIX)/include
	install -m 644 aes.h $(DESTDIR)$(PREFIX)/include/
	install -d $(DESTDIR)$(PREFIX)/lib
	install -m 755 $(SHARED_LIB) $(DESTDIR)$(PREFIX)/lib/
	install -m 644 $(STATIC_LIB) $(DESTDIR)$(PREFIX)/lib/
	@echo "Installed $(LIB_NAME) headers and libraries to $(PREFIX)"

# Clean Rule
clean:
	rm -f $(LIB_OBJS) $(TEST_AES_OBJ) $(TEST_OBJS) $(SHARED_LIB) $(STATIC_LIB) $(TEST_TARGET)

# Phony Targets
.PHONY: all clean install test_exe 