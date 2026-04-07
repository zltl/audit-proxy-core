# SSH Proxy Core - Makefile
# Modern C Project Build System

# Compiler and flags
CC := gcc
CFLAGS := -std=c11 -Wall -Wextra -Wpedantic -Werror
CFLAGS += -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE
LDFLAGS :=
LIBS :=

# libssh dependency
LIBSSH_CFLAGS := $(shell pkg-config --cflags libssh 2>/dev/null)
LIBSSH_LIBS := $(shell pkg-config --libs libssh 2>/dev/null)
CFLAGS += $(LIBSSH_CFLAGS)
LIBS += $(LIBSSH_LIBS)

# pthread and crypt for session/auth
LIBS += -lpthread -lcrypt

# Optional TLS/OpenSSL support (build with TLS_ENABLED=1)
TLS_ENABLED ?= 0
ifeq ($(TLS_ENABLED),1)
    OPENSSL_CFLAGS := $(shell pkg-config --cflags openssl 2>/dev/null)
    OPENSSL_LIBS := $(shell pkg-config --libs openssl 2>/dev/null)
    CFLAGS += $(OPENSSL_CFLAGS) -DTLS_ENABLED
    LIBS += $(OPENSSL_LIBS)
endif

# Directories
SRC_DIR := src
INC_DIR := include
BUILD_DIR := build
OBJ_DIR := $(BUILD_DIR)/obj
BIN_DIR := $(BUILD_DIR)/bin
LIB_DIR := lib
TEST_DIR := tests
GEN_DIR := $(BUILD_DIR)/gen
DEPS_DIR := $(BUILD_DIR)/deps

# json-gen-c (downloaded at build time)
# NOTE: Pin to a release tag or specific commit SHA for production builds.
# Example: JSON_GEN_C_VERSION := v1.0.0
JSON_GEN_C_VERSION := main
JSON_GEN_C_URL := https://github.com/zltl/json-gen-c/archive/refs/heads/$(JSON_GEN_C_VERSION).tar.gz
JSON_GEN_C_DIR := $(DEPS_DIR)/json-gen-c-$(JSON_GEN_C_VERSION)
JSON_GEN_C_BIN := $(JSON_GEN_C_DIR)/build/bin/json-gen-c
JSON_GEN_C_STAMP := $(DEPS_DIR)/.json-gen-c-built
JSON_TYPES_DEF := $(SRC_DIR)/json_types.json-gen-c
JSON_GEN_H := $(GEN_DIR)/json.gen.h
JSON_GEN_C := $(GEN_DIR)/json.gen.c
JSON_SSTR_H := $(GEN_DIR)/sstr.h
JSON_SSTR_C := $(GEN_DIR)/sstr.c

# Target
TARGET := ssh-proxy-core
LIB_TARGET := libsshproxy.a

# Source files (include generated sources)
SRCS := $(wildcard $(SRC_DIR)/*.c)
OBJS := $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(SRCS))
# Add generated JSON sources
OBJS += $(OBJ_DIR)/json.gen.o $(OBJ_DIR)/sstr.o $(OBJ_DIR)/error_codes.o
DEPS := $(OBJS:.o=.d)

# Test files
TEST_SRCS := $(wildcard $(TEST_DIR)/*.c)
TEST_BINS := $(patsubst $(TEST_DIR)/%.c,$(BIN_DIR)/%,$(TEST_SRCS))

# Build types
DEBUG_FLAGS := -g -O0 -DDEBUG
RELEASE_FLAGS := -O2 -DNDEBUG

# Default to debug build
BUILD_TYPE ?= debug

ifeq ($(BUILD_TYPE),release)
    CFLAGS += $(RELEASE_FLAGS)
else
    CFLAGS += $(DEBUG_FLAGS)
endif

# Include paths
CFLAGS += -I$(INC_DIR) -I$(TEST_DIR) -I$(GEN_DIR)

# Phony targets
.PHONY: all clean test run install uninstall dirs debug release help check-deps compile_commands.json json-gen-c deps-clean

# Default target
all: check-deps dirs json-gen $(BIN_DIR)/$(TARGET)

# Download and build json-gen-c tool
$(JSON_GEN_C_STAMP):
	@echo "Downloading json-gen-c..."
	@mkdir -p $(DEPS_DIR)
	@curl -sL $(JSON_GEN_C_URL) | tar -xz -C $(DEPS_DIR)
	@echo "Building json-gen-c..."
	@$(MAKE) -C $(JSON_GEN_C_DIR) -j$(shell nproc) >/dev/null 2>&1 || $(MAKE) -C $(JSON_GEN_C_DIR)
	@touch $(JSON_GEN_C_STAMP)

$(JSON_GEN_C_BIN): $(JSON_GEN_C_STAMP)

# Generate JSON serialization code
json-gen: $(JSON_GEN_H)

$(JSON_GEN_H) $(JSON_GEN_C) $(JSON_SSTR_H) $(JSON_SSTR_C): $(JSON_TYPES_DEF) $(JSON_GEN_C_BIN)
	@echo "Generating JSON serialization code..."
	@mkdir -p $(GEN_DIR) $(GEN_DIR)/utils
	@$(JSON_GEN_C_BIN) -in $(JSON_TYPES_DEF) -out $(GEN_DIR)
	@cp $(JSON_GEN_C_DIR)/src/utils/error_codes.h $(GEN_DIR)/utils/
	@cp $(JSON_GEN_C_DIR)/src/utils/error_codes.c $(GEN_DIR)/utils/

# Compile generated JSON sources
$(OBJ_DIR)/json.gen.o: $(JSON_GEN_C) $(JSON_GEN_H)
	$(CC) $(CFLAGS) -Wno-unused-parameter -Wno-pedantic -MMD -MP -c -o $@ $<

$(OBJ_DIR)/sstr.o: $(JSON_SSTR_C) $(JSON_SSTR_H)
	$(CC) $(CFLAGS) -Wno-unused-parameter -Wno-pedantic -MMD -MP -c -o $@ $<

$(OBJ_DIR)/error_codes.o: $(GEN_DIR)/utils/error_codes.c
	$(CC) $(CFLAGS) -Wno-unused-parameter -MMD -MP -c -o $@ $<

# Check dependencies
check-deps:
	@pkg-config --exists libssh || { \
		echo "Error: libssh not found. Please install:"; \
		echo "  Ubuntu/Debian: sudo apt-get install libssh-dev"; \
		echo "  RHEL/CentOS:   sudo yum install libssh-devel"; \
		echo "  macOS:         brew install libssh"; \
		echo "  Or build from source: https://www.libssh.org/get-it/"; \
		exit 1; \
	}
ifeq ($(TLS_ENABLED),1)
	@pkg-config --exists openssl || { \
		echo "Error: OpenSSL not found (required for TLS_ENABLED=1). Please install:"; \
		echo "  Ubuntu/Debian: sudo apt-get install libssl-dev"; \
		echo "  RHEL/CentOS:   sudo yum install openssl-devel"; \
		echo "  macOS:         brew install openssl"; \
		exit 1; \
	}
endif

# Debug build
debug:
	$(MAKE) BUILD_TYPE=debug all

# Release build
release:
	$(MAKE) BUILD_TYPE=release all

# Create directories
dirs:
	@mkdir -p $(OBJ_DIR) $(BIN_DIR) $(GEN_DIR)

# Link executable
$(BIN_DIR)/$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

# Compile source files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

# Build static library
lib: dirs $(filter-out $(OBJ_DIR)/main.o,$(OBJS))
	ar rcs $(BIN_DIR)/$(LIB_TARGET) $(filter-out $(OBJ_DIR)/main.o,$(OBJS))

# Build and run tests
test: dirs json-gen $(TEST_BINS)
	@echo "Running tests..."
	@for test in $(TEST_BINS); do \
		echo ""; \
		$$test || exit 1; \
	done

$(BIN_DIR)/test_%: $(TEST_DIR)/test_%.c $(filter-out $(OBJ_DIR)/main.o,$(OBJS))
	$(CC) $(CFLAGS) -Wno-unused-parameter $(LDFLAGS) -o $@ $< $(filter-out $(OBJ_DIR)/main.o,$(OBJS)) $(LIBS)

# Run the program
run: all
	@$(BIN_DIR)/$(TARGET) -d -c config.ini

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)

# Clean downloaded dependencies
deps-clean:
	rm -rf $(DEPS_DIR)

# Install (requires root)
PREFIX ?= /usr/local
install: release
	install -d $(PREFIX)/bin
	install -m 755 $(BIN_DIR)/$(TARGET) $(PREFIX)/bin/
	install -d $(PREFIX)/include/ssh_proxy
	install -m 644 $(INC_DIR)/*.h $(PREFIX)/include/ssh_proxy/

# Uninstall
uninstall:
	rm -f $(PREFIX)/bin/$(TARGET)
	rm -rf $(PREFIX)/include/ssh_proxy

# Format code (requires clang-format)
format:
	@find $(SRC_DIR) $(INC_DIR) $(TEST_DIR) -name '*.c' -o -name '*.h' | xargs clang-format -i

# Static analysis (requires cppcheck)
check:
	@cppcheck --enable=all --std=c11 -I$(INC_DIR) $(SRC_DIR) $(TEST_DIR)

# Generate compile_commands.json for language servers
compile_commands.json: dirs
	@echo "Generating compile_commands.json..."
	@echo '[' > compile_commands.json
	@first=1; \
	for src in $(SRCS); do \
		if [ $$first -eq 0 ]; then echo ',' >> compile_commands.json; fi; \
		echo '  {' >> compile_commands.json; \
		echo '    "directory": "'$(shell pwd)'",' >> compile_commands.json; \
		echo '    "command": "$(CC) $(CFLAGS) -c '$${src}'",' >> compile_commands.json; \
		echo '    "file": "'$${src}'"' >> compile_commands.json; \
		echo '  }' >> compile_commands.json; \
		first=0; \
	done
	@echo ']' >> compile_commands.json
	@echo "Generated compile_commands.json with $(words $(SRCS)) entries"

# Include dependency files
-include $(DEPS)

# Help
help:
	@echo "SSH Proxy Core - Build System"
	@echo ""
	@echo "Usage: make [target] [BUILD_TYPE=debug|release]"
	@echo ""
	@echo "Targets:"
	@echo "  all      - Build the project (default)"
	@echo "  debug    - Build with debug flags"
	@echo "  release  - Build with release flags"
	@echo "  lib      - Build static library"
	@echo "  test     - Build and run tests"
	@echo "  run      - Build and run the program"
	@echo "  clean    - Remove build artifacts"
	@echo "  install  - Install to system (PREFIX=/usr/local)"
	@echo "  format   - Format source code"
	@echo "  check    - Run static analysis"
	@echo "  compile_commands.json - Generate compile_commands.json for language servers"
	@echo "  help     - Show this help message"
