SHELL := /bin/bash

GO ?= go
MAKE ?= make
CC ?= cc

OUT_DIR ?= build
OUT_BIN ?= $(OUT_DIR)/patchwork
OUT_EXT_DIR ?= $(OUT_DIR)/extensions
OUT_SQLEAN_DIR ?= $(OUT_EXT_DIR)/sqlean

GO_BUILD_TAGS ?= sqlite_fts5 sqlite_preupdate_hook sqlite_vtable
SQLITE_CFLAGS ?= -DSQLITE_ENABLE_SESSION -DSQLITE_ENABLE_SNAPSHOT -DSQLITE_ENABLE_RBU -DSQLITE_ENABLE_RTREE -DSQLITE_ENABLE_GEOPOLY
SQLITE_LDFLAGS ?=

CRSQLITE_TOOLCHAIN ?= nightly-2023-10-05
SQLITE_VEC_SQLITE_INCLUDE ?= $(abspath third_party/cr-sqlite/core/src/sqlite)
SQLITE_VEC_CFLAGS ?= -I$(SQLITE_VEC_SQLITE_INCLUDE)
SQLEAN_SQLITE_INCLUDE ?= $(abspath third_party/cr-sqlite/core/src/sqlite)
SQLEAN_CFLAGS ?= -I$(SQLEAN_SQLITE_INCLUDE)

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
LIB_EXT := dylib
SQLEAN_COMPILE_TARGET := compile-macos
SQLITE_VEC_PLATFORM_CFLAGS :=
SQLITE_VEC_PLATFORM_LDFLAGS :=
else ifeq ($(OS),Windows_NT)
LIB_EXT := dll
SQLEAN_COMPILE_TARGET := compile-windows
SQLITE_VEC_PLATFORM_CFLAGS :=
SQLITE_VEC_PLATFORM_LDFLAGS :=
else
LIB_EXT := so
SQLEAN_COMPILE_TARGET := compile-linux
SQLITE_VEC_PLATFORM_CFLAGS :=
SQLITE_VEC_PLATFORM_LDFLAGS := -lm
endif

CRSQLITE_LIB := third_party/cr-sqlite/core/dist/crsqlite.$(LIB_EXT)
VEC_LIB := third_party/sqlite-vec/dist/vec0.$(LIB_EXT)
SQLEAN_BUNDLE_LIB := third_party/sqlean/dist/sqlean.$(LIB_EXT)

SQLEAN_SAFE_MODULES := crypto math regexp stats text time unicode uuid

.PHONY: help
help:
	@echo "Targets:"
	@echo "  make build-patchwork          Build patchwork binary ($(OUT_BIN))"
	@echo "  make build-extensions         Build cr-sqlite, sqlite-vec, sqlean artifacts"
	@echo "  make build-all                Build patchwork and all extension artifacts"
	@echo "  make test                     Run go test ./..."
	@echo "  make test-sqlitedriver-ext    Run sqlite driver extension tests with built artifacts"
	@echo "  make clean                    Remove build output and third_party extension dist folders"
	@echo ""
	@echo "Common overrides:"
	@echo "  GO_BUILD_TAGS='sqlite_fts5 sqlite_preupdate_hook sqlite_vtable sqlite_icu'"
	@echo "  SQLITE_LDFLAGS='-licuuc -licui18n'"

.PHONY: build-all
build-all: build-patchwork build-extensions

.PHONY: build-patchwork
build-patchwork: $(OUT_DIR)
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(SQLITE_CFLAGS)" \
	CGO_LDFLAGS="$(SQLITE_LDFLAGS)" \
	$(GO) build -tags "$(GO_BUILD_TAGS)" -o "$(OUT_BIN)" ./cmd/patchwork

.PHONY: build-extensions
build-extensions: build-extension-crsqlite build-extension-vec build-extension-sqlean

.PHONY: build-extension-crsqlite
build-extension-crsqlite: $(OUT_EXT_DIR)
	cd third_party/cr-sqlite/core && \
	RUSTUP_TOOLCHAIN="$(CRSQLITE_TOOLCHAIN)" $(MAKE) loadable
	cp "$(CRSQLITE_LIB)" "$(OUT_EXT_DIR)/crsqlite.$(LIB_EXT)"

.PHONY: build-extension-vec
build-extension-vec: $(OUT_EXT_DIR)
	@if [ ! -f "$(SQLITE_VEC_SQLITE_INCLUDE)/sqlite3ext.h" ]; then \
		echo "missing sqlite3ext.h at $(SQLITE_VEC_SQLITE_INCLUDE)"; \
		echo "expected from vendored third_party/cr-sqlite tree"; \
		exit 1; \
	fi
	@if [ ! -f third_party/sqlite-vec/sqlite-vec.h ]; then \
		$(MAKE) -C third_party/sqlite-vec sqlite-vec.h; \
	fi
	$(CC) -fPIC -shared -Wall -Wextra -O3 \
		$(SQLITE_VEC_CFLAGS) $(SQLITE_VEC_PLATFORM_CFLAGS) \
		third_party/sqlite-vec/sqlite-vec.c \
		-o "$(OUT_EXT_DIR)/vec0.$(LIB_EXT)" \
		$(SQLITE_VEC_PLATFORM_LDFLAGS)

.PHONY: build-extension-sqlean
build-extension-sqlean: $(OUT_EXT_DIR) $(OUT_SQLEAN_DIR)
	@if [ ! -f "$(SQLEAN_SQLITE_INCLUDE)/sqlite3ext.h" ]; then \
		echo "missing sqlite3ext.h at $(SQLEAN_SQLITE_INCLUDE)"; \
		echo "expected from vendored third_party/cr-sqlite tree"; \
		exit 1; \
	fi
	@if [ ! -f "third_party/sqlean/src/crypto/xxhash.impl.h" ]; then \
		$(MAKE) -C third_party/sqlean download-external; \
	fi
	$(MAKE) -C third_party/sqlean prepare-dist
	$(MAKE) -C third_party/sqlean "$(SQLEAN_COMPILE_TARGET)" CFLAGS="$(SQLEAN_CFLAGS)"
	cp "$(SQLEAN_BUNDLE_LIB)" "$(OUT_EXT_DIR)/sqlean.$(LIB_EXT)"
	for mod in $(SQLEAN_SAFE_MODULES); do \
		cp "third_party/sqlean/dist/$${mod}.$(LIB_EXT)" "$(OUT_SQLEAN_DIR)/$${mod}.$(LIB_EXT)"; \
	done

.PHONY: test
test:
	$(GO) test ./...

.PHONY: test-sqlitedriver-ext
test-sqlitedriver-ext: build-extensions
	PATCHWORK_SQLITE_TEST_CRSQLITE_PATH="$$(pwd)/$(OUT_EXT_DIR)/crsqlite.$(LIB_EXT)" \
	PATCHWORK_SQLITE_TEST_VEC_PATH="$$(pwd)/$(OUT_EXT_DIR)/vec0" \
	PATCHWORK_SQLITE_TEST_SQLEAN_PATH="$$(pwd)/$(OUT_EXT_DIR)/sqlean" \
	PATCHWORK_SQLITE_TEST_SQLEAN_DIR="$$(pwd)/$(OUT_SQLEAN_DIR)" \
	$(GO) test ./internal/sqlitedriver -v

$(OUT_DIR):
	mkdir -p "$(OUT_DIR)"

$(OUT_EXT_DIR):
	mkdir -p "$(OUT_EXT_DIR)"

$(OUT_SQLEAN_DIR):
	mkdir -p "$(OUT_SQLEAN_DIR)"

.PHONY: clean
clean:
	rm -rf "$(OUT_DIR)"
	rm -rf third_party/cr-sqlite/core/dist third_party/cr-sqlite/core/dbg
	rm -rf third_party/sqlite-vec/dist
	rm -rf third_party/sqlean/dist
