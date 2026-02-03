.PHONY: all build release debug test clean static static-full static-freebsd static-freebsd-full coverage fuzz fuzz-smoke install uninstall help

BINS := kunci-server kunci-client kunci-dmcrypt
MUSL_TARGET := x86_64-unknown-linux-musl
FREEBSD_TARGET := x86_64-unknown-freebsd

all: build

build:
	cargo build --workspace

release:
	cargo build --workspace --release

debug:
	cargo build --workspace

test:
	cargo test --workspace

clean:
	cargo clean

coverage:
	sh ./scripts/coverage.sh

fuzz:
	@if ! command -v cargo-fuzz >/dev/null 2>&1; then \
		echo "cargo-fuzz not found; install with 'cargo install cargo-fuzz'"; \
		exit 1; \
	fi
	@cargo fuzz list

fuzz-smoke:
	@if ! command -v cargo-fuzz >/dev/null 2>&1; then \
		echo "cargo-fuzz not found; install with 'cargo install cargo-fuzz'"; \
		exit 1; \
	fi
	@if command -v rustup >/dev/null 2>&1; then \
		if ! rustup toolchain list | grep -q '^nightly'; then \
			echo "rustup nightly toolchain is required; install with 'rustup toolchain install nightly'"; \
			exit 1; \
		fi; \
	else \
		echo "rustup not found; install nightly or run 'cargo +nightly fuzz' manually"; \
		exit 1; \
	fi
	@FUZZ_TIME=$${FUZZ_TIME:-30}; \
	for target in `cargo +nightly fuzz list`; do \
		echo "Fuzzing $$target for $$FUZZ_TIME seconds"; \
		cargo +nightly fuzz run $$target -- -max_total_time=$$FUZZ_TIME; \
	done

static:
	@OS=`uname -s`; \
	if [ "$$OS" = "FreeBSD" ]; then \
		echo "musl target not supported on FreeBSD; skipping"; \
	else \
		if ! command -v x86_64-linux-musl-gcc >/dev/null 2>&1; then \
			echo "x86_64-linux-musl-gcc not found; install musl tools or set CC"; \
			exit 1; \
		fi; \
		rustup target add $(MUSL_TARGET); \
		for bin in $(BINS); do \
			if [ "$$bin" = "kunci-dmcrypt" ] && [ -z "$$ALLOW_DMCRYPT" ]; then \
				echo "Skipping kunci-dmcrypt (not supported for musl static)"; \
				continue; \
			fi; \
			cargo build --release --target $(MUSL_TARGET) -p $$bin; \
		done; \
	fi

static-full:
	@OS=`uname -s`; \
	if [ "$$OS" = "FreeBSD" ]; then \
		echo "musl target not supported on FreeBSD; skipping"; \
	else \
		if ! command -v x86_64-linux-musl-gcc >/dev/null 2>&1; then \
			echo "x86_64-linux-musl-gcc not found; install musl tools or set CC"; \
			exit 1; \
		fi; \
		rustup target add $(MUSL_TARGET); \
		for bin in $(BINS); do \
			if [ "$$bin" = "kunci-dmcrypt" ] && [ -z "$$ALLOW_DMCRYPT" ]; then \
				echo "Skipping kunci-dmcrypt (not supported for musl static)"; \
				continue; \
			fi; \
			if [ "$$bin" = "kunci-dmcrypt" ]; then \
				cargo build --release --target $(MUSL_TARGET) -p $$bin; \
			else \
				cargo build --release --target $(MUSL_TARGET) --features full -p $$bin; \
			fi; \
		done; \
	fi

static-freebsd:
	@if command -v rustup >/dev/null 2>&1; then \
		rustup target add $(FREEBSD_TARGET); \
	else \
		echo "rustup not found; assuming $(FREEBSD_TARGET) toolchain is installed"; \
	fi
	@for bin in $(BINS); do \
		if [ "$$bin" = "kunci-dmcrypt" ] && [ -z "$$ALLOW_DMCRYPT" ]; then \
			echo "Skipping kunci-dmcrypt (requires libcryptsetup headers)"; \
			continue; \
		fi; \
		cargo build --release --target $(FREEBSD_TARGET) -p $$bin; \
	done

static-freebsd-full:
	@if command -v rustup >/dev/null 2>&1; then \
		rustup target add $(FREEBSD_TARGET); \
	else \
		echo "rustup not found; assuming $(FREEBSD_TARGET) toolchain is installed"; \
	fi
	@for bin in $(BINS); do \
		if [ "$$bin" = "kunci-dmcrypt" ]; then \
			if [ -z "$$ALLOW_DMCRYPT" ]; then \
				echo "Skipping kunci-dmcrypt (requires libcryptsetup headers)"; \
				continue; \
			fi; \
			cargo build --release --target $(FREEBSD_TARGET) -p $$bin; \
		else \
			cargo build --release --target $(FREEBSD_TARGET) --features full -p $$bin; \
		fi; \
	done

install:
	@for bin in $(BINS); do \
		install -Dm755 target/release/$$bin /usr/local/bin/$$bin; \
	done

uninstall:
	@for bin in $(BINS); do \
		rm -f /usr/local/bin/$$bin; \
	done

help:
	@echo "Available targets:"
	@echo "  all          - Build the project (default)"
	@echo "  build        - Build the project"
	@echo "  release      - Build release version"
	@echo "  debug        - Build debug version"
	@echo "  test         - Run tests"
	@echo "  clean        - Clean build artifacts"
	@echo "  coverage     - Run llvm-cov and emit lcov report (scripts/coverage.sh)"
	@echo "  fuzz         - List available fuzz targets"
	@echo "  fuzz-smoke   - Run each fuzz target for a short duration (default 30s)"
	@echo "  static       - Build statically linked binaries (musl)"
	@echo "  static-full  - Build statically linked binaries with full features"
	@echo "  install      - Install binaries to /usr/local/bin (requires root)"
	@echo "  uninstall    - Uninstall binaries from /usr/local/bin"
	@echo "  help         - Show this help message"

musl: static
