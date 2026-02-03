#!/usr/bin/env sh

set -eu

if ! command -v cargo >/dev/null 2>&1; then
    echo "ERROR: cargo not found" >&2
    exit 1
fi

if ! command -v cargo-llvm-cov >/dev/null 2>&1; then
    echo "ERROR: cargo-llvm-cov not found (install with 'cargo install cargo-llvm-cov')" >&2
    exit 1
fi

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

OUT_DIR="${OUT_DIR:-/tmp}"
OUT_FILE="${OUT_FILE:-${OUT_DIR}/kunci.lcov}"

cargo llvm-cov \
  -p kunci-core \
  -p kunci-server \
  -p kunci-client \
  --features full \
  --lcov \
  --output-path "$OUT_FILE"

echo "Coverage written to $OUT_FILE"
