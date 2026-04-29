#!/usr/bin/env bash
set -euo pipefail

if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo not found in PATH"
  exit 1
fi

if ! cargo audit --version >/dev/null 2>&1; then
  echo "cargo-audit is not installed. Install with: cargo install cargo-audit"
  exit 1
fi

echo "Running cargo audit against Cargo.lock..."
cargo audit
