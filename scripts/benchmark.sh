#!/usr/bin/env bash
set -euo pipefail
TARGET=${1:-test_target.c}
BASELINE_TIME=${2:-60}
echo "=== TreeScanner Benchmark ==="
echo "Target: $TARGET"
echo "Baseline time: ${BASELINE_TIME}s"
echo "Build and runtime scaffold only; requires AFL++ tooling in PATH."
