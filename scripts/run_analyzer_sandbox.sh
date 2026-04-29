#!/usr/bin/env bash
set -euo pipefail

if [[ $# -eq 0 ]]; then
  echo "Usage: $0 <target-path> [--output <hints.json>] [--report <report.html>] [extra analyzer args]"
  exit 1
fi

analyzer_bin="${ANALYZER_BIN:-}"

if [[ -z "${analyzer_bin}" ]]; then
  export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-target}"
  cargo build -p analyzer >/dev/null
  analyzer_bin="${CARGO_TARGET_DIR}/debug/analyzer"
fi

# Constrain analyzer resource use to reduce blast radius if a parser dependency misbehaves.
ulimit -t "${TS_CPU_SECONDS:-30}"   # CPU seconds
ulimit -v "${TS_VMEM_KB:-1048576}"  # Virtual memory (1 GiB by default)
ulimit -f "${TS_FILE_KB:-10240}"    # Max output file size (10 MiB)
if [[ -n "${TS_NPROC:-}" ]]; then
  ulimit -u "${TS_NPROC}"           # Max processes (optional; can break rayon in constrained envs)
fi

export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-1}"

exec "${analyzer_bin}" "$@"
