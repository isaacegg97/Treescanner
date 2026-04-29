# TreeScanner

TreeScanner is a structure-aware analyzer + AFL++ custom mutator.

## Quick Start
1. Build analyzer: `cargo build --release -p analyzer`
2. Analyze target: `./target/release/analyzer test_target.c -o hints.json --report report.html`
3. Build mutator: `cargo build --release -p mutator`
4. Fuzz with AFL++:
   `TREESCANNER_HINTS=hints.json afl-fuzz -i seeds -o out -l ./target/release/libmutator.so ./fuzz_target`

## Offset Inference Strategy
- Direct subscript: `data[0]` => offset `0`
- Assignment-chain and parameter-context guided inference (heuristic)
- Unknown complex cases remain `None`

## Known Limitations
- Heuristic offset inference (best effort)
- Lightweight dataflow only
- Assumes linear byte-buffer style inputs

## Benchmarking
Run `scripts/benchmark.sh test_target.c 60` as a baseline scaffold.
