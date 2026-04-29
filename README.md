# TreeScanner

[![Rust](https://img.shields.io/badge/language-Rust-orange.svg)](https://www.rust-lang.org/)
[![AFL++](https://img.shields.io/badge/fuzzing-AFL%2B%2B-red.svg)](https://aflplus.plus/)

TreeScanner is an experimental, structure-aware program analyzer and custom mutator for AFL++. It bridges the gap between static analysis and dynamic fuzzing by inferring input structure constraints from source code and using them to guide mutation.

## 🚀 Overview

Typical fuzzers treat inputs as opaque byte streams. TreeScanner uses a two-stage approach to make fuzzing "smarter":

1.  **Static Analysis:** The `analyzer` parses source code to identify how an application accesses its input buffer (e.g., through subscripts, offsets, or specific parameter contexts).
2.  **Guided Mutation:** The `mutator` (built as an AFL++ custom mutator) consumes these "hints" to perform structure-aware mutations, focusing on the specific offsets and data types identified during analysis.

## 🛠 Project Structure

* **/analyzer**: A Rust-based static analysis tool that generates structure hints from C code.
* **/mutator**: An AFL++ compatible custom mutator that uses hints to guide the fuzzer.
* **/common**: Shared logic and data structures for hint serialization.
* **/scripts**: Utility scripts for benchmarking and automation.

## 🚦 Quick Start

### 1. Prerequisites
* Rust (latest stable)
* AFL++ installed and in your PATH
* Clang/LLVM (for target compilation)

### 2. Build the Toolkit
```bash
# Build the static analyzer
cargo build --release -p analyzer

# Build the custom mutator library
cargo build --release -p mutator
```

### 3. Analyze a Target
Run the analyzer on your source file to generate a `hints.json` file and a visual report:
```bash
./target/release/analyzer test_target.c -o hints.json --report report.html
```

### 4. Fuzz with AFL++
Pass the generated hints to the mutator via the `TREESCANNER_HINTS` environment variable:
```bash
TREESCANNER_HINTS=hints.json \
afl-fuzz -i seeds -o out -l ./target/release/libmutator.so -- ./your_fuzz_target
```

## 🧠 Technical Strategy

### Offset Inference
TreeScanner employs several heuristics to understand how data is used:
* **Direct Subscripts:** Automatically identifies `data[x]` patterns to map specific offsets.
* **Assignment Chains:** Traces how input data is passed through local variables to identify secondary offsets.
* **Contextual Inference:** Heuristically determines potential field boundaries based on parameter usage in common C functions.

### Limitations
* **Heuristic Nature:** Offset inference is "best effort" and may miss complex pointer arithmetic.
* **Linear Buffers:** The current implementation assumes a linear, byte-buffer style input.
* **Language Support:** Primary support is currently focused on C.

## 📊 Benchmarking
You can run the included benchmark scaffold to see how TreeScanner performs against a baseline:
```bash
./scripts/benchmark.sh test_target.c 60
```
