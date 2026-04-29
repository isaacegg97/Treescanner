TreeScanner

Structure-aware mutation engine for coverage-guided fuzzing

Overview

TreeScanner augments traditional fuzzers by introducing code-structure-aware mutations derived from static analysis.

Instead of relying solely on random mutations, TreeScanner identifies structurally significant input regions (e.g., length fields, branch conditions, table indices) and applies targeted mutations to maximize code coverage and bug discovery.

Motivation

Modern fuzzers like AFL++ are highly effective but fundamentally blind to program structure.

TreeScanner addresses this limitation by:

extracting structural hints from source code using Tree-sitter
mapping those hints to input mutation strategies
biasing fuzzing toward semantically meaningful changes
Features
Tree-sitter-based static analysis
detects length fields, boundary checks, and indexing patterns
Structure-aware mutation rules
targeted mutations based on code semantics
AFL++ integration
works as a custom mutator
Feedback-driven prioritization
ranks mutation strategies based on coverage gains
Architecture
          Source Code
               ↓
        Tree-sitter Parser
               ↓
     Structural Pattern Extractor
               ↓
        Mutation Rule Engine
               ↓
        AFL++ Custom Mutator
               ↓
        Target Application
               ↓
        Coverage Feedback
               ↺
Example

Given code:

len = data[i];
buffer.SetLength(len);

TreeScanner identifies:

data[i] as a length field

Generated mutations:

set to 0
set to max
off-by-one variations
inconsistent payload sizes
Use Cases
parser fuzzing (binary formats, protocols)
browser components (e.g., Chromium subsystems)
media decoders
network protocol handlers
Limitations
heuristic mapping between code and input offsets
no full dataflow or taint tracking
effectiveness depends on input structure visibility
Roadmap
improved offset inference
lightweight taint tracking
mutation prioritization via reinforcement learning
grammar inference integration
Philosophy

TreeScanner does not attempt to replace fuzzers.

It augments them by answering a simple question:

“Where should we push to make the program break?”

Security Hardening

TreeScanner links third-party parsing and fuzzing components, so the project now includes explicit runtime controls:

- Analyzer guardrails:
  - `--max-files` limits how many files are scanned in one run
  - `--max-file-size-bytes` skips oversized files
  - `--max-hints-per-file` prevents unbounded hint growth
- Sandbox wrapper:
  - `scripts/run_analyzer_sandbox.sh` runs analyzer with `ulimit` caps (CPU, memory, file size, process count)
- Dependency audit:
  - `scripts/dependency_audit.sh` runs `cargo audit` against `Cargo.lock`

Example hardened run:

`scripts/run_analyzer_sandbox.sh test_target.c --output hints.json --report report.html --global-hints global_hints.json --max-files 2000 --max-file-size-bytes 1048576 --max-hints-per-file 2000`