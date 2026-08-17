# TreeScanner Code Review and Functionality Roadmap

## Scope

This review covers the current Rust workspace: the static analyzer, shared hint schema, AFL++ custom mutator, scripts, and repository documentation. The project has a clear split between hint production in `analyzer`, serialization in `common`, and hint consumption in `mutator`.

## Strengths

- The workspace is small and focused, with a clean separation between analyzer, mutator, and shared model crates.
- The analyzer avoids unsafe Rust and uses tree-sitter queries instead of regular-expression-only source scanning.
- The CLI exposes practical guardrails for large scans, including maximum file count, maximum file size, hint caps, and optional thread control.
- The mutator already weights mutations by severity, which is a useful foundation for prioritizing more security-relevant hints.
- The analyzer has regression tests for global hint loading, sample target detection, direct offset inference, and truncating casts.

## Findings and Risks

### 1. Hint schema lacks stable identifiers and provenance

`StructuralHint` captures location, kind, label, offset, severity, and confidence, but does not include a stable ID, rule ID, source snippet, analyzer version, or evidence trail. This makes it difficult to deduplicate hints across runs, triage false positives, or connect generated hints back to a specific detection rule.

**Recommendation:** Add optional fields such as `rule_id`, `snippet`, `evidence`, and `schema_version`. Keep the fields optional initially to preserve compatibility with existing hint files.

### 2. Global hint catalog is validated but not applied

The analyzer loads and validates the global hint catalog, then only prints the number of loaded hints. No catalog entry currently influences emitted hints, severity, labels, or mutation strategy.

**Recommendation:** Map analyzer detections to catalog `id` values and use catalog metadata to standardize labels, severity, relations, and mutation recommendations.

### 3. Offset inference is too local

Current offset inference records numeric indexes from direct input subscripts and maps them to hints on the same source line. This is useful for simple cases, but misses common patterns such as `size_t n = data[0];`, shifted multi-byte fields, pointer aliases, and helper functions.

**Recommendation:** Extend offset inference with simple dataflow facts: assignment of `data[N]` into local variables, aliases like `p = data + N`, and multi-byte expressions such as `(data[0] << 8) | data[1]`.

### 4. Mutator behavior is byte-oriented despite structural labels

Each hint currently mutates one byte at one offset. Length fields, boundary checks, and vulnerability hints often require coordinated changes across multiple bytes or between a length field and payload size.

**Recommendation:** Add mutation strategies that operate over ranges and related offsets, including endian-aware integer mutations, length-vs-buffer-size mismatches, and dictionary insertion near hinted offsets.

### 5. Error reporting during directory scans hides aggregate quality

Files that fail analysis are skipped with a stderr message, while the final output only reports generated hint count. Users cannot easily tell how many files failed, why they failed, or whether the output is complete enough to trust.

**Recommendation:** Emit an optional scan summary containing processed files, skipped files, parse errors, oversized files, and per-rule hit counts.

### 6. Risky-function detection needs context sensitivity

Calls to allocation and copy APIs are treated as high-risk when their arguments have certain textual shapes. This is intentionally heuristic, but it can create false positives for guarded calls and false negatives for wrappers.

**Recommendation:** Detect nearby dominating bounds checks, known safe wrappers, and common destination-size patterns. Surface the confidence adjustment in reports.

## Proposed Additional Functionality

### A. Rich hint schema and compatibility layer

Add optional fields to hints:

- `id`: deterministic hash of file, line, column, kind, and normalized label.
- `rule_id`: stable detector name such as `c.boundary_check.input_influenced`.
- `byte_width`: expected field width where known.
- `endianness`: `little`, `big`, or `unknown`.
- `related_offsets`: offsets that should be mutated together.
- `snippet`: short source excerpt for report/debug use.

This would make hints more actionable for both humans and mutators while keeping old hint files readable.

### B. SARIF export

Add `--sarif <path>` to the analyzer so findings can be imported into GitHub code scanning and security dashboards. Each structural hint can become a SARIF result with rule metadata, source location, severity, confidence, and suggested fuzzing mutation.

### C. Analyzer rule statistics

Add `--stats <path>` to emit machine-readable scan telemetry:

- number of files discovered, analyzed, skipped, and failed;
- number of hints per kind and per severity;
- top files by hint count;
- percentage of hints with inferred offsets.

This would help users evaluate analyzer quality before starting an expensive fuzzing run.

### D. Multi-byte and relation-aware mutator

Teach the AFL++ mutator to consume richer hints and apply coordinated mutations:

- write boundary values to 16-bit, 32-bit, and 64-bit fields;
- mutate length fields to be smaller/larger than actual payload length;
- synchronize or intentionally desynchronize related length and offset fields;
- insert or delete payload bytes near fields whose labels mention copy, allocation, or boundary behavior.

### E. Corpus minimization hints

Add a helper that groups generated inputs by which hint IDs they exercise. This can complement AFL++ coverage by preserving structurally distinct inputs even when edge coverage is similar.

### F. Report usability improvements

Enhance the HTML report with filtering and sorting by severity, kind, confidence, file, and whether an offset was inferred. Add rule descriptions and mutation recommendations directly in the report.

## Suggested Implementation Order

1. Add optional schema fields and keep serialization backward-compatible. **Implemented.**
2. Wire analyzer detections to stable `rule_id` values and catalog metadata. **Implemented.**
3. Add `--stats` output because it is low-risk and immediately useful. **Implemented.**
4. Improve offset inference for assignment chains and multi-byte expressions.
5. Add multi-byte and relation-aware mutator strategies.
6. Add SARIF export once rule IDs and provenance are stable.

## Review Verdict

TreeScanner is a promising prototype with a practical architecture. The highest-value next step is not to add more heuristic detectors immediately, but to improve hint provenance, scan telemetry, and mutator expressiveness so that existing detections become easier to trust, debug, and exploit during fuzzing.
