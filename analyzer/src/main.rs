#![forbid(unsafe_code)]

use anyhow::Result;
use clap::Parser;
mod offset_inference;

use common::{HintKind, Severity, StructuralHint, StructuralMap};
use offset_inference::{infer_offset_for_hint, OffsetContext};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use tera::{Context, Tera};
use tree_sitter::{Query, QueryCursor, StreamingIterator};
use walkdir::WalkDir;

#[derive(Parser, Debug)]
struct Args {
    #[arg(value_name = "TARGET")]
    input: PathBuf,

    #[arg(short, long, default_value = "hints.json")]
    output: PathBuf,

    #[arg(short, long)]
    report: Option<PathBuf>,

    #[arg(short, long)]
    threads: Option<usize>,

    #[arg(long, default_value = "global_hints.json")]
    global_hints: PathBuf,

    #[arg(long, default_value_t = 5000)]
    max_files: usize,

    #[arg(long, default_value_t = 1048576)]
    max_file_size_bytes: u64,

    #[arg(long, default_value_t = 2000)]
    max_hints_per_file: usize,

    #[arg(long)]
    stats: Option<PathBuf>,
}

#[derive(Serialize)]
struct ReportStats {
    files_count: usize,
    hints_count: usize,
    length_fields: usize,
    vulnerabilities: usize,
    influence_edges: usize,
}

#[derive(Debug, Serialize)]
struct ScanStats {
    files_discovered: usize,
    files_analyzed: usize,
    files_failed: usize,
    hints_count: usize,
    hints_with_offsets: usize,
    hints_by_kind: HashMap<String, usize>,
    hints_by_severity: HashMap<String, usize>,
    top_files_by_hint_count: Vec<FileHintCount>,
}

#[derive(Debug, Serialize)]
struct FileHintCount {
    file: String,
    hints: usize,
}

#[derive(Debug, Deserialize)]
struct GlobalHintCatalog {
    version: String,
    hints: Vec<GlobalHint>,
}

#[derive(Debug, Deserialize)]
struct GlobalHint {
    id: String,
    kind: String,
    category: String,
    severity: String,
    label: String,
    relations: Vec<String>,
    signals: Vec<String>,
    mutations: Vec<String>,
}

impl GlobalHintCatalog {
    fn by_id(&self) -> HashMap<&str, &GlobalHint> {
        self.hints
            .iter()
            .map(|hint| (hint.id.as_str(), hint))
            .collect()
    }
}

#[derive(Clone, Copy)]
struct AnalyzerLimits {
    max_file_size_bytes: u64,
    max_hints_per_file: usize,
}

fn push_hint_limited(hints: &mut Vec<StructuralHint>, hint: StructuralHint, limit: usize) {
    if hints.len() < limit {
        hints.push(hint);
    }
}

fn load_global_hints(path: &Path) -> Result<GlobalHintCatalog> {
    let content = fs::read_to_string(path)?;
    let catalog: GlobalHintCatalog = serde_json::from_str(&content)?;

    if catalog.version.trim().is_empty() {
        anyhow::bail!("global hints missing version");
    }

    for hint in &catalog.hints {
        if hint.id.trim().is_empty()
            || hint.kind.trim().is_empty()
            || hint.category.trim().is_empty()
            || hint.severity.trim().is_empty()
            || hint.label.trim().is_empty()
        {
            anyhow::bail!("global hint has an empty required field");
        }
        if hint.relations.is_empty() || hint.signals.is_empty() || hint.mutations.is_empty() {
            anyhow::bail!(
                "global hint {} missing relations/signals/mutations",
                hint.id
            );
        }
    }

    Ok(catalog)
}

fn is_input_like(name: &str) -> bool {
    let n = name.to_lowercase();
    n.contains("data")
        || n.contains("buf")
        || n.contains("input")
        || n.contains("packet")
        || n.contains("msg")
        || n.contains("payload")
}

fn parse_severity(input: &str) -> Severity {
    match input.to_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        _ => Severity::Low,
    }
}

fn default_confidence() -> f32 {
    0.6
}

fn node_snippet(source: &str, node: tree_sitter::Node<'_>) -> String {
    node.utf8_text(source.as_bytes())
        .unwrap_or_default()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(160)
        .collect()
}

fn stable_hint_id(hint: &StructuralHint) -> String {
    let mut hasher = DefaultHasher::new();
    hint.file.hash(&mut hasher);
    hint.line.hash(&mut hasher);
    hint.column.hash(&mut hasher);
    format!("{:?}", hint.kind).hash(&mut hasher);
    hint.label.hash(&mut hasher);
    hint.rule_id.hash(&mut hasher);
    format!("ts-{:016x}", hasher.finish())
}

fn make_hint(
    path: &Path,
    node: tree_sitter::Node<'_>,
    kind: HintKind,
    label: impl Into<String>,
    severity: Severity,
    rule_id: &'static str,
    evidence: impl Into<String>,
    source: &str,
) -> StructuralHint {
    let mut hint = StructuralHint::new(
        path.to_string_lossy().into(),
        node.start_position().row + 1,
        node.start_position().column,
        kind,
        label.into(),
        severity,
        default_confidence(),
    )
    .with_rule_id(rule_id)
    .with_snippet(node_snippet(source, node))
    .with_evidence(evidence);
    hint.id = Some(stable_hint_id(&hint));
    hint
}

fn kind_name(kind: &HintKind) -> &'static str {
    match kind {
        HintKind::LengthField => "LengthField",
        HintKind::BoundaryCheck => "BoundaryCheck",
        HintKind::ArrayIndex => "ArrayIndex",
        HintKind::Vulnerability => "Vulnerability",
    }
}

fn severity_name(severity: &Severity) -> &'static str {
    match severity {
        Severity::Low => "Low",
        Severity::Medium => "Medium",
        Severity::High => "High",
        Severity::Critical => "Critical",
    }
}

fn build_scan_stats(
    files_discovered: usize,
    files_failed: usize,
    hints: &[StructuralHint],
) -> ScanStats {
    let mut hints_by_kind = HashMap::new();
    let mut hints_by_severity = HashMap::new();
    let mut hints_by_file = HashMap::new();

    for hint in hints {
        *hints_by_kind
            .entry(kind_name(&hint.kind).to_string())
            .or_insert(0) += 1;
        *hints_by_severity
            .entry(severity_name(&hint.severity).to_string())
            .or_insert(0) += 1;
        *hints_by_file.entry(hint.file.clone()).or_insert(0) += 1;
    }

    let mut top_files_by_hint_count: Vec<_> = hints_by_file
        .into_iter()
        .map(|(file, hints)| FileHintCount { file, hints })
        .collect();
    top_files_by_hint_count.sort_by(|a, b| b.hints.cmp(&a.hints).then_with(|| a.file.cmp(&b.file)));
    top_files_by_hint_count.truncate(10);

    ScanStats {
        files_discovered,
        files_analyzed: files_discovered.saturating_sub(files_failed),
        files_failed,
        hints_count: hints.len(),
        hints_with_offsets: hints.iter().filter(|h| h.offset.is_some()).count(),
        hints_by_kind,
        hints_by_severity,
        top_files_by_hint_count,
    }
}

fn apply_global_catalog_metadata(hints: &mut [StructuralHint], catalog: &GlobalHintCatalog) {
    let catalog_by_id = catalog.by_id();
    for hint in hints {
        let Some(rule_id) = hint.rule_id.as_deref() else {
            continue;
        };
        let Some(global_hint) = catalog_by_id.get(rule_id) else {
            continue;
        };

        hint.severity = parse_severity(&global_hint.severity);
        hint.evidence
            .push(format!("catalog label: {}", global_hint.label));
        hint.evidence
            .push(format!("catalog kind: {}", global_hint.kind));
        hint.evidence
            .push(format!("catalog category: {}", global_hint.category));
        hint.evidence.push(format!(
            "catalog relations: {}",
            global_hint.relations.join(", ")
        ));
        hint.evidence.push(format!(
            "catalog signals: {}",
            global_hint.signals.join(", ")
        ));
        hint.evidence.push(format!(
            "recommended mutations: {}",
            global_hint.mutations.join(", ")
        ));
    }
}

fn process_file(path: &Path, limits: AnalyzerLimits) -> Result<Vec<StructuralHint>> {
    let meta = fs::metadata(path)?;
    if meta.len() > limits.max_file_size_bytes {
        anyhow::bail!(
            "file too large ({} bytes > {}): {}",
            meta.len(),
            limits.max_file_size_bytes,
            path.display()
        );
    }

    let source = fs::read_to_string(path)?;
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&tree_sitter_c::LANGUAGE.into())?;

    let tree = parser.parse(&source, None).ok_or_else(|| {
        anyhow::anyhow!("tree-sitter parser returned no tree for {}", path.display())
    })?;

    let mut cursor = QueryCursor::new();
    let mut hints = Vec::new();

    let lang = tree_sitter_c::LANGUAGE.into();

    // ----------------------------
    // 1. Input-derived identifiers
    // ----------------------------
    let query_inputs = Query::new(
        &lang,
        r#"
        (parameter_declaration
            declarator: (identifier) @param)
    "#,
    )?;

    let mut input_vars = HashSet::new();

    let mut matches = cursor.matches(&query_inputs, tree.root_node(), source.as_bytes());
    while let Some(m) = matches.next() {
        for c in m.captures {
            let name = query_inputs.capture_names()[c.index as usize];
            if name == "param" {
                let var = c.node.utf8_text(source.as_bytes())?.to_string();
                input_vars.insert(var);
            }
        }
    }

    // ----------------------------
    // 2. Assignment tracking (1-hop taint)
    // ----------------------------
    let query_assign = Query::new(
        &lang,
        r#"
        (assignment_expression
            left: (identifier) @lhs
            right: (_) @rhs)
    "#,
    )?;

    let mut var_origin: HashMap<String, String> = HashMap::new();

    let mut matches = cursor.matches(&query_assign, tree.root_node(), source.as_bytes());
    while let Some(m) = matches.next() {
        let mut lhs: Option<String> = None;
        let mut rhs_text: Option<String> = None;

        for c in m.captures {
            let name = query_assign.capture_names()[c.index as usize];
            match name {
                "lhs" => lhs = Some(c.node.utf8_text(source.as_bytes())?.to_string()),
                "rhs" => rhs_text = Some(c.node.utf8_text(source.as_bytes())?.to_string()),
                _ => {}
            }
        }

        if let (Some(l), Some(r)) = (lhs, rhs_text) {
            if is_input_like(&r) || input_vars.contains(&r) {
                var_origin.insert(l.clone(), "input".to_string());
            } else {
                var_origin.insert(l.clone(), "derived".to_string());
            }
        }
    }

    // ----------------------------
    // 3. Length field detection (structural, not lexical)
    // ----------------------------
    let query_len = Query::new(
        &lang,
        r#"
        (assignment_expression
            left: (identifier) @lhs
            right: (subscript_expression) @rhs)
    "#,
    )?;

    let mut matches = cursor.matches(&query_len, tree.root_node(), source.as_bytes());
    while let Some(m) = matches.next() {
        let mut lhs = None;
        let mut rhs_node = None;

        for c in m.captures {
            let name = query_len.capture_names()[c.index as usize];
            match name {
                "lhs" => lhs = Some(c.node.utf8_text(source.as_bytes())?.to_string()),
                "rhs" => rhs_node = Some(c.node),
                _ => {}
            }
        }

        if let (Some(var), Some(node)) = (lhs, rhs_node) {
            if is_input_like(&var) || var_origin.contains_key(&var) {
                push_hint_limited(
                    &mut hints,
                    make_hint(
                        path,
                        node,
                        HintKind::LengthField,
                        format!("Input-derived length field: {}", var),
                        Severity::Medium,
                        "core.length_field",
                        format!("assignment from input-derived subscript into {var}"),
                        &source,
                    ),
                    limits.max_hints_per_file,
                );
            }
        }
    }

    // ----------------------------
    // 4. Boundary checks with input-shaped variables
    // ----------------------------
    let query_bounds = Query::new(
        &lang,
        r#"
        (if_statement
            condition: (_) @cond)
    "#,
    )?;

    let mut matches = cursor.matches(&query_bounds, tree.root_node(), source.as_bytes());
    while let Some(m) = matches.next() {
        for c in m.captures {
            let name = query_bounds.capture_names()[c.index as usize];
            if name == "cond" {
                let cond_text = c.node.utf8_text(source.as_bytes())?.to_lowercase();
                if cond_text.contains("len")
                    || cond_text.contains("size")
                    || cond_text.contains("data")
                    || cond_text.contains("buf")
                {
                    push_hint_limited(
                        &mut hints,
                        make_hint(
                            path,
                            c.node,
                            HintKind::BoundaryCheck,
                            "Input-influenced boundary check",
                            Severity::Medium,
                            "core.boundary_check",
                            "if condition references input-shaped data, length, or size",
                            &source,
                        ),
                        limits.max_hints_per_file,
                    );
                }
            }
        }
    }

    // ----------------------------
    // 5. Table/array index with input-shaped index
    // ----------------------------
    let query_index = Query::new(
        &lang,
        r#"
        (subscript_expression
            index: (_) @idx)
    "#,
    )?;
    let mut matches = cursor.matches(&query_index, tree.root_node(), source.as_bytes());
    while let Some(m) = matches.next() {
        for c in m.captures {
            let name = query_index.capture_names()[c.index as usize];
            if name == "idx" {
                let idx_text = c.node.utf8_text(source.as_bytes())?.to_lowercase();
                if idx_text.contains("len")
                    || idx_text.contains("size")
                    || idx_text.contains("idx")
                    || idx_text.contains("offset")
                    || idx_text.contains("data")
                {
                    push_hint_limited(
                        &mut hints,
                        make_hint(
                            path,
                            c.node,
                            HintKind::ArrayIndex,
                            "Input-influenced array/table index",
                            Severity::High,
                            "core.table_index",
                            "subscript index references input-shaped data, length, size, idx, or offset",
                            &source,
                        ),
                        limits.max_hints_per_file,
                    );
                }
            }
        }
    }

    // ----------------------------
    // 6. Risky function coupling (structural, not string-based)
    // ----------------------------
    let query_calls = Query::new(
        &lang,
        r#"
        (call_expression
            function: (identifier) @func
            arguments: (argument_list) @args)
    "#,
    )?;

    let risky = ["memcpy", "memmove", "malloc", "realloc", "strcpy", "strcat"];

    let mut matches = cursor.matches(&query_calls, tree.root_node(), source.as_bytes());
    while let Some(m) = matches.next() {
        let mut func = None;
        let mut args = None;

        for c in m.captures {
            let name = query_calls.capture_names()[c.index as usize];
            match name {
                "func" => func = Some(c.node.utf8_text(source.as_bytes())?.to_string()),
                "args" => args = Some(c.node),
                _ => {}
            }
        }

        if let (Some(f), Some(n)) = (func, args) {
            if risky.contains(&f.as_str()) {
                let text = n.utf8_text(source.as_bytes())?;
                let lower_f = f.to_lowercase();

                let has_input_shape = text.contains('[')
                    || text.contains("len")
                    || text.contains("size")
                    || lower_f == "malloc"
                    || lower_f == "realloc";

                if has_input_shape {
                    let label = if lower_f == "memcpy"
                        || lower_f == "memmove"
                        || lower_f == "strcpy"
                        || lower_f == "strcat"
                    {
                        format!("Unchecked copy pattern in {}", f)
                    } else {
                        format!("Dangerous allocation pattern in {}", f)
                    };
                    push_hint_limited(
                        &mut hints,
                        make_hint(
                            path,
                            n,
                            HintKind::Vulnerability,
                            label,
                            Severity::High,
                            if lower_f == "malloc" || lower_f == "realloc" {
                                "ap.dangerous_allocation"
                            } else {
                                "ap.unchecked_copy"
                            },
                            format!("risky call `{f}` has input-shaped arguments"),
                            &source,
                        ),
                        limits.max_hints_per_file,
                    );
                }
            }
        }
    }

    // ----------------------------
    // 7. Truncating casts (integer narrowing)
    // ----------------------------
    let query_casts = Query::new(
        &lang,
        r#"
        (cast_expression
            type: (type_descriptor) @ty
            value: (_) @val)
    "#,
    )?;
    let mut matches = cursor.matches(&query_casts, tree.root_node(), source.as_bytes());
    while let Some(m) = matches.next() {
        let mut ty = None;
        let mut val = None;
        for c in m.captures {
            let name = query_casts.capture_names()[c.index as usize];
            match name {
                "ty" => ty = Some(c.node.utf8_text(source.as_bytes())?.to_lowercase()),
                "val" => val = Some(c.node),
                _ => {}
            }
        }

        if let (Some(ty_text), Some(val_node)) = (ty, val) {
            let is_narrow = ty_text.contains("char")
                || ty_text.contains("short")
                || ty_text.contains("uint8_t")
                || ty_text.contains("int8_t");
            if is_narrow {
                push_hint_limited(
                    &mut hints,
                    make_hint(
                        path,
                        val_node,
                        HintKind::Vulnerability,
                        "Truncating cast from potentially larger value",
                        Severity::High,
                        "ap.truncating_cast",
                        format!("cast target type `{ty_text}` is narrower than common size types"),
                        &source,
                    ),
                    limits.max_hints_per_file,
                );
            }
        }
    }

    // ----------------------------
    // 8. Early-exit validation bypass patterns
    // ----------------------------
    let query_early_exit = Query::new(
        &lang,
        r#"
        (if_statement
            consequence: (compound_statement
                (return_statement) @ret))
    "#,
    )?;
    let mut matches = cursor.matches(&query_early_exit, tree.root_node(), source.as_bytes());
    while let Some(m) = matches.next() {
        for c in m.captures {
            if query_early_exit.capture_names()[c.index as usize] == "ret" {
                push_hint_limited(
                    &mut hints,
                    make_hint(
                        path,
                        c.node,
                        HintKind::Vulnerability,
                        "Early exit may bypass validation or cleanup",
                        Severity::Medium,
                        "ap.state_desync",
                        "if statement consequence returns early",
                        &source,
                    ),
                    limits.max_hints_per_file,
                );
            }
        }
    }

    let offset_context = OffsetContext::new(&source, &tree)?;
    for hint in hints.iter_mut() {
        if hint.offset.is_none() {
            hint.offset = infer_offset_for_hint(hint, &source, &tree, &offset_context);
            if hint.offset.is_some() {
                hint.confidence = 0.9;
            }
        }
    }

    Ok(hints)
}

fn main() -> Result<()> {
    let args = Args::parse();

    let global_catalog = load_global_hints(&args.global_hints)?;
    println!(
        "Loaded {} global hints from {}",
        global_catalog.hints.len(),
        args.global_hints.display()
    );

    if let Some(t) = args.threads {
        rayon::ThreadPoolBuilder::new()
            .num_threads(t)
            .build_global()?;
    }

    let mut files = Vec::new();

    if args.input.is_dir() {
        for entry in WalkDir::new(&args.input).into_iter().filter_map(|e| e.ok()) {
            let p = entry.path();
            let is_c_family = p
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| matches!(e, "c" | "cpp" | "h"))
                .unwrap_or(false);
            if is_c_family {
                files.push(p.to_path_buf());
            }
        }
    } else {
        files.push(args.input.clone());
    }

    if files.len() > args.max_files {
        files.truncate(args.max_files);
    }

    let limits = AnalyzerLimits {
        max_file_size_bytes: args.max_file_size_bytes,
        max_hints_per_file: args.max_hints_per_file,
    };

    println!("Scanning {} files...", files.len());

    let processed_results: Vec<_> = files.par_iter().map(|f| process_file(f, limits)).collect();

    let mut files_failed = 0;
    let mut all_hints: Vec<_> = processed_results
        .into_iter()
        .filter_map(|res| match res {
            Ok(hints) => Some(hints),
            Err(err) => {
                files_failed += 1;
                eprintln!("Skipping file due to analysis error: {err}");
                None
            }
        })
        .flatten()
        .collect();
    apply_global_catalog_metadata(&mut all_hints, &global_catalog);

    let map = StructuralMap::new(all_hints.clone());

    fs::write(&args.output, serde_json::to_string_pretty(&map)?)?;

    let stats = build_scan_stats(files.len(), files_failed, &all_hints);
    if let Some(stats_path) = args.stats {
        fs::write(&stats_path, serde_json::to_string_pretty(&stats)?)?;
    }

    if let Some(report_path) = args.report {
        let mut tera = Tera::default();
        tera.add_raw_template("report", include_str!("report_template.html"))?;

        let mut ctx = Context::new();
        ctx.insert("hints", &all_hints);

        let stats = ReportStats {
            files_count: files.len(),
            hints_count: all_hints.len(),
            length_fields: all_hints
                .iter()
                .filter(|h| matches!(h.kind, HintKind::LengthField))
                .count(),
            vulnerabilities: all_hints
                .iter()
                .filter(|h| matches!(h.kind, HintKind::Vulnerability))
                .count(),
            influence_edges: all_hints.len(),
        };

        ctx.insert("stats", &stats);

        fs::write(&report_path, tera.render("report", &ctx)?)?;
    }

    println!("Done. {} hints generated.", all_hints.len());

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn repo_root() -> PathBuf {
        match PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent() {
            Some(parent) => parent.to_path_buf(),
            None => panic!("analyzer should be nested in workspace root"),
        }
    }

    fn write_temp_c_file(contents: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        let ts = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(d) => d.as_nanos(),
            Err(_) => 0,
        };
        path.push(format!("treescanner_test_{ts}.c"));
        if let Err(err) = fs::write(&path, contents) {
            panic!("temp C source should be writable: {err}");
        }
        path
    }

    #[test]
    fn parses_global_hints_catalog() {
        let hints_path = repo_root().join("global_hints.json");
        let catalog = match load_global_hints(&hints_path) {
            Ok(c) => c,
            Err(err) => panic!("global hints should parse: {err}"),
        };
        assert!(!catalog.version.is_empty());
        assert!(!catalog.hints.is_empty());
        assert!(catalog.hints.iter().all(|h| !h.id.is_empty()));
    }

    #[test]
    fn finds_multiple_security_antipatterns_in_sample() {
        let sample_path = repo_root().join("test_target.c");
        let hints = match process_file(
            &sample_path,
            AnalyzerLimits {
                max_file_size_bytes: 1024 * 1024,
                max_hints_per_file: 10_000,
            },
        ) {
            Ok(h) => h,
            Err(err) => panic!("sample file should parse: {err}"),
        };
        assert!(!hints.is_empty());

        let labels: Vec<&str> = hints.iter().map(|h| h.label.as_str()).collect();
        assert!(labels
            .iter()
            .any(|l| l.contains("Input-influenced boundary check")));
        assert!(labels
            .iter()
            .any(|l| l.contains("Input-influenced array/table index")));
        assert!(labels.iter().any(|l| l.contains("Unchecked copy pattern")));
        assert!(labels
            .iter()
            .any(|l| l.contains("Dangerous allocation pattern")));
        assert!(labels
            .iter()
            .any(|l| l.contains("Early exit may bypass validation")));
    }

    #[test]
    fn infers_offset_for_direct_subscript() {
        let src = r#"
            int f(unsigned char *data, size_t len) {
                size_t sz = 0;
                sz = data[0];
                return sz;
            }
        "#;
        let path = write_temp_c_file(src);
        let hints = process_file(
            &path,
            AnalyzerLimits {
                max_file_size_bytes: 1024 * 1024,
                max_hints_per_file: 10_000,
            },
        )
        .expect("temp source should parse");
        let _ = fs::remove_file(path);

        let len_hints: Vec<_> = hints
            .iter()
            .filter(|h| matches!(h.kind, HintKind::LengthField))
            .collect();
        assert!(!len_hints.is_empty());
        assert_eq!(len_hints[0].offset, Some(0));
    }

    #[test]
    fn detects_truncating_cast_pattern() {
        let src = r#"
            #include <stdint.h>
            int f(const unsigned char *data, size_t data_len) {
                uint8_t n = (uint8_t)data_len;
                return n + data[0];
            }
        "#;
        let path = write_temp_c_file(src);
        let hints = match process_file(
            &path,
            AnalyzerLimits {
                max_file_size_bytes: 1024 * 1024,
                max_hints_per_file: 10_000,
            },
        ) {
            Ok(h) => h,
            Err(err) => panic!("temp source should parse: {err}"),
        };
        let _ = fs::remove_file(path);

        assert!(hints.iter().any(|h| h
            .label
            .contains("Truncating cast from potentially larger value")));
    }

    #[test]
    fn emitted_hints_include_rule_provenance() {
        let sample_path = repo_root().join("test_target.c");
        let hints = process_file(
            &sample_path,
            AnalyzerLimits {
                max_file_size_bytes: 1024 * 1024,
                max_hints_per_file: 10_000,
            },
        )
        .expect("sample file should parse");

        assert!(hints.iter().all(|h| h.id.is_some()));
        assert!(hints.iter().all(|h| h.rule_id.is_some()));
        assert!(hints
            .iter()
            .any(|h| h.rule_id.as_deref() == Some("ap.unchecked_copy")));
        assert!(hints.iter().any(|h| !h.evidence.is_empty()));
        assert!(hints.iter().any(|h| h.snippet.is_some()));
    }

    #[test]
    fn builds_scan_stats_for_machine_readable_summary() {
        let hints = vec![
            StructuralHint::new(
                "a.c".to_string(),
                1,
                0,
                HintKind::LengthField,
                "length".to_string(),
                Severity::Medium,
                0.6,
            ),
            StructuralHint::new(
                "a.c".to_string(),
                2,
                0,
                HintKind::Vulnerability,
                "copy".to_string(),
                Severity::High,
                0.6,
            ),
        ];

        let stats = build_scan_stats(3, 1, &hints);
        assert_eq!(stats.files_discovered, 3);
        assert_eq!(stats.files_analyzed, 2);
        assert_eq!(stats.files_failed, 1);
        assert_eq!(stats.hints_count, 2);
        assert_eq!(stats.hints_by_kind.get("LengthField"), Some(&1));
        assert_eq!(stats.hints_by_severity.get("High"), Some(&1));
        assert_eq!(stats.top_files_by_hint_count[0].file, "a.c");
        assert_eq!(stats.top_files_by_hint_count[0].hints, 2);
    }
}
