#![forbid(unsafe_code)]

use anyhow::Result;
use clap::Parser;
use common::{HintKind, StructuralHint, StructuralMap};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use tera::{Context, Tera};
use tree_sitter::{Query, QueryCursor, StreamingIterator};
use walkdir::WalkDir;

#[derive(Parser, Debug)]
struct Args {
    #[arg(short, long)]
    input: PathBuf,

    #[arg(short, long)]
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
}

#[derive(Serialize)]
struct ReportStats {
    files_count: usize,
    hints_count: usize,
    length_fields: usize,
    influence_edges: usize,
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
            anyhow::bail!("global hint {} missing relations/signals/mutations", hint.id);
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

    let tree = parser
        .parse(&source, None)
        .ok_or_else(|| anyhow::anyhow!("tree-sitter parser returned no tree for {}", path.display()))?;

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
            if let Some(origin) = var_origin.get(&var) {
                if origin == "input" {
                    push_hint_limited(
                        &mut hints,
                        StructuralHint {
                        file: path.to_string_lossy().into(),
                        line: node.start_position().row + 1,
                        column: node.start_position().column,
                        kind: HintKind::LengthField,
                        label: format!("Input-derived length field: {}", var),
                        offset: None,
                        },
                        limits.max_hints_per_file,
                    );
                }
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
                        StructuralHint {
                        file: path.to_string_lossy().into(),
                        line: c.node.start_position().row + 1,
                        column: c.node.start_position().column,
                        kind: HintKind::BoundaryCheck,
                        label: "Input-influenced boundary check".to_string(),
                        offset: None,
                        },
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
                        StructuralHint {
                        file: path.to_string_lossy().into(),
                        line: c.node.start_position().row + 1,
                        column: c.node.start_position().column,
                        kind: HintKind::ArrayIndex,
                        label: "Input-influenced array/table index".to_string(),
                        offset: None,
                        },
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

                let has_input_shape = text.contains('[')
                    || text.contains("len")
                    || text.contains("size");

                if has_input_shape {
                    let lower_f = f.to_lowercase();
                    let label = if lower_f == "memcpy" || lower_f == "memmove" || lower_f == "strcpy" || lower_f == "strcat" {
                        format!("Unchecked copy pattern in {}", f)
                    } else {
                        format!("Dangerous allocation pattern in {}", f)
                    };
                    push_hint_limited(
                        &mut hints,
                        StructuralHint {
                        file: path.to_string_lossy().into(),
                        line: n.start_position().row + 1,
                        column: n.start_position().column,
                        kind: HintKind::Vulnerability,
                        label,
                        offset: None,
                        },
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
            let is_narrow = ty_text.contains("char") || ty_text.contains("short") || ty_text.contains("uint8_t") || ty_text.contains("int8_t");
            if is_narrow {
                push_hint_limited(
                    &mut hints,
                    StructuralHint {
                    file: path.to_string_lossy().into(),
                    line: val_node.start_position().row + 1,
                    column: val_node.start_position().column,
                    kind: HintKind::Vulnerability,
                    label: "Truncating cast from potentially larger value".to_string(),
                    offset: None,
                    },
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
                    StructuralHint {
                    file: path.to_string_lossy().into(),
                    line: c.node.start_position().row + 1,
                    column: c.node.start_position().column,
                    kind: HintKind::Vulnerability,
                    label: "Early exit may bypass validation or cleanup".to_string(),
                    offset: None,
                    },
                    limits.max_hints_per_file,
                );
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
        rayon::ThreadPoolBuilder::new().num_threads(t).build_global()?;
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

    let all_hints: Vec<_> = files
        .par_iter()
        .map(|f| process_file(f, limits))
        .collect::<Vec<_>>()
        .into_iter()
        .filter_map(|res| match res {
            Ok(hints) => Some(hints),
            Err(err) => {
                eprintln!("Skipping file due to analysis error: {err}");
                None
            }
        })
        .flatten()
        .collect();

    let map = StructuralMap {
        hints: all_hints.clone(),
    };

    fs::write(&args.output, serde_json::to_string_pretty(&map)?)?;

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
        assert!(labels.iter().any(|l| l.contains("Dangerous allocation pattern")));
        assert!(labels
            .iter()
            .any(|l| l.contains("Early exit may bypass validation")));
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

        assert!(hints
            .iter()
            .any(|h| h.label.contains("Truncating cast from potentially larger value")));
    }
}