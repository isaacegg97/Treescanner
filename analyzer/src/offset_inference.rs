use common::StructuralHint;
use std::collections::HashMap;
use tree_sitter::{Query, QueryCursor, StreamingIterator, Tree};

pub struct OffsetContext {
    direct_offsets: HashMap<usize, usize>,
}

impl OffsetContext {
    pub fn new(source: &str, tree: &Tree) -> anyhow::Result<Self> {
        let mut direct_offsets = HashMap::new();
        let lang = tree_sitter_c::LANGUAGE.into();
        let query = Query::new(
            &lang,
            r#"
            (subscript_expression
                argument: (identifier) @base
                index: (number_literal) @idx)
        "#,
        )?;

        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&query, tree.root_node(), source.as_bytes());
        while let Some(m) = matches.next() {
            let mut base = None;
            let mut idx = None;
            let mut row = None;

            for c in m.captures {
                let name = query.capture_names()[c.index as usize];
                match name {
                    "base" => {
                        base = c.node.utf8_text(source.as_bytes()).ok().map(|s: &str| s.to_lowercase())
                    }
                    "idx" => {
                        idx = c
                            .node
                            .utf8_text(source.as_bytes())
                            .ok()
                            .and_then(|s: &str| s.parse::<usize>().ok());
                        row = Some(c.node.start_position().row + 1);
                    }
                    _ => {}
                }
            }

            if let (Some(base_name), Some(index), Some(line)) = (base, idx, row) {
                if base_name.contains("data") || base_name.contains("buf") || base_name.contains("input") {
                    direct_offsets.insert(line, index);
                }
            }
        }

        Ok(Self { direct_offsets })
    }

    pub fn infer_offset(&self, hint: &StructuralHint) -> Option<usize> {
        self.direct_offsets.get(&hint.line).copied()
    }
}

pub fn infer_offset_for_hint(hint: &StructuralHint, _source: &str, _tree: &Tree, ctx: &OffsetContext) -> Option<usize> {
    ctx.infer_offset(hint)
}
