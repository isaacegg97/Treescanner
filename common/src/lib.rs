#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

fn is_none<T>(value: &Option<T>) -> bool {
    value.is_none()
}

fn is_empty<T>(value: &[T]) -> bool {
    value.is_empty()
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct StructuralHint {
    pub file: String,
    pub line: usize,
    pub column: usize,
    pub kind: HintKind,
    pub label: String,
    pub offset: Option<usize>,
    pub severity: Severity,
    pub confidence: f32,
    #[serde(default, skip_serializing_if = "is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "is_none")]
    pub rule_id: Option<String>,
    #[serde(default, skip_serializing_if = "is_none")]
    pub byte_width: Option<usize>,
    #[serde(default, skip_serializing_if = "is_none")]
    pub endianness: Option<Endianness>,
    #[serde(default, skip_serializing_if = "is_empty")]
    pub related_offsets: Vec<usize>,
    #[serde(default, skip_serializing_if = "is_none")]
    pub snippet: Option<String>,
    #[serde(default, skip_serializing_if = "is_empty")]
    pub evidence: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum HintKind {
    LengthField,
    BoundaryCheck,
    ArrayIndex,
    Vulnerability,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum Endianness {
    Little,
    Big,
    Unknown,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct StructuralMap {
    #[serde(default = "default_schema_version")]
    pub schema_version: String,
    pub hints: Vec<StructuralHint>,
}

impl StructuralHint {
    pub fn new(
        file: String,
        line: usize,
        column: usize,
        kind: HintKind,
        label: String,
        severity: Severity,
        confidence: f32,
    ) -> Self {
        Self {
            file,
            line,
            column,
            kind,
            label,
            offset: None,
            severity,
            confidence,
            id: None,
            rule_id: None,
            byte_width: None,
            endianness: None,
            related_offsets: Vec::new(),
            snippet: None,
            evidence: Vec::new(),
        }
    }

    pub fn with_rule_id(mut self, rule_id: impl Into<String>) -> Self {
        self.rule_id = Some(rule_id.into());
        self
    }

    pub fn with_snippet(mut self, snippet: impl Into<String>) -> Self {
        self.snippet = Some(snippet.into());
        self
    }

    pub fn with_evidence(mut self, evidence: impl Into<String>) -> Self {
        self.evidence.push(evidence.into());
        self
    }
}

impl StructuralMap {
    pub fn new(hints: Vec<StructuralHint>) -> Self {
        Self {
            schema_version: default_schema_version(),
            hints,
        }
    }
}

fn default_schema_version() -> String {
    "2.0".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserializes_legacy_hint_without_optional_metadata() {
        let json = r#"{
            "hints": [{
                "file": "target.c",
                "line": 1,
                "column": 0,
                "kind": "LengthField",
                "label": "legacy",
                "offset": 0,
                "severity": "Medium",
                "confidence": 0.6
            }]
        }"#;

        let map: StructuralMap = serde_json::from_str(json).expect("legacy hints should parse");
        assert_eq!(map.schema_version, "2.0");
        assert_eq!(map.hints.len(), 1);
        assert!(map.hints[0].id.is_none());
        assert!(map.hints[0].rule_id.is_none());
        assert!(map.hints[0].related_offsets.is_empty());
        assert!(map.hints[0].evidence.is_empty());
    }
}
