#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct StructuralHint {
    pub file: String,
    pub line: usize,
    pub column: usize,
    pub kind: HintKind,
    pub label: String,
    pub offset: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum HintKind {
    LengthField,
    BoundaryCheck,
    ArrayIndex,
    Vulnerability,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct StructuralMap {
    pub hints: Vec<StructuralHint>,
}
