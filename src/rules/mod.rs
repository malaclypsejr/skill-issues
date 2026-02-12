use serde::{Deserialize, Serialize};

pub mod base64_encoded;
pub mod excessive_backticks;
pub mod excessive_whitespace;
pub mod high_entropy;
pub mod html_comments;
pub mod invisible_chars;
pub mod mixed_scripts;
pub mod non_printable;
pub mod suspicious_keywords;
pub mod unicode_homoglyphs;
pub mod url_encoding;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Error,
    Warning,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Issue {
    pub severity: Severity,
    pub line: usize,
    pub column: Option<usize>,
    pub message: String,
    pub rule: String,
}

pub trait Rule {
    fn name(&self) -> &'static str;
    fn check(&self, content: &str) -> Vec<Issue>;
}
