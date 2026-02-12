use super::{Issue, Rule, Severity};

pub struct NonPrintableCharRule;

impl Rule for NonPrintableCharRule {
    fn name(&self) -> &'static str {
        "non-printable-chars"
    }

    fn check(&self, content: &str) -> Vec<Issue> {
        let mut issues = Vec::new();

        for (line_num, line) in content.lines().enumerate() {
            for (col, ch) in line.chars().enumerate() {
                // Check for control characters except standard whitespace
                if ch.is_control() && !matches!(ch, '\t' | '\n' | '\r') {
                    issues.push(Issue {
                        severity: Severity::Error,
                        line: line_num + 1,
                        column: Some(col + 1),
                        message: format!("Non-printable character U+{:04X} detected", ch as u32),
                        rule: self.name().to_string(),
                    });
                }
                // Check for zero-width characters
                if matches!(
                    ch as u32,
                    0x200B | 0x200C | 0x200D | 0xFEFF | 0x2060 | 0x00AD
                ) {
                    issues.push(Issue {
                        severity: Severity::Error,
                        line: line_num + 1,
                        column: Some(col + 1),
                        message: format!(
                            "Zero-width character U+{:04X} detected (possible steganography)",
                            ch as u32
                        ),
                        rule: self.name().to_string(),
                    });
                }
            }
        }
        issues
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_zero_width_space() {
        let rule = NonPrintableCharRule;
        let content = "Normal text\nText with zero-width: \u{200B}space\nMore text";
        let issues = rule.check(content);

        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].rule, "non-printable-chars");
        assert_eq!(issues[0].severity, Severity::Error);
        assert_eq!(issues[0].line, 2);
        assert!(issues[0].message.contains("U+200B"));
    }

    #[test]
    fn detects_multiple_invisible_chars() {
        let rule = NonPrintableCharRule;
        let content = "\u{200B} start\n\u{200C} middle\n\u{FEFF} end";
        let issues = rule.check(content);

        assert_eq!(issues.len(), 3);
    }

    #[test]
    fn allows_standard_whitespace() {
        let rule = NonPrintableCharRule;
        let content = "Line with tabs\tand spaces\nAnd newlines\r\n";
        let issues = rule.check(content);

        assert!(issues.is_empty());
    }

    #[test]
    fn no_false_positives_on_clean_text() {
        let rule = NonPrintableCharRule;
        let content = "This is completely normal text\nWith standard ASCII characters only";
        let issues = rule.check(content);

        assert!(issues.is_empty());
    }
}
