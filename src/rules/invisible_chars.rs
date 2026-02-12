use super::{Issue, Rule, Severity};

pub struct InvisibleCharactersRule;

impl Rule for InvisibleCharactersRule {
    fn name(&self) -> &'static str {
        "invisible-characters"
    }

    fn check(&self, content: &str) -> Vec<Issue> {
        let mut issues = Vec::new();
        // Invisible or near-invisible characters
        let invisible: [(char, &str); 8] = [
            ('\u{200B}', "ZERO WIDTH SPACE"),
            ('\u{200C}', "ZERO WIDTH NON-JOINER"),
            ('\u{200D}', "ZERO WIDTH JOINER"),
            ('\u{FEFF}', "ZERO WIDTH NO-BREAK SPACE (BOM)"),
            ('\u{2060}', "WORD JOINER"),
            ('\u{00AD}', "SOFT HYPHEN"),
            ('\u{180E}', "MONGOLIAN VOWEL SEPARATOR"),
            ('\u{200E}', "LEFT-TO-RIGHT MARK"),
        ];

        for (line_num, line) in content.lines().enumerate() {
            for (col, ch) in line.chars().enumerate() {
                for (inv_char, name) in &invisible {
                    if ch == *inv_char {
                        issues.push(Issue {
                            severity: Severity::Error,
                            line: line_num + 1,
                            column: Some(col + 1),
                            message: format!("Invisible character: {name}"),
                            rule: self.name().to_string(),
                        });
                    }
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
        let rule = InvisibleCharactersRule;
        let content = "Text with\u{200B}invisible space";
        let issues = rule.check(content);

        assert!(!issues.is_empty());
        assert!(issues
            .iter()
            .any(|i| i.message.contains("ZERO WIDTH SPACE")));
    }

    #[test]
    fn detects_zero_width_joiner() {
        let rule = InvisibleCharactersRule;
        let content = "Text with\u{200D}joiner";
        let issues = rule.check(content);

        assert!(!issues.is_empty());
        assert!(issues
            .iter()
            .any(|i| i.message.contains("ZERO WIDTH JOINER")));
    }

    #[test]
    fn detects_bom() {
        let rule = InvisibleCharactersRule;
        let content = "\u{FEFF}Text with BOM";
        let issues = rule.check(content);

        assert!(!issues.is_empty());
        assert!(issues.iter().any(|i| i.message.contains("BOM")));
    }

    #[test]
    fn detects_multiple_invisible_chars() {
        let rule = InvisibleCharactersRule;
        let content = "\u{200B}\u{200C}\u{200D}Three different invisible chars";
        let issues = rule.check(content);

        assert_eq!(issues.len(), 3);
    }

    #[test]
    fn no_false_positives_on_clean_text() {
        let rule = InvisibleCharactersRule;
        let content = "Normal text without any invisible characters";
        let issues = rule.check(content);

        assert!(issues.is_empty());
    }

    #[test]
    fn correctly_identifies_position() {
        let rule = InvisibleCharactersRule;
        let content = "abc\u{200B}def";
        let issues = rule.check(content);

        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].line, 1);
        assert_eq!(issues[0].column, Some(4));
    }
}
