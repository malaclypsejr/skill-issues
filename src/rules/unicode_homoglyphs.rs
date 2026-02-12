use std::collections::HashMap;

use super::{Issue, Rule, Severity};

pub struct UnicodeHomoglyphRule;

impl Rule for UnicodeHomoglyphRule {
    fn name(&self) -> &'static str {
        "unicode-homoglyphs"
    }

    fn check(&self, content: &str) -> Vec<Issue> {
        let mut issues = Vec::new();
        // Common homoglyphs that look like ASCII but aren't
        let homoglyphs: HashMap<char, (&str, char)> = [
            ('а', ("Cyrillic а (U+0430)", 'a')), // looks like 'a'
            ('е', ("Cyrillic е (U+0435)", 'e')), // looks like 'e'
            ('о', ("Cyrillic о (U+043E)", 'o')), // looks like 'o'
            ('р', ("Cyrillic р (U+0440)", 'p')), // looks like 'p'
            ('с', ("Cyrillic с (U+0441)", 'c')), // looks like 'c'
            ('х', ("Cyrillic х (U+0445)", 'x')), // looks like 'x'
            ('і', ("Cyrillic і (U+0456)", 'i')), // looks like 'i'
            ('ј', ("Cyrillic ј (U+0458)", 'j')), // looks like 'j'
            ('ԛ', ("Cyrillic ԛ (U+051B)", 'q')), // looks like 'q'
            ('ѕ', ("Cyrillic ѕ (U+0455)", 's')), // looks like 's'
        ]
        .iter()
        .copied()
        .collect();

        for (line_num, line) in content.lines().enumerate() {
            for (col, ch) in line.chars().enumerate() {
                if let Some((name, ascii_equiv)) = homoglyphs.get(&ch) {
                    issues.push(Issue {
                        severity: Severity::Error,
                        line: line_num + 1,
                        column: Some(col + 1),
                        message: format!(
                            "Homoglyph detected: '{ch}' looks like '{ascii_equiv}' but is {name}"
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
    fn detects_cyrillic_a() {
        let rule = UnicodeHomoglyphRule;
        // Cyrillic 'а' (U+0430) looks like Latin 'a'
        let content = "pаssword"; // First 'a' is Cyrillic
        let issues = rule.check(content);

        assert!(!issues.is_empty());
        assert_eq!(issues[0].rule, "unicode-homoglyphs");
        assert_eq!(issues[0].severity, Severity::Error);
        assert!(issues[0].message.contains("Cyrillic"));
    }

    #[test]
    fn detects_cyrillic_o() {
        let rule = UnicodeHomoglyphRule;
        // Cyrillic 'о' (U+043E) looks like Latin 'o'
        let content = "hellо world"; // 'o' in hello is Cyrillic
        let issues = rule.check(content);

        assert!(!issues.is_empty());
        assert!(issues[0].message.contains("Cyrillic о"));
    }

    #[test]
    fn detects_multiple_homoglyphs() {
        let rule = UnicodeHomoglyphRule;
        // Mixed Cyrillic and Latin
        let content = "аbсde"; // а and с are Cyrillic
        let issues = rule.check(content);

        assert_eq!(issues.len(), 2);
    }

    #[test]
    fn no_false_positives_on_pure_latin() {
        let rule = UnicodeHomoglyphRule;
        let content = "This is normal ASCII text only";
        let issues = rule.check(content);

        assert!(issues.is_empty());
    }

    #[test]
    fn correctly_identifies_homoglyph_column() {
        let rule = UnicodeHomoglyphRule;
        let content = "prefixаsuffix"; // Cyrillic 'а' at position 7
        let issues = rule.check(content);

        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].column, Some(7));
    }
}
