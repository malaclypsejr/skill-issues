use regex::Regex;

use super::{Issue, Rule, Severity};

pub struct ExcessiveBackticksRule;

impl Rule for ExcessiveBackticksRule {
    fn name(&self) -> &'static str {
        "excessive-backticks"
    }

    fn check(&self, content: &str) -> Vec<Issue> {
        let mut issues = Vec::new();
        let re = Regex::new(r"`{10,}").unwrap();

        for (line_num, line) in content.lines().enumerate() {
            if let Some(mat) = re.find(line) {
                issues.push(Issue {
                    severity: Severity::Warning,
                    line: line_num + 1,
                    column: Some(mat.start() + 1),
                    message: format!(
                        "Excessive backticks ({}), may be trying to break code block parsing",
                        mat.len()
                    ),
                    rule: self.name().to_string(),
                });
            }
        }
        issues
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_excessive_backticks() {
        let rule = ExcessiveBackticksRule;
        let content = "``` ```````````` end"; // 12 backticks
        let issues = rule.check(content);

        assert!(!issues.is_empty());
        assert_eq!(issues[0].rule, "excessive-backticks");
        assert_eq!(issues[0].severity, Severity::Warning);
        assert!(issues[0].message.contains("12"));
    }

    #[test]
    fn allows_normal_backticks() {
        let rule = ExcessiveBackticksRule;
        let content = "`inline code` and ```code block```";
        let issues = rule.check(content);

        assert!(issues.is_empty());
    }

    #[test]
    fn detects_exactly_ten_backticks() {
        let rule = ExcessiveBackticksRule;
        let content = "``````````"; // Exactly 10
        let issues = rule.check(content);

        assert!(!issues.is_empty());
    }

    #[test]
    fn detects_multiple_violations() {
        let rule = ExcessiveBackticksRule;
        let content = "```````````` line 1\nSome text\n```````````` line 3";
        let issues = rule.check(content);

        assert_eq!(issues.len(), 2);
        assert_eq!(issues[0].line, 1);
        assert_eq!(issues[1].line, 3);
    }

    #[test]
    fn no_false_positives_on_clean_text() {
        let rule = ExcessiveBackticksRule;
        let content = "Normal text with `some` code markers";
        let issues = rule.check(content);

        assert!(issues.is_empty());
    }
}
