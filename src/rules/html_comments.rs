use regex::Regex;

use super::{Issue, Rule, Severity};

pub struct HtmlCommentRule;

impl Rule for HtmlCommentRule {
    fn name(&self) -> &'static str {
        "html-comments"
    }

    fn check(&self, content: &str) -> Vec<Issue> {
        let mut issues = Vec::new();
        let re = Regex::new(r"<!--.*?-->").expect("Invalid regex");

        for (line_num, line) in content.lines().enumerate() {
            for mat in re.find_iter(line) {
                issues.push(Issue {
                    severity: Severity::Error,
                    line: line_num + 1,
                    column: Some(mat.start() + 1),
                    message: format!("HTML comment detected: '{}'", mat.as_str()),
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
    fn detects_html_comments() {
        let rule = HtmlCommentRule;
        let content = "Normal text\n<!-- hidden instruction -->\nMore text";
        let issues = rule.check(content);

        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].rule, "html-comments");
        assert_eq!(issues[0].severity, Severity::Error);
        assert_eq!(issues[0].line, 2);
        assert_eq!(issues[0].column, Some(1));
        assert!(issues[0].message.contains("<!-- hidden instruction -->"));
    }

    #[test]
    fn detects_multiple_html_comments() {
        let rule = HtmlCommentRule;
        let content = "<!-- comment 1 -->\nText\n<!-- comment 2 -->";
        let issues = rule.check(content);

        assert_eq!(issues.len(), 2);
        assert_eq!(issues[0].line, 1);
        assert_eq!(issues[1].line, 3);
    }

    #[test]
    fn no_false_positives_on_clean_text() {
        let rule = HtmlCommentRule;
        let content = "This is normal markdown text\nWith no HTML comments at all";
        let issues = rule.check(content);

        assert!(issues.is_empty());
    }

    #[test]
    fn no_false_positives_on_angles_without_comments() {
        let rule = HtmlCommentRule;
        let content = "This has <br> tags and <b>bold</b> text";
        let issues = rule.check(content);

        assert!(issues.is_empty());
    }
}
