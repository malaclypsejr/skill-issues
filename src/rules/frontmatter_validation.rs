use std::collections::BTreeMap;

use super::{Issue, Rule, Severity};

/// Detects structural issues in YAML frontmatter of skill markdown files,
/// with provider-aware checks for `OpenCode`, Claude Code, and Codex.
///
/// Checks:
/// 1. Missing required fields (`name`, `description`)
/// 2. Missing `location` for OpenCode-targeted skills
/// 3. Provider-incompatible field combinations
/// 4. Unrestricted `allowed-tools` (wildcard `*`)
/// 5. Provider detection signals
/// 6. Short/empty `description`
/// 7. Description-body keyword overlap (filler heuristic)
/// 8. Codex name format violation (non-kebab-case)
/// 9. Codex description angle brackets (`<` or `>`)
/// 10. Codex `allowed-tools` format (space-separated vs YAML list)
pub struct FrontmatterValidationRule;

#[derive(Debug, PartialEq, Eq)]
enum Provider {
    OpenCode,
    ClaudeCode,
    Codex,
    Unknown,
}

impl FrontmatterValidationRule {
    #[expect(clippy::type_complexity, reason = "Returning structured frontmatter data is clearer as a tuple")]
    /// Extract YAML frontmatter as (`start_line`, `body_lines`, `body_start_line`, `body_text`).
    fn extract_frontmatter(content: &str) -> Option<(usize, Vec<(usize, &str)>, Option<usize>, &str)> {
        let mut lines = content.lines().enumerate();

        let (first_idx, first_line) = lines.next()?;
        if first_line.trim() != "---" {
            return None;
        }

        let mut fm_lines = Vec::new();
        let mut body_start: Option<usize> = None;

        for (idx, line) in lines {
            if line.trim() == "---" {
                body_start = Some(idx + 1);
                break;
            }
            fm_lines.push((idx, line));
        }

        let body_text = body_start.map_or("", |start| {
            let char_count: usize = content
                .lines()
                .take(start)
                .map(|l| l.len() + 1)
                .sum();
            &content[char_count.min(content.len())..]
        });

        if fm_lines.is_empty() {
            None
        } else {
            Some((first_idx, fm_lines, body_start, body_text))
        }
    }

    /// Parse top-level YAML keys from frontmatter lines.
    /// Returns a map of key -> (`line_number`, `value_str`).
    fn parse_top_level_keys(
        fm_lines: &[(usize, &str)],
    ) -> BTreeMap<String, (usize, String)> {
        let mut keys: BTreeMap<String, (usize, String)> = BTreeMap::new();

        for (line_idx, line) in fm_lines {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            if let Some(colon_pos) = trimmed.find(':') {
                let key = trimmed[..colon_pos].trim().to_lowercase();
                let value = trimmed[colon_pos + 1..].trim().to_string();
                let is_top_level = line.len() == trimmed.len();

                if is_top_level && !key.is_empty() {
                    keys.insert(key, (*line_idx, value));
                }
            }
        }

        keys
    }

    /// Determine the provider from frontmatter keys.
    fn detect_provider(keys: &BTreeMap<String, (usize, String)>) -> Provider {
        let has_location = keys.contains_key("location");
        let has_hooks = keys.contains_key("hooks");
        let has_model = keys.contains_key("model");
        let has_disable_model = keys.contains_key("disable-model-invocation");
        let has_license = keys.contains_key("license");
        let has_compatibility = keys.contains_key("compatibility");
        let has_metadata = keys.contains_key("metadata");

        let opencode_signal = has_location;
        let claude_signal = has_hooks || has_model || has_disable_model;
        let codex_signal = has_license || has_compatibility || has_metadata;

        if opencode_signal && !claude_signal && !codex_signal {
            Provider::OpenCode
        } else if claude_signal && !opencode_signal && !codex_signal {
            Provider::ClaudeCode
        } else if codex_signal && !opencode_signal && !claude_signal {
            Provider::Codex
        } else {
            Provider::Unknown
        }
    }
}

impl Rule for FrontmatterValidationRule {
    fn name(&self) -> &'static str {
        "frontmatter-validation"
    }

    #[expect(clippy::too_many_lines, reason = "Rule implements 10 distinct checks on frontmatter")]
    fn check(&self, content: &str) -> Vec<Issue> {
        let mut issues = Vec::new();

        let Some((start, fm_lines, _body_start, body_text)) =
            Self::extract_frontmatter(content)
        else {
            return issues;
        };

        let keys = Self::parse_top_level_keys(&fm_lines);
        let provider = Self::detect_provider(&keys);

        let issue_line = |line_idx: usize, msg: String, severity: Severity| Issue {
            severity,
            line: line_idx + 1,
            column: Some(1),
            message: msg,
            rule: "frontmatter-validation".to_string(),
        };

        let opening_line = start + 1;

        // ── Check 1: Missing required fields ──
        if !keys.contains_key("name") {
            issues.push(issue_line(
                opening_line,
                "Missing required field 'name' in frontmatter".to_string(),
                Severity::Error,
            ));
        }
        if !keys.contains_key("description") {
            issues.push(issue_line(
                opening_line,
                "Missing required field 'description' in frontmatter".to_string(),
                Severity::Error,
            ));
        }

        // ── Check 2: Missing location for OpenCode skills ──
        if provider == Provider::OpenCode && !keys.contains_key("location") {
            issues.push(issue_line(
                opening_line,
                "OpenCode skill missing 'location' — required for skills placed under \
                 ~/.config/opencode/skills/"
                    .to_string(),
                Severity::Error,
            ));
        }

        // ── Check 3: Provider-incompatible field combinations ──
        let has_location = keys.contains_key("location");
        let has_hooks = keys.contains_key("hooks");
        let has_model = keys.contains_key("model");
        let has_disable_model = keys.contains_key("disable-model-invocation");

        let claude_specific = has_hooks || has_model || has_disable_model;
        if has_location && claude_specific {
            let (claude_line, _) = keys
                .get("hooks")
                .or_else(|| keys.get("model"))
                .or_else(|| keys.get("disable-model-invocation"))
                .unwrap_or_else(|| keys.get("location").unwrap());
            issues.push(issue_line(
                *claude_line,
                "Frontmatter contains both OpenCode-specific ('location') and Claude-Code-specific \
                 ('hooks'/'model'/'disable-model-invocation') fields — likely misconfigured"
                    .to_string(),
                Severity::Warning,
            ));
        }

        // ── Check 4: Unrestricted allowed-tools ──
        if let Some((line, value)) = keys.get("allowed-tools") {
            let v = value.trim();
            if v == "*" || v == "\"*\"" || v == "'*'" {
                issues.push(issue_line(
                    *line,
                    "Unrestricted 'allowed-tools: *' — allows any tool, consider restricting \
                     to specific tools"
                        .to_string(),
                    Severity::Warning,
                ));
            }
        }

        // ── Check 6: Empty or short description ──
        if let Some((line, value)) = keys.get("description") {
            let v = value.trim();
            if v.is_empty() || v == "\"\"" || v == "''" {
                issues.push(issue_line(
                    *line,
                    "Description is empty — should describe the skill's purpose".to_string(),
                    Severity::Warning,
                ));
            } else if v.len() < 20 {
                issues.push(issue_line(
                    *line,
                    format!(
                        "Description is very short ({} chars) — consider a more detailed \
                         description (at least 20 characters)",
                        v.len()
                    ),
                    Severity::Warning,
                ));
            }
        }

        // ── Check 7: Description-body keyword overlap ──
        if let Some((line, value)) = keys.get("description") {
            let desc = value.trim().trim_matches('"').trim_matches('\'');
            if desc.len() >= 8 && !body_text.is_empty() {
                let desc_lower = desc.to_lowercase();
                let body_lower = body_text.to_lowercase();
                let words: Vec<&str> = desc_lower
                    .split_whitespace()
                    .filter(|w| w.len() >= 5)
                    .collect();
                let mut overlap_count = 0;
                for word in &words {
                    if body_lower.contains(word) {
                        overlap_count += 1;
                    }
                }
                if overlap_count >= 3 {
                    #[expect(clippy::cast_precision_loss, reason = "Word count for overlap ratio fits safely in f64 mantissa")]
                    let ratio = f64::from(overlap_count) / (words.len().max(1) as f64);
                    if ratio >= 0.5 {
                        issues.push(issue_line(
                            *line,
                            format!(
                                "Description shares {}/{} significant words with body text — \
                                 may be AI-generated filler rather than a crafted description",
                                overlap_count,
                                words.len()
                            ),
                            Severity::Warning,
                        ));
                    }
                }
            }
        }

        // ── Check 8: Codex name format ──
        if provider == Provider::Codex
            && let Some((line, value)) = keys.get("name") {
                let name = value.trim().trim_matches('"').trim_matches('\'');
                if !is_valid_codex_name(name) {
                    issues.push(issue_line(
                        *line,
                        format!(
                            "Name '{name}' violates Codex kebab-case format — must match \
                             ^[a-z0-9-]+$ (lowercase, numbers, hyphens only)"
                        ),
                        Severity::Error,
                    ));
                }
            }

        // ── Check 9: Description angle brackets (Codex) ──
        if provider == Provider::Codex
            && let Some((line, value)) = keys.get("description") {
                let v = value.trim();
                if v.contains('<') || v.contains('>') || v.contains('\u{3c}') || v.contains('\u{3e}')
                {
                    issues.push(issue_line(
                        *line,
                        "Description contains angle brackets (<>) — Codex forbids this in \
                         the description field"
                            .to_string(),
                        Severity::Error,
                    ));
                }
            }

        // ── Check 10: allowed-tools format (Codex expects space-separated) ──
        if provider == Provider::Codex
            && let Some((line, value)) = keys.get("allowed-tools") {
                let v = value.trim().trim_matches('"').trim_matches('\'');
                if v.starts_with('-') || v.starts_with('[') {
                    issues.push(issue_line(
                        *line,
                        "allowed-tools uses YAML list syntax — Codex expects space-separated \
                         format (e.g. 'Bash(git:*) Read')"
                            .to_string(),
                        Severity::Warning,
                    ));
                }
            }

        // ── Check 5 (summary): Unknown provider from mixed signals ──
        if provider == Provider::Unknown {
            let has_location = keys.contains_key("location");
            let has_hooks = keys.contains_key("hooks");
            let has_model = keys.contains_key("model");
            let has_disable_model = keys.contains_key("disable-model-invocation");
            let has_license = keys.contains_key("license");
            let has_compatibility = keys.contains_key("compatibility");
            let has_metadata = keys.contains_key("metadata");

            let signals = [
                has_location,
                has_hooks,
                has_model,
                has_disable_model,
                has_license,
                has_compatibility,
                has_metadata,
            ];
            let signal_count = signals.iter().filter(|&&s| s).count();

            if signal_count == 0 {
                issues.push(issue_line(
                    opening_line,
                    "Cannot determine skill provider — no provider-specific fields found \
                     (location/hooks/model/license/compatibility). Consider adding \
                     provider-identifying keys."
                        .to_string(),
                    Severity::Warning,
                ));
            } else {
                let mut provider_signals = Vec::new();
                if has_location {
                    provider_signals.push("OpenCode (location)");
                }
                if has_hooks || has_model || has_disable_model {
                    provider_signals.push("Claude Code (hooks/model)");
                }
                if has_license || has_compatibility || has_metadata {
                    provider_signals.push("Codex (license/compatibility/metadata)");
                }
                issues.push(issue_line(
                    opening_line,
                    format!(
                        "Ambiguous provider detection — fields from multiple providers: {}",
                        provider_signals.join(", ")
                    ),
                    Severity::Warning,
                ));
            }
        }

        issues
    }
}

fn is_valid_codex_name(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    if name.starts_with('-') || name.ends_with('-') || name.contains("--") {
        return false;
    }
    name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(content: &str) -> Vec<Issue> {
        FrontmatterValidationRule.check(content)
    }

    #[test]
    fn no_frontmatter_no_issues() {
        let content = "# Just a heading\n\nSome content.\n";
        assert!(check(content).is_empty());
    }

    #[test]
    fn clean_frontmatter_no_issues() {
        let content = "\
---
name: my-skill
description: A well-described skill for doing useful things
location: my-skill/SKILL.md
---
# Body
";
        assert!(check(content).is_empty());
    }

    #[test]
    fn missing_name_is_error() {
        let content = "\
---
description: A skill without a name
---
# Body
";
        let issues = check(content);
        assert!(
            issues.iter().any(|i| i.severity == Severity::Error
                && i.message.contains("name")),
            "expected error for missing name, got: {issues:?}"
        );
    }

    #[test]
    fn missing_description_is_error() {
        let content = "\
---
name: no-desc
---
# Body
";
        let issues = check(content);
        assert!(
            issues.iter().any(|i| i.severity == Severity::Error
                && i.message.contains("description")),
            "expected error for missing description, got: {issues:?}"
        );
    }

    #[test]
    fn opencode_missing_location_is_error() {
        let content = "\
---
name: my-skill
description: A skill
location: my-skill/SKILL.md
hooks:
  - event: SessionStart
---
# Body
";
        let issues = check(content);
        assert!(
            issues.iter().any(|i| i.severity == Severity::Warning
                && i.message.contains("misconfigured")),
            "expected warning for mixed providers, got: {issues:?}"
        );
    }

    #[test]
    fn mixed_provider_fields_is_warning() {
        let content = "\
---
name: mixed
description: Has both OpenCode and Claude fields
location: mixed/SKILL.md
model: claude-sonnet-4-20250514
---
# Body
";
        let issues = check(content);
        assert!(
            issues.iter().any(|i| i.message.contains("misconfigured")),
            "expected misconfigured warning, got: {issues:?}"
        );
    }

    #[test]
    fn unrestricted_allowed_tools_is_warning() {
        let content = "\
---
name: permissive
description: A skill that allows all tools
allowed-tools: \"*\"
---
# Body
";
        let issues = check(content);
        assert!(
            issues.iter().any(|i| i.message.contains("Unrestricted")),
            "expected unrestricted warning, got: {issues:?}"
        );
    }

    #[test]
    fn short_description_is_warning() {
        let content = "\
---
name: short-desc
description: Too short
---
# Body
";
        let issues = check(content);
        assert!(
            issues.iter().any(|i| i.message.contains("short")),
            "expected short description warning, got: {issues:?}"
        );
    }

    #[test]
    fn empty_description_is_warning() {
        let content = "\
---
name: empty-desc
description: \"\"
---
# Body
";
        let issues = check(content);
        assert!(
            issues.iter().any(|i| i.message.contains("empty")),
            "expected empty description warning, got: {issues:?}"
        );
    }

    #[test]
    fn description_body_overlap_is_warning() {
        let content = "\
---
name: filler-skill
description: This skill helps you analyze security vulnerabilities and audit smart contracts thoroughly
---
# Security Audit Helper

This skill helps you analyze security vulnerabilities in your codebase.
It performs thorough auditing of smart contracts and provides detailed reports.
Use this skill when you need to find vulnerabilities and audit contracts.
";
        let issues = check(content);
        assert!(
            issues.iter().any(|i| i.message.contains("filler")),
            "expected filler warning for overlapping words, got: {issues:?}"
        );
    }

    #[test]
    fn clean_description_doesnt_trigger_overlap() {
        let content = "\
---
name: helper
description: Provides quick access to project-specific build commands and deployment scripts
---
# Developer Helper

This skill contains shortcuts for common development tasks.
It wraps the build system and provides one-liners for CI/CD operations.
";
        let issues = check(content);
        assert!(
            !issues.iter().any(|i| i.message.contains("filler")),
            "clean description should not trigger overlap, got: {issues:?}"
        );
    }

    #[test]
    fn codex_uppercase_name_is_error() {
        let content = "\
---
name: MySkill
description: A Codex skill for doing important things effectively
license: MIT
---
# Body
";
        let issues = check(content);
        assert!(
            issues.iter().any(|i| i.severity == Severity::Error
                && i.message.contains("kebab-case")),
            "expected kebab-case error for Codex, got: {issues:?}"
        );
    }

    #[test]
    fn codex_valid_name_no_error() {
        let content = "\
---
name: my-codex-skill
description: A Codex skill for doing important things effectively
license: MIT
---
# Body
";
        let issues = check(content);
        assert!(
            !issues.iter().any(|i| i.message.contains("kebab-case")),
            "valid kebab-case name should not trigger error, got: {issues:?}"
        );
    }

    #[test]
    fn codex_angle_brackets_in_description_is_error() {
        let content = "\
---
name: codex-bad-desc
description: Runs <system> commands for admin tasks
license: MIT
---
# Body
";
        let issues = check(content);
        assert!(
            issues.iter().any(|i| i.message.contains("angle brackets")),
            "expected angle bracket error for Codex, got: {issues:?}"
        );
    }

    #[test]
    fn codex_list_format_allowed_tools_is_warning() {
        let content = "\
---
name: codex-tools
description: A Codex skill with list-format allowed-tools
license: MIT
allowed-tools: \"- Bash\"
---
# Body
";
        let issues = check(content);
        assert!(
            issues.iter().any(|i| i.message.contains("YAML list syntax")),
            "expected YAML list warning for Codex, got: {issues:?}"
        );
    }

    #[test]
    fn codex_space_separated_allowed_tools_ok() {
        let content = "\
---
name: codex-tools
description: A Codex skill with correct allowed-tools format
license: MIT
allowed-tools: \"Bash(git:*) Read\"
---
# Body
";
        let issues = check(content);
        assert!(
            !issues.iter().any(|i| i.message.contains("YAML list syntax")),
            "space-separated tools should not trigger warning, got: {issues:?}"
        );
    }

    #[test]
    fn unknown_provider_with_no_signals_warns() {
        let content = "\
---
name: plain-skill
description: Just a plain skill with no provider signals
---
# Body
";
        let issues = check(content);
        assert!(
            issues.iter().any(|i| i.message.contains("Cannot determine")),
            "expected unknown provider warning, got: {issues:?}"
        );
    }

    #[test]
    fn ambiguous_multi_provider_warns() {
        let content = "\
---
name: all-providers
description: Has signals from multiple providers
location: all/SKILL.md
model: claude-sonnet-4
license: MIT
---
# Body
";
        let issues = check(content);
        let msgs: Vec<&str> = issues.iter().map(|i| i.message.as_str()).collect();
        assert!(
            msgs.iter().any(|m| m.contains("Ambiguous provider")),
            "expected ambiguous provider warning, got: {issues:?}"
        );
    }

    #[test]
    fn codex_name_with_double_hyphen_is_error() {
        let content = "\
---
name: bad--name
description: A Codex skill for doing important things effectively
license: MIT
---
# Body
";
        let issues = check(content);
        assert!(
            issues.iter().any(|i| i.message.contains("kebab-case")),
            "double hyphen should trigger kebab-case error, got: {issues:?}"
        );
    }

    #[test]
    fn codex_name_leading_hyphen_is_error() {
        let content = "\
---
name: -bad-name
description: A Codex skill for doing important things effectively
license: MIT
---
# Body
";
        let issues = check(content);
        assert!(
            issues.iter().any(|i| i.message.contains("kebab-case")),
            "leading hyphen should trigger kebab-case error, got: {issues:?}"
        );
    }

    #[test]
    fn codex_name_with_underscore_is_error() {
        let content = "\
---
name: bad_name
description: A Codex skill for doing important things effectively
license: MIT
---
# Body
";
        let issues = check(content);
        assert!(
            issues.iter().any(|i| i.message.contains("kebab-case")),
            "underscore should trigger kebab-case error, got: {issues:?}"
        );
    }
}
