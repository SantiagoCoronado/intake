//! Tests for PolicyEngine — mirrors `tests/test_policy.py`.

use std::path::PathBuf;

use intake_core::{
    Channel, Matcher, PolicyConfig, PolicyEngine, PolicyRule, TrustLevel,
};

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("fixtures")
}

fn basic_policy() -> PolicyConfig {
    PolicyConfig {
        version: "1.0".to_string(),
        default_deny: true,
        rules: vec![
            PolicyRule {
                channel: Matcher::Specific(Channel::OwnerCli),
                trust: Matcher::Specific(TrustLevel::Owner),
                allow: vec!["*".to_string()],
                deny: vec![],
                priority: 0,
            },
            PolicyRule {
                channel: Matcher::Specific(Channel::ExternalEmail),
                trust: Matcher::Specific(TrustLevel::Untrusted),
                allow: vec!["read_email".to_string(), "summarize".to_string()],
                deny: vec!["shell_exec".to_string(), "send_email".to_string()],
                priority: 10,
            },
            PolicyRule {
                channel: Matcher::Wildcard,
                trust: Matcher::Specific(TrustLevel::Hostile),
                deny: vec!["*".to_string()],
                allow: vec![],
                priority: 100,
            },
        ],
    }
}

#[test]
fn test_owner_allowed_everything() {
    let engine = PolicyEngine::from_config(basic_policy());
    let result = engine.evaluate("shell_exec", Channel::OwnerCli, TrustLevel::Owner);
    assert!(result.allowed);
    assert!(result.matched_rule.is_some());
}

#[test]
fn test_untrusted_email_allowed_read() {
    let engine = PolicyEngine::from_config(basic_policy());
    let result = engine.evaluate("read_email", Channel::ExternalEmail, TrustLevel::Untrusted);
    assert!(result.allowed);
}

#[test]
fn test_untrusted_email_denied_shell() {
    let engine = PolicyEngine::from_config(basic_policy());
    let result = engine.evaluate("shell_exec", Channel::ExternalEmail, TrustLevel::Untrusted);
    assert!(!result.allowed);
    assert!(result.reason.contains("shell_exec"));
}

#[test]
fn test_untrusted_email_denied_send() {
    let engine = PolicyEngine::from_config(basic_policy());
    let result = engine.evaluate("send_email", Channel::ExternalEmail, TrustLevel::Untrusted);
    assert!(!result.allowed);
}

#[test]
fn test_hostile_denied_everything() {
    let engine = PolicyEngine::from_config(basic_policy());
    for tool in &["read_email", "shell_exec", "send_email", "anything"] {
        let result = engine.evaluate(tool, Channel::ExternalEmail, TrustLevel::Hostile);
        assert!(!result.allowed, "Hostile should be denied {tool}");
    }
}

#[test]
fn test_default_deny_when_no_rule_matches() {
    let config = PolicyConfig {
        version: "1.0".to_string(),
        default_deny: true,
        rules: vec![],
    };
    let engine = PolicyEngine::from_config(config);
    let result = engine.evaluate("anything", Channel::ExternalEmail, TrustLevel::Untrusted);
    assert!(!result.allowed);
    assert!(result.matched_rule.is_none());
    assert!(result.reason.contains("default"));
}

#[test]
fn test_default_allow_when_configured() {
    let config = PolicyConfig {
        version: "1.0".to_string(),
        default_deny: false,
        rules: vec![],
    };
    let engine = PolicyEngine::from_config(config);
    let result = engine.evaluate("anything", Channel::ExternalEmail, TrustLevel::Untrusted);
    assert!(result.allowed);
}

#[test]
fn test_wildcard_channel_matches_any() {
    let config = PolicyConfig {
        version: "1.0".to_string(),
        default_deny: true,
        rules: vec![PolicyRule {
            channel: Matcher::Wildcard,
            trust: Matcher::Specific(TrustLevel::Untrusted),
            deny: vec!["dangerous".to_string()],
            allow: vec![],
            priority: 0,
        }],
    };
    let engine = PolicyEngine::from_config(config);
    let result = engine.evaluate("dangerous", Channel::ExternalDiscord, TrustLevel::Untrusted);
    assert!(!result.allowed);
}

#[test]
fn test_wildcard_trust_matches_any() {
    let config = PolicyConfig {
        version: "1.0".to_string(),
        default_deny: true,
        rules: vec![PolicyRule {
            channel: Matcher::Specific(Channel::ExternalEmail),
            trust: Matcher::Wildcard,
            deny: vec!["shell_exec".to_string()],
            allow: vec![],
            priority: 0,
        }],
    };
    let engine = PolicyEngine::from_config(config);
    let result = engine.evaluate("shell_exec", Channel::ExternalEmail, TrustLevel::Owner);
    assert!(!result.allowed);
}

#[test]
fn test_priority_ordering_higher_overrides() {
    let config = PolicyConfig {
        version: "1.0".to_string(),
        default_deny: true,
        rules: vec![
            PolicyRule {
                channel: Matcher::Wildcard,
                trust: Matcher::Wildcard,
                deny: vec!["tool_a".to_string()],
                allow: vec![],
                priority: 1,
            },
            PolicyRule {
                channel: Matcher::Wildcard,
                trust: Matcher::Wildcard,
                allow: vec!["tool_a".to_string()],
                deny: vec![],
                priority: 10,
            },
        ],
    };
    let engine = PolicyEngine::from_config(config);
    let result = engine.evaluate("tool_a", Channel::ExternalEmail, TrustLevel::Untrusted);
    assert!(result.allowed);
    assert_eq!(result.matched_rule.unwrap().priority, 10);
}

#[test]
fn test_higher_priority_deny_overrides_lower_allow() {
    let config = PolicyConfig {
        version: "1.0".to_string(),
        default_deny: true,
        rules: vec![
            PolicyRule {
                channel: Matcher::Wildcard,
                trust: Matcher::Wildcard,
                allow: vec!["tool_a".to_string()],
                deny: vec![],
                priority: 1,
            },
            PolicyRule {
                channel: Matcher::Wildcard,
                trust: Matcher::Wildcard,
                deny: vec!["tool_a".to_string()],
                allow: vec![],
                priority: 10,
            },
        ],
    };
    let engine = PolicyEngine::from_config(config);
    let result = engine.evaluate("tool_a", Channel::ExternalEmail, TrustLevel::Untrusted);
    assert!(!result.allowed);
}

#[test]
fn test_from_yaml_basic() {
    let path = fixtures_dir().join("policies").join("basic.yaml");
    let engine = PolicyEngine::from_yaml(&path).unwrap();

    let result = engine.evaluate("shell_exec", Channel::ExternalEmail, TrustLevel::Untrusted);
    assert!(!result.allowed);

    let result = engine.evaluate("read_email", Channel::ExternalEmail, TrustLevel::Untrusted);
    assert!(result.allowed);
}

#[test]
fn test_from_yaml_missing_file() {
    let result = PolicyEngine::from_yaml(std::path::Path::new("/nonexistent/path.yaml"));
    assert!(result.is_err());
}

#[test]
fn test_parse_yaml_invalid_raises() {
    let result = PolicyEngine::parse_yaml("rules: not a list");
    assert!(result.is_err());
}

#[test]
fn test_reload() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("policy.yaml");

    std::fs::write(
        &path,
        "version: \"1.0\"\ndefault_deny: true\nrules:\n  - channel: \"*\"\n    trust: \"*\"\n    deny: [tool_a]\n",
    )
    .unwrap();

    let mut engine = PolicyEngine::from_yaml(&path).unwrap();
    let result = engine.evaluate("tool_a", Channel::OwnerCli, TrustLevel::Owner);
    assert!(!result.allowed);

    std::fs::write(
        &path,
        "version: \"1.0\"\ndefault_deny: true\nrules:\n  - channel: \"*\"\n    trust: \"*\"\n    allow: [tool_a]\n",
    )
    .unwrap();

    engine.reload(&path).unwrap();
    let result = engine.evaluate("tool_a", Channel::OwnerCli, TrustLevel::Owner);
    assert!(result.allowed);
}

#[test]
fn test_validate_warns_wildcard_allow_untrusted() {
    let config = PolicyConfig {
        version: "1.0".to_string(),
        default_deny: true,
        rules: vec![PolicyRule {
            channel: Matcher::Wildcard,
            trust: Matcher::Specific(TrustLevel::Untrusted),
            allow: vec!["*".to_string()],
            deny: vec![],
            priority: 0,
        }],
    };
    let engine = PolicyEngine::from_config(config);
    let warnings = engine.validate();
    assert!(!warnings.is_empty());
    let w = warnings[0].to_lowercase();
    assert!(w.contains("wildcard allow") || w.contains("permissive"));
}

#[test]
fn test_validate_warns_overlap() {
    let config = PolicyConfig {
        version: "1.0".to_string(),
        default_deny: true,
        rules: vec![PolicyRule {
            channel: Matcher::Wildcard,
            trust: Matcher::Wildcard,
            allow: vec!["tool_a".to_string()],
            deny: vec!["tool_a".to_string()],
            priority: 0,
        }],
    };
    let engine = PolicyEngine::from_config(config);
    let warnings = engine.validate();
    assert!(warnings.iter().any(|w| w.contains("tool_a")));
}

// ---------------------------------------------------------------------------
// Shared fixture-driven tests (loads fixtures/test_vectors/policy_evals.json)
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
struct PolicyTestVector {
    description: String,
    policy_file: String,
    tool: String,
    channel: Channel,
    trust: TrustLevel,
    expected_allowed: bool,
    #[serde(default)]
    expected_has_matched_rule: Option<bool>,
    #[serde(default)]
    expected_reason_contains: Option<String>,
    #[serde(default)]
    expected_matched_priority: Option<i32>,
}

#[test]
fn test_shared_fixture_vectors() {
    let vectors_path = fixtures_dir()
        .join("test_vectors")
        .join("policy_evals.json");
    let raw = std::fs::read_to_string(&vectors_path)
        .unwrap_or_else(|e| panic!("Cannot read test vectors at {}: {e}", vectors_path.display()));
    let vectors: Vec<PolicyTestVector> = serde_json::from_str(&raw).unwrap();

    for v in &vectors {
        let policy_path = fixtures_dir().join("policies").join(&v.policy_file);
        let engine = PolicyEngine::from_yaml(&policy_path)
            .unwrap_or_else(|e| panic!("Failed to load {}: {e}", v.policy_file));

        let result = engine.evaluate(&v.tool, v.channel, v.trust);

        assert_eq!(
            result.allowed, v.expected_allowed,
            "FAILED [{}]: tool={} channel={} trust={} — expected allowed={}, got={}",
            v.description, v.tool, v.channel, v.trust, v.expected_allowed, result.allowed,
        );

        if let Some(has_rule) = v.expected_has_matched_rule {
            assert_eq!(
                result.matched_rule.is_some(),
                has_rule,
                "FAILED [{}]: expected matched_rule.is_some()={}",
                v.description,
                has_rule,
            );
        }

        if let Some(ref contains) = v.expected_reason_contains {
            assert!(
                result.reason.contains(contains.as_str()),
                "FAILED [{}]: reason '{}' does not contain '{}'",
                v.description,
                result.reason,
                contains,
            );
        }

        if let Some(prio) = v.expected_matched_priority {
            assert_eq!(
                result.matched_rule.as_ref().unwrap().priority,
                prio,
                "FAILED [{}]: expected matched priority={}, got={}",
                v.description,
                prio,
                result.matched_rule.as_ref().unwrap().priority,
            );
        }
    }
}
