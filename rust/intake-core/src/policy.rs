//! PolicyEngine: loads and evaluates trust-based access control rules.
//!
//! Direct port of `intake_shield/policy.py`.
//!
//! Evaluation uses "last match wins with explicit priority":
//! 1. Collect all rules matching (channel, trust) — wildcards included
//! 2. Sort by priority ascending
//! 3. Walk sorted list; each matching deny/allow updates the verdict
//! 4. Final verdict stands. If no rule ever mentioned the tool, default_deny applies.

use std::path::Path;

use crate::error::IntakeError;
use crate::types::{Channel, EvalResult, Matcher, PolicyConfig, PolicyRule, TrustLevel};

/// Loads and evaluates policy rules against `(channel, trust, tool_name)` tuples.
pub struct PolicyEngine {
    config: PolicyConfig,
    /// Rules pre-sorted by priority ascending.
    rules: Vec<PolicyRule>,
}

impl PolicyEngine {
    /// Create from an already-parsed config.
    pub fn from_config(config: PolicyConfig) -> Self {
        let mut rules = config.rules.clone();
        rules.sort_by_key(|r| r.priority);
        Self { config, rules }
    }

    /// Load policy from a YAML file.
    pub fn from_yaml(path: &Path) -> Result<Self, IntakeError> {
        let raw = std::fs::read_to_string(path).map_err(|e| {
            IntakeError::PolicyLoad(format!("Cannot read policy file: {}: {e}", path.display()))
        })?;
        Self::parse_yaml(&raw)
    }

    /// Load policy from a YAML string.
    pub fn parse_yaml(yaml: &str) -> Result<Self, IntakeError> {
        let config: PolicyConfig =
            serde_yaml::from_str(yaml).map_err(|e| IntakeError::PolicyValidation(e.to_string()))?;
        Ok(Self::from_config(config))
    }

    /// Load policy from a dict-like structure (serde_json::Value or similar).
    pub fn from_value(value: serde_json::Value) -> Result<Self, IntakeError> {
        let config: PolicyConfig = serde_json::from_value(value)
            .map_err(|e| IntakeError::PolicyValidation(e.to_string()))?;
        Ok(Self::from_config(config))
    }

    /// Hot-reload policy from file.
    pub fn reload(&mut self, path: &Path) -> Result<(), IntakeError> {
        let new = Self::from_yaml(path)?;
        self.config = new.config;
        self.rules = new.rules;
        Ok(())
    }

    /// Evaluate whether a tool call is permitted.
    ///
    /// Returns `EvalResult { allowed, matched_rule, reason }`.
    pub fn evaluate(
        &self,
        tool_name: &str,
        channel: Channel,
        trust: TrustLevel,
    ) -> EvalResult {
        let mut verdict: Option<bool> = None;
        let mut matched_rule: Option<&PolicyRule> = None;

        for rule in &self.rules {
            if !Self::matches_rule(rule, channel, trust) {
                continue;
            }

            if rule.deny.contains(&tool_name.to_string())
                || rule.deny.iter().any(|d| d == "*")
            {
                verdict = Some(false);
                matched_rule = Some(rule);
            }
            if rule.allow.contains(&tool_name.to_string())
                || rule.allow.iter().any(|a| a == "*")
            {
                verdict = Some(true);
                matched_rule = Some(rule);
            }
        }

        match verdict {
            None => {
                if self.config.default_deny {
                    EvalResult {
                        allowed: false,
                        matched_rule: None,
                        reason: format!(
                            "No rule matched for tool '{tool_name}' on channel={channel} trust={trust}; default policy is deny"
                        ),
                    }
                } else {
                    EvalResult {
                        allowed: true,
                        matched_rule: None,
                        reason: format!(
                            "No rule matched for tool '{tool_name}'; default policy is allow"
                        ),
                    }
                }
            }
            Some(allowed) => {
                let rule = matched_rule.expect("matched_rule must be set when verdict is Some");
                let action = if allowed { "allowed" } else { "denied" };
                let reason = format!(
                    "Tool '{}' {} by rule (channel={}, trust={}, priority={})",
                    tool_name,
                    action,
                    match &rule.channel {
                        Matcher::Wildcard => "*".to_string(),
                        Matcher::Specific(c) => c.to_string(),
                    },
                    match &rule.trust {
                        Matcher::Wildcard => "*".to_string(),
                        Matcher::Specific(t) => t.to_string(),
                    },
                    rule.priority,
                );
                EvalResult {
                    allowed,
                    matched_rule: Some(rule.clone()),
                    reason,
                }
            }
        }
    }

    /// Check policy for potential misconfigurations. Returns warnings.
    pub fn validate(&self) -> Vec<String> {
        let mut warnings = Vec::new();

        for (i, rule) in self.rules.iter().enumerate() {
            // Warn on wildcard allow with untrusted/hostile trust
            if rule.allow.iter().any(|a| a == "*") {
                let is_risky = matches!(
                    &rule.trust,
                    Matcher::Specific(TrustLevel::Untrusted)
                        | Matcher::Specific(TrustLevel::Hostile)
                        | Matcher::Wildcard
                );
                if is_risky {
                    warnings.push(format!(
                        "Rule {i}: wildcard allow on trust={} — this may be overly permissive",
                        match &rule.trust {
                            Matcher::Wildcard => "*".to_string(),
                            Matcher::Specific(t) => t.to_string(),
                        }
                    ));
                }
            }

            // Warn on tools in both allow and deny
            if !rule.allow.is_empty() && !rule.deny.is_empty() {
                let allow_set: std::collections::HashSet<_> = rule.allow.iter().collect();
                let deny_set: std::collections::HashSet<_> = rule.deny.iter().collect();
                let overlap: Vec<_> = allow_set.intersection(&deny_set).collect();
                if !overlap.is_empty() {
                    let overlap_str: Vec<_> = overlap.iter().map(|s| s.as_str()).collect();
                    warnings.push(format!(
                        "Rule {i}: tools {{{}}} appear in both allow and deny — deny checked first, then allow overrides",
                        overlap_str.join(", ")
                    ));
                }
            }
        }

        warnings
    }

    /// Access the underlying config.
    pub fn config(&self) -> &PolicyConfig {
        &self.config
    }

    fn matches_rule(rule: &PolicyRule, channel: Channel, trust: TrustLevel) -> bool {
        rule.channel.matches(&channel) && rule.trust.matches(&trust)
    }
}
