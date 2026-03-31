"""Tests for PolicyEngine."""

import pytest
from pathlib import Path

from intake_shield.policy import PolicyEngine
from intake_shield.types import (
    Channel,
    PolicyConfig,
    PolicyRule,
    TrustLevel,
)
from intake_shield.exceptions import PolicyLoadError, PolicyValidationError


@pytest.fixture
def basic_policy() -> PolicyConfig:
    return PolicyConfig(
        rules=[
            PolicyRule(
                channel=Channel.OWNER_CLI,
                trust=TrustLevel.OWNER,
                allow=["*"],
                priority=0,
            ),
            PolicyRule(
                channel=Channel.EXTERNAL_EMAIL,
                trust=TrustLevel.UNTRUSTED,
                allow=["read_email", "summarize"],
                deny=["shell_exec", "send_email"],
                priority=10,
            ),
            PolicyRule(
                channel="*",
                trust=TrustLevel.HOSTILE,
                deny=["*"],
                priority=100,
            ),
        ]
    )


class TestPolicyEngine:
    def test_owner_allowed_everything(self, basic_policy: PolicyConfig):
        engine = PolicyEngine(basic_policy)
        allowed, rule, reason = engine.evaluate(
            "shell_exec", Channel.OWNER_CLI, TrustLevel.OWNER
        )
        assert allowed is True
        assert rule is not None

    def test_untrusted_email_allowed_read(self, basic_policy: PolicyConfig):
        engine = PolicyEngine(basic_policy)
        allowed, _, _ = engine.evaluate(
            "read_email", Channel.EXTERNAL_EMAIL, TrustLevel.UNTRUSTED
        )
        assert allowed is True

    def test_untrusted_email_denied_shell(self, basic_policy: PolicyConfig):
        engine = PolicyEngine(basic_policy)
        allowed, _, reason = engine.evaluate(
            "shell_exec", Channel.EXTERNAL_EMAIL, TrustLevel.UNTRUSTED
        )
        assert allowed is False
        assert "shell_exec" in reason

    def test_untrusted_email_denied_send(self, basic_policy: PolicyConfig):
        engine = PolicyEngine(basic_policy)
        allowed, _, _ = engine.evaluate(
            "send_email", Channel.EXTERNAL_EMAIL, TrustLevel.UNTRUSTED
        )
        assert allowed is False

    def test_hostile_denied_everything(self, basic_policy: PolicyConfig):
        engine = PolicyEngine(basic_policy)
        for tool in ["read_email", "shell_exec", "send_email", "anything"]:
            allowed, _, _ = engine.evaluate(
                tool, Channel.EXTERNAL_EMAIL, TrustLevel.HOSTILE
            )
            assert allowed is False, f"Hostile should be denied {tool}"

    def test_default_deny_when_no_rule_matches(self):
        engine = PolicyEngine(PolicyConfig(default_deny=True, rules=[]))
        allowed, rule, reason = engine.evaluate(
            "anything", Channel.EXTERNAL_EMAIL, TrustLevel.UNTRUSTED
        )
        assert allowed is False
        assert rule is None
        assert "default" in reason

    def test_default_allow_when_configured(self):
        engine = PolicyEngine(PolicyConfig(default_deny=False, rules=[]))
        allowed, rule, reason = engine.evaluate(
            "anything", Channel.EXTERNAL_EMAIL, TrustLevel.UNTRUSTED
        )
        assert allowed is True

    def test_wildcard_channel_matches_any(self):
        config = PolicyConfig(
            rules=[
                PolicyRule(channel="*", trust=TrustLevel.UNTRUSTED, deny=["dangerous"]),
            ]
        )
        engine = PolicyEngine(config)
        allowed, _, _ = engine.evaluate(
            "dangerous", Channel.EXTERNAL_DISCORD, TrustLevel.UNTRUSTED
        )
        assert allowed is False

    def test_wildcard_trust_matches_any(self):
        config = PolicyConfig(
            rules=[
                PolicyRule(
                    channel=Channel.EXTERNAL_EMAIL,
                    trust="*",
                    deny=["shell_exec"],
                ),
            ]
        )
        engine = PolicyEngine(config)
        allowed, _, _ = engine.evaluate(
            "shell_exec", Channel.EXTERNAL_EMAIL, TrustLevel.OWNER
        )
        assert allowed is False

    def test_priority_ordering_higher_overrides(self):
        config = PolicyConfig(
            rules=[
                PolicyRule(
                    channel="*",
                    trust="*",
                    deny=["tool_a"],
                    priority=1,
                ),
                PolicyRule(
                    channel="*",
                    trust="*",
                    allow=["tool_a"],
                    priority=10,
                ),
            ]
        )
        engine = PolicyEngine(config)
        allowed, rule, _ = engine.evaluate(
            "tool_a", Channel.EXTERNAL_EMAIL, TrustLevel.UNTRUSTED
        )
        assert allowed is True
        assert rule.priority == 10

    def test_higher_priority_deny_overrides_lower_allow(self):
        config = PolicyConfig(
            rules=[
                PolicyRule(
                    channel="*",
                    trust="*",
                    allow=["tool_a"],
                    priority=1,
                ),
                PolicyRule(
                    channel="*",
                    trust="*",
                    deny=["tool_a"],
                    priority=10,
                ),
            ]
        )
        engine = PolicyEngine(config)
        allowed, _, _ = engine.evaluate(
            "tool_a", Channel.EXTERNAL_EMAIL, TrustLevel.UNTRUSTED
        )
        assert allowed is False

    def test_from_yaml(self, tmp_path: Path):
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text(
            """
version: "1.0"
default_deny: true
rules:
  - channel: owner_cli
    trust: 30
    allow: ["*"]
    priority: 0
  - channel: external_email
    trust: 10
    deny: [shell_exec]
    allow: [read_email]
    priority: 10
"""
        )
        engine = PolicyEngine.from_yaml(policy_file)
        allowed, _, _ = engine.evaluate(
            "shell_exec", Channel.EXTERNAL_EMAIL, TrustLevel.UNTRUSTED
        )
        assert allowed is False
        allowed, _, _ = engine.evaluate(
            "read_email", Channel.EXTERNAL_EMAIL, TrustLevel.UNTRUSTED
        )
        assert allowed is True

    def test_from_yaml_missing_file(self):
        with pytest.raises(PolicyLoadError):
            PolicyEngine.from_yaml("/nonexistent/path.yaml")

    def test_from_dict_invalid_raises(self):
        with pytest.raises(PolicyValidationError):
            PolicyEngine.from_dict({"rules": "not a list"})

    def test_reload(self, tmp_path: Path):
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text(
            'version: "1.0"\ndefault_deny: true\nrules:\n'
            "  - channel: \"*\"\n    trust: \"*\"\n    deny: [tool_a]\n"
        )
        engine = PolicyEngine.from_yaml(policy_file)
        allowed, _, _ = engine.evaluate(
            "tool_a", Channel.OWNER_CLI, TrustLevel.OWNER
        )
        assert allowed is False

        policy_file.write_text(
            'version: "1.0"\ndefault_deny: true\nrules:\n'
            "  - channel: \"*\"\n    trust: \"*\"\n    allow: [tool_a]\n"
        )
        engine.reload(policy_file)
        allowed, _, _ = engine.evaluate(
            "tool_a", Channel.OWNER_CLI, TrustLevel.OWNER
        )
        assert allowed is True

    def test_validate_warns_wildcard_allow_untrusted(self):
        config = PolicyConfig(
            rules=[
                PolicyRule(
                    channel="*",
                    trust=TrustLevel.UNTRUSTED,
                    allow=["*"],
                ),
            ]
        )
        engine = PolicyEngine(config)
        warnings = engine.validate()
        assert len(warnings) >= 1
        assert "wildcard allow" in warnings[0].lower() or "permissive" in warnings[0].lower()

    def test_validate_warns_overlap(self):
        config = PolicyConfig(
            rules=[
                PolicyRule(
                    channel="*",
                    trust="*",
                    allow=["tool_a"],
                    deny=["tool_a"],
                ),
            ]
        )
        engine = PolicyEngine(config)
        warnings = engine.validate()
        assert any("tool_a" in w for w in warnings)
