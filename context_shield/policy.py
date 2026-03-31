"""PolicyEngine: loads and evaluates trust-based access control rules."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from context_shield.exceptions import PolicyLoadError, PolicyValidationError
from context_shield.types import (
    Channel,
    PolicyConfig,
    PolicyRule,
    TrustLevel,
)

logger = logging.getLogger(__name__)


class PolicyEngine:
    """Loads and evaluates policy rules against (channel, trust, tool_name) tuples.

    Evaluation uses "last match wins with explicit priority":
    1. Collect all rules matching (channel, trust) — wildcards included
    2. Sort by priority ascending
    3. Walk sorted list; each matching deny/allow updates the verdict
    4. Final verdict stands. If no rule ever mentioned the tool, default_deny applies.
    """

    def __init__(self, config: PolicyConfig) -> None:
        self._config = config
        self._rules = sorted(config.rules, key=lambda r: r.priority)

    @classmethod
    def from_yaml(cls, path: Path | str) -> PolicyEngine:
        """Load policy from a YAML file."""
        path = Path(path)
        try:
            raw = path.read_text(encoding="utf-8")
        except OSError as e:
            raise PolicyLoadError(f"Cannot read policy file: {path}") from e

        try:
            data = yaml.safe_load(raw)
        except yaml.YAMLError as e:
            raise PolicyLoadError(f"Invalid YAML in {path}") from e

        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PolicyEngine:
        """Load policy from a dict."""
        try:
            config = PolicyConfig(**data)
        except (ValidationError, TypeError) as e:
            raise PolicyValidationError(f"Invalid policy config: {e}") from e
        return cls(config)

    def reload(self, path: Path | str) -> None:
        """Hot-reload policy from file."""
        engine = self.from_yaml(path)
        self._config = engine._config
        self._rules = engine._rules
        logger.info("Policy reloaded from %s", path)

    def evaluate(
        self,
        tool_name: str,
        channel: Channel,
        trust: TrustLevel,
    ) -> tuple[bool, PolicyRule | None, str]:
        """Evaluate whether a tool call is permitted.

        Returns (allowed, matched_rule, reason).
        """
        verdict: bool | None = None
        matched_rule: PolicyRule | None = None

        for rule in self._rules:
            if not self._matches_rule(rule, channel, trust):
                continue

            if tool_name in rule.deny or "*" in rule.deny:
                verdict = False
                matched_rule = rule
            if tool_name in rule.allow or "*" in rule.allow:
                verdict = True
                matched_rule = rule

        if verdict is None:
            if self._config.default_deny:
                return (
                    False,
                    None,
                    f"No rule matched for tool '{tool_name}' on "
                    f"channel={channel.value} trust={trust.name}; "
                    f"default policy is deny",
                )
            return (
                True,
                None,
                f"No rule matched for tool '{tool_name}'; default policy is allow",
            )

        action = "allowed" if verdict else "denied"
        reason = (
            f"Tool '{tool_name}' {action} by rule "
            f"(channel={matched_rule.channel}, trust={matched_rule.trust}, "
            f"priority={matched_rule.priority})"
        )
        return verdict, matched_rule, reason

    def _matches_rule(
        self, rule: PolicyRule, channel: Channel, trust: TrustLevel
    ) -> bool:
        """Check if a rule's selectors match the given channel and trust."""
        channel_match = rule.channel == "*" or rule.channel == channel
        trust_match = rule.trust == "*" or rule.trust == trust
        return channel_match and trust_match

    def validate(self) -> list[str]:
        """Check policy for potential misconfigurations. Returns warnings."""
        warnings: list[str] = []
        for i, rule in enumerate(self._rules):
            if "*" in rule.allow and rule.trust in (
                TrustLevel.UNTRUSTED,
                TrustLevel.HOSTILE,
                "*",
            ):
                warnings.append(
                    f"Rule {i}: wildcard allow on "
                    f"trust={rule.trust} — this may be overly permissive"
                )
            if rule.allow and rule.deny:
                overlap = set(rule.allow) & set(rule.deny)
                if overlap:
                    warnings.append(
                        f"Rule {i}: tools {overlap} appear in both "
                        f"allow and deny — deny checked first, "
                        f"then allow overrides"
                    )
        return warnings

    @property
    def config(self) -> PolicyConfig:
        return self._config
