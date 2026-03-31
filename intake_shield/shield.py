"""ContextShield: facade composing all components into one middleware."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Callable

from intake_shield.audit import AuditLog
from intake_shield.context import ContextWindowBuilder
from intake_shield.guard import ActionGuard
from intake_shield.policy import PolicyEngine
from intake_shield.provenance import ProvenanceTracker
from intake_shield.tagger import ContextTagger
from intake_shield.types import (
    Channel,
    GuardDecision,
    TaggedInput,
    ToolCall,
    TrustLevel,
)

logger = logging.getLogger(__name__)


class ContextShield:
    """Facade composing all components. Single entry point for users.

    Usage:
        shield = ContextShield.from_policy("policy.yaml")

        # Tag and add input
        tagged = shield.tag_input(email_body, Channel.EXTERNAL_EMAIL)
        shield.add_to_context(tagged)

        # Build messages for LLM
        messages = shield.build_context()

        # After LLM responds with tool call:
        decision = shield.check_tool_call("shell_exec", {"command": "rm -rf /"})
        if decision.allowed:
            result = execute_tool(...)
    """

    def __init__(
        self,
        tagger: ContextTagger,
        policy: PolicyEngine,
        guard: ActionGuard,
        context_builder: ContextWindowBuilder,
        provenance: ProvenanceTracker,
        audit: AuditLog,
    ) -> None:
        self.tagger = tagger
        self.policy = policy
        self.guard = guard
        self.context_builder = context_builder
        self.provenance = provenance
        self.audit = audit

    @classmethod
    def from_policy(
        cls,
        policy_path: Path | str,
        system_preamble: str = "",
        max_untrusted_tokens: int | None = None,
        audit_log_file: Path | None = None,
    ) -> ContextShield:
        """Create a fully wired ContextShield from a policy YAML file."""
        tagger = ContextTagger()
        policy = PolicyEngine.from_yaml(policy_path)
        provenance = ProvenanceTracker()
        audit = AuditLog(log_file=audit_log_file)
        guard = ActionGuard(policy=policy, provenance=provenance, audit=audit)
        context_builder = ContextWindowBuilder(
            system_preamble=system_preamble,
            max_untrusted_tokens=max_untrusted_tokens,
        )
        return cls(
            tagger=tagger,
            policy=policy,
            guard=guard,
            context_builder=context_builder,
            provenance=provenance,
            audit=audit,
        )

    def tag_input(
        self,
        content: str,
        channel: Channel,
        *,
        source_description: str = "",
        metadata: dict[str, Any] | None = None,
        trust_override: TrustLevel | None = None,
    ) -> TaggedInput:
        """Tag a raw input with trust metadata."""
        return self.tagger.tag(
            content,
            channel,
            source_description=source_description,
            metadata=metadata,
            trust_override=trust_override,
        )

    def add_to_context(
        self,
        tagged_input: TaggedInput,
        role: str = "user",
    ) -> None:
        """Register in provenance tracker and add to context builder."""
        self.provenance.register(tagged_input)
        self.context_builder.add_input(tagged_input, role=role)

    def add_assistant_message(self, content: str) -> None:
        """Add an assistant response to context."""
        self.context_builder.add_assistant_message(content)

    def build_context(self) -> list[dict]:
        """Build messages array ready for LLM API call."""
        return self.context_builder.build()

    def check_tool_call(
        self,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
        originating_input_ids: list[str] | None = None,
    ) -> GuardDecision:
        """Check if a tool call is permitted by policy."""
        tc = ToolCall(
            tool_name=tool_name,
            arguments=arguments or {},
            originating_inputs=originating_input_ids or [],
        )
        return self.guard.check(tc)

    def wrap_tools(
        self,
        tools: dict[str, Callable],
    ) -> dict[str, Callable]:
        """Wrap a dict of {name: function} with guard checks."""
        return {
            name: self.guard.wrap_tool(name, fn) for name, fn in tools.items()
        }

    def reset(self) -> None:
        """Clear all state for a new conversation."""
        self.provenance.clear()
        self.context_builder.clear()
