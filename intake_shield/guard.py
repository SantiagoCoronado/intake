"""ActionGuard: intercepts tool calls and enforces policy."""

from __future__ import annotations

import functools
import logging
from typing import Any, Callable

from intake_shield.audit import AuditLog
from intake_shield.exceptions import ActionBlockedError
from intake_shield.policy import PolicyEngine
from intake_shield.provenance import ProvenanceTracker
from intake_shield.types import AuditEntry, GuardDecision, ToolCall

logger = logging.getLogger(__name__)

GuardHook = Callable[[ToolCall, GuardDecision], GuardDecision | None]


class ActionGuard:
    """Intercepts tool calls and enforces policy.

    Resolves effective trust from provenance, evaluates against policy,
    and logs all decisions.
    """

    def __init__(
        self,
        policy: PolicyEngine,
        provenance: ProvenanceTracker,
        audit: AuditLog | None = None,
        on_block: GuardHook | None = None,
        on_allow: GuardHook | None = None,
    ) -> None:
        self._policy = policy
        self._provenance = provenance
        self._audit = audit or AuditLog()
        self._on_block = on_block
        self._on_allow = on_allow

    def check(self, tool_call: ToolCall) -> GuardDecision:
        """Evaluate a tool call against policy WITHOUT executing it.

        Resolves effective (channel, trust) from provenance tracker:
        - Uses originating_inputs if provided
        - Falls back to minimum trust of ALL context inputs (conservative)
        """
        effective_trust, effective_channel = self._provenance.resolve_effective_trust(
            tool_call.originating_inputs or None
        )

        allowed, matched_rule, reason = self._policy.evaluate(
            tool_call.tool_name, effective_channel, effective_trust
        )

        decision = GuardDecision(
            allowed=allowed,
            tool_call=tool_call,
            matched_rule=matched_rule,
            effective_trust=effective_trust,
            effective_channel=effective_channel,
            reason=reason,
        )

        action_taken = "allowed" if allowed else "blocked"
        entry = AuditEntry(
            decision=decision,
            context_input_ids=self._provenance.input_ids(),
            action_taken=action_taken,
        )
        self._audit.record(entry)

        if allowed and self._on_allow:
            override = self._on_allow(tool_call, decision)
            if override is not None:
                return override
        elif not allowed and self._on_block:
            override = self._on_block(tool_call, decision)
            if override is not None:
                return override

        logger.info(
            "Guard %s: tool=%s trust=%s channel=%s — %s",
            action_taken.upper(),
            tool_call.tool_name,
            effective_trust.name,
            effective_channel.value,
            reason,
        )
        return decision

    def wrap_tool(
        self,
        tool_name: str,
        tool_fn: Callable[..., Any],
    ) -> Callable[..., Any]:
        """Returns a wrapped version of tool_fn that checks policy before executing.

        Raises ActionBlockedError if the tool call is denied.
        """

        @functools.wraps(tool_fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            tc = ToolCall(tool_name=tool_name, arguments=kwargs or {})
            decision = self.check(tc)
            if not decision.allowed:
                raise ActionBlockedError(decision)
            return tool_fn(*args, **kwargs)

        return wrapper

    def guard_decorator(self, tool_name: str | None = None) -> Callable:
        """Decorator form of wrap_tool.

        Usage:
            @guard.guard_decorator()
            def shell_exec(command: str) -> str: ...
        """

        def decorator(fn: Callable) -> Callable:
            name = tool_name or fn.__name__
            return self.wrap_tool(name, fn)

        return decorator

    @property
    def audit(self) -> AuditLog:
        return self._audit
