"""Custom exceptions for context-shield."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from context_shield.types import GuardDecision


class ContextShieldError(Exception):
    """Base exception for context-shield."""


class PolicyLoadError(ContextShieldError):
    """Failed to load or parse policy file."""


class PolicyValidationError(ContextShieldError):
    """Policy file has invalid rules."""


class ActionBlockedError(ContextShieldError):
    """A tool call was blocked by policy."""

    def __init__(self, decision: GuardDecision) -> None:
        self.decision = decision
        super().__init__(
            f"Blocked: {decision.tool_call.tool_name} — {decision.reason}"
        )


class ProvenanceError(ContextShieldError):
    """Referenced input ID not found in provenance tracker."""
