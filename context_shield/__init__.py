"""context-shield: Trust boundary enforcement for autonomous AI agents."""

from context_shield.types import (
    AuditEntry,
    Channel,
    GuardDecision,
    PolicyConfig,
    PolicyRule,
    TaggedInput,
    ToolCall,
    TrustLevel,
)
from context_shield.tagger import ContextTagger
from context_shield.policy import PolicyEngine
from context_shield.guard import ActionGuard
from context_shield.provenance import ProvenanceTracker
from context_shield.audit import AuditLog
from context_shield.context import ContextWindowBuilder
from context_shield.shield import ContextShield
from context_shield.exceptions import (
    ActionBlockedError,
    ContextShieldError,
    PolicyLoadError,
    PolicyValidationError,
    ProvenanceError,
)

__all__ = [
    "ActionBlockedError",
    "ActionGuard",
    "AuditEntry",
    "AuditLog",
    "Channel",
    "ContextShield",
    "ContextShieldError",
    "ContextTagger",
    "ContextWindowBuilder",
    "GuardDecision",
    "PolicyConfig",
    "PolicyEngine",
    "PolicyLoadError",
    "PolicyRule",
    "PolicyValidationError",
    "ProvenanceError",
    "ProvenanceTracker",
    "TaggedInput",
    "ToolCall",
    "TrustLevel",
]
