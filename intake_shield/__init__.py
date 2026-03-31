"""intake: Trust boundary enforcement for autonomous AI agents."""

from intake_shield.types import (
    AuditEntry,
    Channel,
    GuardDecision,
    PolicyConfig,
    PolicyRule,
    TaggedInput,
    ToolCall,
    TrustLevel,
)
from intake_shield.tagger import ContextTagger
from intake_shield.policy import PolicyEngine
from intake_shield.guard import ActionGuard
from intake_shield.provenance import ProvenanceTracker
from intake_shield.audit import AuditLog
from intake_shield.context import ContextWindowBuilder
from intake_shield.shield import ContextShield
from intake_shield.exceptions import (
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
