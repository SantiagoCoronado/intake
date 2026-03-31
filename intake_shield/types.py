"""Core data structures for intake."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import IntEnum, Enum
from typing import Any, Literal

from pydantic import BaseModel, Field


class TrustLevel(IntEnum):
    """Ordered trust levels. Higher value = more trusted.

    IntEnum so comparisons like `trust >= TrustLevel.TRUSTED` work naturally.
    """

    HOSTILE = 0
    UNTRUSTED = 10
    TRUSTED = 20
    OWNER = 30


class Channel(str, Enum):
    """Known input source channels."""

    OWNER_CLI = "owner_cli"
    API_AUTHORIZED = "api_authorized"
    EXTERNAL_EMAIL = "external_email"
    EXTERNAL_DISCORD = "external_discord"
    EXTERNAL_WEBHOOK = "external_webhook"
    FILE_CONTENT = "file_content"
    TOOL_OUTPUT = "tool_output"
    SYSTEM = "system"


class TaggedInput(BaseModel):
    """An input segment with immutable trust metadata."""

    model_config = {"frozen": True}

    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    content: str
    channel: Channel
    trust: TrustLevel
    source_description: str = ""
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    metadata: dict[str, Any] = Field(default_factory=dict)


class PolicyRule(BaseModel):
    """A single policy rule mapping (channel, trust) -> permissions."""

    channel: Channel | Literal["*"] = "*"
    trust: TrustLevel | Literal["*"] = "*"
    allow: list[str] = Field(default_factory=list)
    deny: list[str] = Field(default_factory=list)
    priority: int = 0


class PolicyConfig(BaseModel):
    """Top-level policy document."""

    version: str = "1.0"
    default_deny: bool = True
    rules: list[PolicyRule]


class ToolCall(BaseModel):
    """Represents an intended tool invocation."""

    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    originating_inputs: list[str] = Field(default_factory=list)


class GuardDecision(BaseModel):
    """Result of ActionGuard evaluation."""

    allowed: bool
    tool_call: ToolCall
    matched_rule: PolicyRule | None = None
    effective_trust: TrustLevel | None = None
    effective_channel: Channel | None = None
    reason: str = ""
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


class AuditEntry(BaseModel):
    """Structured audit log entry."""

    decision: GuardDecision
    context_input_ids: list[str] = Field(default_factory=list)
    action_taken: Literal["allowed", "blocked", "escalated"]
