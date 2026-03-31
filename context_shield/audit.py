"""AuditLog: structured logging of guard decisions."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Literal

from context_shield.types import AuditEntry, GuardDecision

logger = logging.getLogger(__name__)


class AuditLog:
    """Structured audit log for all guard decisions."""

    def __init__(
        self,
        log_file: Path | None = None,
    ) -> None:
        self._entries: list[AuditEntry] = []
        self._log_file = log_file

    def record(self, entry: AuditEntry) -> None:
        """Record an audit entry."""
        self._entries.append(entry)
        logger.info(
            "Audit: %s tool=%s reason=%s",
            entry.action_taken,
            entry.decision.tool_call.tool_name,
            entry.decision.reason,
        )
        if self._log_file:
            self._append_to_file(entry)

    def _append_to_file(self, entry: AuditEntry) -> None:
        """Append entry to the log file as JSON lines."""
        with open(self._log_file, "a", encoding="utf-8") as f:
            f.write(entry.model_dump_json() + "\n")

    def get_recent(self, n: int = 50) -> list[AuditEntry]:
        """Get the most recent N entries."""
        return self._entries[-n:]

    def get_blocked(self) -> list[AuditEntry]:
        """Get all blocked entries."""
        return [e for e in self._entries if e.action_taken == "blocked"]

    def get_allowed(self) -> list[AuditEntry]:
        """Get all allowed entries."""
        return [e for e in self._entries if e.action_taken == "allowed"]

    @property
    def entries(self) -> list[AuditEntry]:
        return list(self._entries)
