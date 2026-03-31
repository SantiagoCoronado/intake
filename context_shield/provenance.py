"""ProvenanceTracker: tracks tagged inputs and resolves effective trust."""

from __future__ import annotations

import logging

from context_shield.exceptions import ProvenanceError
from context_shield.types import Channel, TaggedInput, TrustLevel

logger = logging.getLogger(__name__)


class ProvenanceTracker:
    """Tracks which tagged inputs are in the current context window
    and resolves effective trust for tool calls."""

    def __init__(self) -> None:
        self._inputs: dict[str, TaggedInput] = {}

    def register(self, tagged_input: TaggedInput) -> None:
        """Register a tagged input as present in the context."""
        self._inputs[tagged_input.id] = tagged_input
        logger.debug(
            "Registered input %s: channel=%s trust=%s",
            tagged_input.id,
            tagged_input.channel.value,
            tagged_input.trust.name,
        )

    def remove(self, input_id: str) -> None:
        """Remove an input (e.g., when context is trimmed)."""
        self._inputs.pop(input_id, None)

    def get(self, input_id: str) -> TaggedInput | None:
        """Get a tagged input by ID."""
        return self._inputs.get(input_id)

    def resolve_effective_trust(
        self, input_ids: list[str] | None = None
    ) -> tuple[TrustLevel, Channel]:
        """Resolve the effective (trust, channel) for a set of input IDs.

        If input_ids is None or empty, considers ALL registered inputs.
        Returns (min_trust, channel_of_min_trust_input).

        Raises ProvenanceError if no inputs are registered.
        """
        if input_ids:
            inputs = []
            for iid in input_ids:
                inp = self._inputs.get(iid)
                if inp is None:
                    raise ProvenanceError(
                        f"Input ID '{iid}' not found in provenance tracker"
                    )
                inputs.append(inp)
        else:
            inputs = list(self._inputs.values())

        if not inputs:
            raise ProvenanceError("No inputs registered in provenance tracker")

        min_input = min(inputs, key=lambda i: i.trust)
        return min_input.trust, min_input.channel

    def all_inputs(self) -> list[TaggedInput]:
        """Return all registered inputs."""
        return list(self._inputs.values())

    def input_ids(self) -> list[str]:
        """Return all registered input IDs."""
        return list(self._inputs.keys())

    def clear(self) -> None:
        """Remove all tracked inputs."""
        self._inputs.clear()
