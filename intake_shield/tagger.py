"""ContextTagger: classifies inputs with trust metadata."""

from __future__ import annotations

import logging
from typing import Any, Callable

from intake_shield.types import Channel, TaggedInput, TrustLevel

logger = logging.getLogger(__name__)

ChannelClassifier = Callable[[str, dict[str, Any]], Channel]
TrustClassifier = Callable[[Channel, dict[str, Any]], TrustLevel]

DEFAULT_TRUST_MAP: dict[Channel, TrustLevel] = {
    Channel.OWNER_CLI: TrustLevel.OWNER,
    Channel.SYSTEM: TrustLevel.OWNER,
    Channel.API_AUTHORIZED: TrustLevel.TRUSTED,
    Channel.TOOL_OUTPUT: TrustLevel.TRUSTED,
    Channel.FILE_CONTENT: TrustLevel.UNTRUSTED,
    Channel.EXTERNAL_EMAIL: TrustLevel.UNTRUSTED,
    Channel.EXTERNAL_DISCORD: TrustLevel.UNTRUSTED,
    Channel.EXTERNAL_WEBHOOK: TrustLevel.UNTRUSTED,
}


class ContextTagger:
    """Tags raw inputs with trust metadata before they enter the context window.

    Uses a registry of (channel -> trust) defaults, overridable with
    custom classifier functions.
    """

    def __init__(
        self,
        default_trust_map: dict[Channel, TrustLevel] | None = None,
        channel_classifier: ChannelClassifier | None = None,
        trust_classifier: TrustClassifier | None = None,
    ) -> None:
        self._trust_map = default_trust_map or dict(DEFAULT_TRUST_MAP)
        self._channel_classifier = channel_classifier
        self._trust_classifier = trust_classifier

    def tag(
        self,
        content: str,
        channel: Channel,
        *,
        source_description: str = "",
        metadata: dict[str, Any] | None = None,
        trust_override: TrustLevel | None = None,
    ) -> TaggedInput:
        """Create an immutable TaggedInput from raw content.

        If trust_override is provided it takes precedence.
        Otherwise, trust is resolved via trust_classifier (if set)
        or the default_trust_map.
        """
        meta = metadata or {}

        if trust_override is not None:
            trust = trust_override
        elif self._trust_classifier is not None:
            trust = self._trust_classifier(channel, meta)
        else:
            trust = self._trust_map.get(channel, TrustLevel.UNTRUSTED)

        tagged = TaggedInput(
            content=content,
            channel=channel,
            trust=trust,
            source_description=source_description,
            metadata=meta,
        )
        logger.debug(
            "Tagged input %s: channel=%s trust=%s source=%s",
            tagged.id,
            channel.value,
            trust.name,
            source_description,
        )
        return tagged

    def tag_batch(
        self,
        items: list[dict[str, Any]],
    ) -> list[TaggedInput]:
        """Tag multiple inputs. Each dict must contain 'content' and 'channel'."""
        return [
            self.tag(
                content=item["content"],
                channel=item["channel"],
                source_description=item.get("source_description", ""),
                metadata=item.get("metadata"),
                trust_override=item.get("trust_override"),
            )
            for item in items
        ]
