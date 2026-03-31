"""Tests for ContextTagger."""

import pytest

from intake_shield.tagger import ContextTagger, DEFAULT_TRUST_MAP
from intake_shield.types import Channel, TaggedInput, TrustLevel


class TestContextTagger:
    def test_default_trust_map_assigns_correct_trust(self):
        tagger = ContextTagger()
        for channel, expected_trust in DEFAULT_TRUST_MAP.items():
            tagged = tagger.tag("test", channel)
            assert tagged.trust == expected_trust, (
                f"Channel {channel.value} should have trust {expected_trust.name}"
            )

    def test_tag_returns_tagged_input(self):
        tagger = ContextTagger()
        tagged = tagger.tag(
            "hello",
            Channel.EXTERNAL_EMAIL,
            source_description="email from alice@corp.com",
        )
        assert isinstance(tagged, TaggedInput)
        assert tagged.content == "hello"
        assert tagged.channel == Channel.EXTERNAL_EMAIL
        assert tagged.trust == TrustLevel.UNTRUSTED
        assert tagged.source_description == "email from alice@corp.com"
        assert len(tagged.id) == 12

    def test_tagged_input_is_immutable(self):
        tagger = ContextTagger()
        tagged = tagger.tag("test", Channel.OWNER_CLI)
        with pytest.raises(Exception):
            tagged.trust = TrustLevel.HOSTILE  # type: ignore[misc]

    def test_trust_override_takes_precedence(self):
        tagger = ContextTagger()
        tagged = tagger.tag(
            "malicious",
            Channel.EXTERNAL_EMAIL,
            trust_override=TrustLevel.HOSTILE,
        )
        assert tagged.trust == TrustLevel.HOSTILE

    def test_custom_trust_classifier(self):
        def my_classifier(channel: Channel, meta: dict) -> TrustLevel:
            if meta.get("verified"):
                return TrustLevel.TRUSTED
            return TrustLevel.UNTRUSTED

        tagger = ContextTagger(trust_classifier=my_classifier)

        tagged_verified = tagger.tag(
            "content", Channel.EXTERNAL_EMAIL, metadata={"verified": True}
        )
        assert tagged_verified.trust == TrustLevel.TRUSTED

        tagged_unverified = tagger.tag("content", Channel.EXTERNAL_EMAIL)
        assert tagged_unverified.trust == TrustLevel.UNTRUSTED

    def test_custom_trust_map(self):
        custom_map = {Channel.EXTERNAL_EMAIL: TrustLevel.HOSTILE}
        tagger = ContextTagger(default_trust_map=custom_map)
        tagged = tagger.tag("test", Channel.EXTERNAL_EMAIL)
        assert tagged.trust == TrustLevel.HOSTILE

    def test_unknown_channel_defaults_to_untrusted(self):
        tagger = ContextTagger(default_trust_map={})
        tagged = tagger.tag("test", Channel.EXTERNAL_EMAIL)
        assert tagged.trust == TrustLevel.UNTRUSTED

    def test_tag_batch(self):
        tagger = ContextTagger()
        items = [
            {"content": "a", "channel": Channel.OWNER_CLI},
            {"content": "b", "channel": Channel.EXTERNAL_EMAIL},
            {
                "content": "c",
                "channel": Channel.EXTERNAL_DISCORD,
                "trust_override": TrustLevel.HOSTILE,
            },
        ]
        results = tagger.tag_batch(items)
        assert len(results) == 3
        assert results[0].trust == TrustLevel.OWNER
        assert results[1].trust == TrustLevel.UNTRUSTED
        assert results[2].trust == TrustLevel.HOSTILE

    def test_metadata_preserved(self):
        tagger = ContextTagger()
        tagged = tagger.tag(
            "test",
            Channel.EXTERNAL_EMAIL,
            metadata={"sender": "alice@corp.com", "priority": "high"},
        )
        assert tagged.metadata["sender"] == "alice@corp.com"
        assert tagged.metadata["priority"] == "high"

    def test_unique_ids(self):
        tagger = ContextTagger()
        ids = {tagger.tag("test", Channel.OWNER_CLI).id for _ in range(100)}
        assert len(ids) == 100
