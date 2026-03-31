"""Tests for ContextWindowBuilder."""

import pytest

from context_shield.context import ContextWindowBuilder, TRUST_PROTOCOL_PREAMBLE
from context_shield.tagger import ContextTagger
from context_shield.types import Channel, TrustLevel


@pytest.fixture
def tagger() -> ContextTagger:
    return ContextTagger()


@pytest.fixture
def builder() -> ContextWindowBuilder:
    return ContextWindowBuilder(system_preamble="You are a helpful assistant.")


class TestContextWindowBuilder:
    def test_system_preamble_is_first_message(self, builder: ContextWindowBuilder):
        messages = builder.build()
        assert len(messages) == 1
        assert messages[0]["role"] == "system"
        assert TRUST_PROTOCOL_PREAMBLE in messages[0]["content"]
        assert "helpful assistant" in messages[0]["content"]

    def test_trust_delimiters_wrap_content(
        self, builder: ContextWindowBuilder, tagger: ContextTagger
    ):
        tagged = tagger.tag(
            "Hello world",
            Channel.EXTERNAL_EMAIL,
            source_description="email from alice@corp.com",
        )
        builder.add_input(tagged)
        messages = builder.build()
        assert len(messages) == 2

        user_msg = messages[1]
        assert user_msg["role"] == "user"
        assert '<context-shield channel="external_email"' in user_msg["content"]
        assert 'trust="untrusted"' in user_msg["content"]
        assert f'id="{tagged.id}"' in user_msg["content"]
        assert 'source="email from alice@corp.com"' in user_msg["content"]
        assert "Hello world" in user_msg["content"]
        assert "</context-shield>" in user_msg["content"]

    def test_multiple_inputs_ordered(
        self, builder: ContextWindowBuilder, tagger: ContextTagger
    ):
        a = tagger.tag("first", Channel.OWNER_CLI)
        b = tagger.tag("second", Channel.EXTERNAL_EMAIL)
        builder.add_input(a)
        builder.add_input(b)
        messages = builder.build()
        assert len(messages) == 3  # system + 2 user
        assert "first" in messages[1]["content"]
        assert "second" in messages[2]["content"]

    def test_assistant_message_added(self, builder: ContextWindowBuilder):
        builder.add_assistant_message("I can help with that.")
        messages = builder.build()
        assert len(messages) == 2
        assert messages[1]["role"] == "assistant"
        assert messages[1]["content"] == "I can help with that."

    def test_max_untrusted_tokens_truncates(self, tagger: ContextTagger):
        builder = ContextWindowBuilder(max_untrusted_tokens=10)  # ~40 chars
        long_content = "A" * 200
        tagged = tagger.tag(long_content, Channel.EXTERNAL_EMAIL)
        builder.add_input(tagged)
        messages = builder.build()
        content = messages[1]["content"]
        assert "[TRUNCATED" in content
        assert len(content) < len(long_content) + 200  # delimiters + truncation msg

    def test_max_untrusted_tokens_does_not_truncate_trusted(
        self, tagger: ContextTagger
    ):
        builder = ContextWindowBuilder(max_untrusted_tokens=10)
        long_content = "A" * 200
        tagged = tagger.tag(long_content, Channel.OWNER_CLI)
        builder.add_input(tagged)
        messages = builder.build()
        assert "[TRUNCATED" not in messages[1]["content"]
        assert "A" * 200 in messages[1]["content"]

    def test_source_with_quotes_escaped(
        self, builder: ContextWindowBuilder, tagger: ContextTagger
    ):
        tagged = tagger.tag(
            "test", Channel.EXTERNAL_EMAIL, source_description='Bob "The Builder"'
        )
        builder.add_input(tagged)
        messages = builder.build()
        assert "&quot;" in messages[1]["content"]

    def test_clear(self, builder: ContextWindowBuilder, tagger: ContextTagger):
        tagged = tagger.tag("test", Channel.OWNER_CLI)
        builder.add_input(tagged)
        assert len(builder.get_messages()) == 1
        builder.clear()
        assert len(builder.get_messages()) == 0

    def test_empty_preamble(self, tagger: ContextTagger):
        builder = ContextWindowBuilder()
        messages = builder.build()
        assert messages[0]["content"] == TRUST_PROTOCOL_PREAMBLE

    def test_owner_input_tagged_as_owner(
        self, builder: ContextWindowBuilder, tagger: ContextTagger
    ):
        tagged = tagger.tag("admin command", Channel.OWNER_CLI)
        builder.add_input(tagged)
        messages = builder.build()
        assert 'trust="owner"' in messages[1]["content"]
