"""Tests for ProvenanceTracker."""

import pytest

from intake_shield.provenance import ProvenanceTracker
from intake_shield.tagger import ContextTagger
from intake_shield.types import Channel, TrustLevel
from intake_shield.exceptions import ProvenanceError


@pytest.fixture
def tagger() -> ContextTagger:
    return ContextTagger()


@pytest.fixture
def tracker() -> ProvenanceTracker:
    return ProvenanceTracker()


class TestProvenanceTracker:
    def test_register_and_get(self, tracker: ProvenanceTracker, tagger: ContextTagger):
        tagged = tagger.tag("hello", Channel.OWNER_CLI)
        tracker.register(tagged)
        assert tracker.get(tagged.id) is tagged

    def test_get_returns_none_for_unknown(self, tracker: ProvenanceTracker):
        assert tracker.get("nonexistent") is None

    def test_remove(self, tracker: ProvenanceTracker, tagger: ContextTagger):
        tagged = tagger.tag("hello", Channel.OWNER_CLI)
        tracker.register(tagged)
        tracker.remove(tagged.id)
        assert tracker.get(tagged.id) is None

    def test_remove_nonexistent_is_noop(self, tracker: ProvenanceTracker):
        tracker.remove("nonexistent")  # should not raise

    def test_resolve_effective_trust_single(
        self, tracker: ProvenanceTracker, tagger: ContextTagger
    ):
        tagged = tagger.tag("hello", Channel.EXTERNAL_EMAIL)
        tracker.register(tagged)
        trust, channel = tracker.resolve_effective_trust([tagged.id])
        assert trust == TrustLevel.UNTRUSTED
        assert channel == Channel.EXTERNAL_EMAIL

    def test_resolve_effective_trust_min(
        self, tracker: ProvenanceTracker, tagger: ContextTagger
    ):
        owner = tagger.tag("cmd", Channel.OWNER_CLI)
        email = tagger.tag("email", Channel.EXTERNAL_EMAIL)
        hostile = tagger.tag(
            "attack", Channel.EXTERNAL_DISCORD, trust_override=TrustLevel.HOSTILE
        )
        for t in [owner, email, hostile]:
            tracker.register(t)

        trust, channel = tracker.resolve_effective_trust(
            [owner.id, email.id, hostile.id]
        )
        assert trust == TrustLevel.HOSTILE
        assert channel == Channel.EXTERNAL_DISCORD

    def test_resolve_all_context_when_no_ids(
        self, tracker: ProvenanceTracker, tagger: ContextTagger
    ):
        owner = tagger.tag("cmd", Channel.OWNER_CLI)
        email = tagger.tag("email", Channel.EXTERNAL_EMAIL)
        tracker.register(owner)
        tracker.register(email)

        trust, channel = tracker.resolve_effective_trust()
        assert trust == TrustLevel.UNTRUSTED
        assert channel == Channel.EXTERNAL_EMAIL

    def test_resolve_empty_tracker_raises(self, tracker: ProvenanceTracker):
        with pytest.raises(ProvenanceError):
            tracker.resolve_effective_trust()

    def test_resolve_unknown_id_raises(
        self, tracker: ProvenanceTracker, tagger: ContextTagger
    ):
        tagged = tagger.tag("hello", Channel.OWNER_CLI)
        tracker.register(tagged)
        with pytest.raises(ProvenanceError):
            tracker.resolve_effective_trust(["nonexistent"])

    def test_all_inputs(self, tracker: ProvenanceTracker, tagger: ContextTagger):
        a = tagger.tag("a", Channel.OWNER_CLI)
        b = tagger.tag("b", Channel.EXTERNAL_EMAIL)
        tracker.register(a)
        tracker.register(b)
        assert len(tracker.all_inputs()) == 2

    def test_clear(self, tracker: ProvenanceTracker, tagger: ContextTagger):
        tagged = tagger.tag("hello", Channel.OWNER_CLI)
        tracker.register(tagged)
        tracker.clear()
        assert len(tracker.all_inputs()) == 0
