"""Tests for ActionGuard."""

import pytest

from context_shield.audit import AuditLog
from context_shield.guard import ActionGuard
from context_shield.policy import PolicyEngine
from context_shield.provenance import ProvenanceTracker
from context_shield.tagger import ContextTagger
from context_shield.types import (
    Channel,
    PolicyConfig,
    PolicyRule,
    ToolCall,
    TrustLevel,
)
from context_shield.exceptions import ActionBlockedError


@pytest.fixture
def policy() -> PolicyEngine:
    return PolicyEngine(
        PolicyConfig(
            default_deny=True,
            rules=[
                PolicyRule(
                    channel=Channel.OWNER_CLI,
                    trust=TrustLevel.OWNER,
                    allow=["*"],
                    priority=0,
                ),
                PolicyRule(
                    channel=Channel.EXTERNAL_EMAIL,
                    trust=TrustLevel.UNTRUSTED,
                    allow=["read_email", "summarize"],
                    deny=["shell_exec", "send_email"],
                    priority=10,
                ),
            ],
        )
    )


@pytest.fixture
def tagger() -> ContextTagger:
    return ContextTagger()


@pytest.fixture
def provenance() -> ProvenanceTracker:
    return ProvenanceTracker()


@pytest.fixture
def guard(policy: PolicyEngine, provenance: ProvenanceTracker) -> ActionGuard:
    return ActionGuard(policy=policy, provenance=provenance)


class TestActionGuard:
    def test_allowed_tool_call(
        self,
        guard: ActionGuard,
        provenance: ProvenanceTracker,
        tagger: ContextTagger,
    ):
        owner_input = tagger.tag("do stuff", Channel.OWNER_CLI)
        provenance.register(owner_input)

        tc = ToolCall(
            tool_name="shell_exec",
            originating_inputs=[owner_input.id],
        )
        decision = guard.check(tc)
        assert decision.allowed is True
        assert decision.effective_trust == TrustLevel.OWNER

    def test_blocked_tool_call(
        self,
        guard: ActionGuard,
        provenance: ProvenanceTracker,
        tagger: ContextTagger,
    ):
        email_input = tagger.tag("malicious", Channel.EXTERNAL_EMAIL)
        provenance.register(email_input)

        tc = ToolCall(
            tool_name="shell_exec",
            originating_inputs=[email_input.id],
        )
        decision = guard.check(tc)
        assert decision.allowed is False
        assert decision.effective_trust == TrustLevel.UNTRUSTED

    def test_conservative_fallback_no_originating_ids(
        self,
        guard: ActionGuard,
        provenance: ProvenanceTracker,
        tagger: ContextTagger,
    ):
        owner_input = tagger.tag("owner cmd", Channel.OWNER_CLI)
        email_input = tagger.tag("email content", Channel.EXTERNAL_EMAIL)
        provenance.register(owner_input)
        provenance.register(email_input)

        tc = ToolCall(tool_name="shell_exec")
        decision = guard.check(tc)
        # Should use min trust (UNTRUSTED from email) -> shell_exec denied
        assert decision.allowed is False
        assert decision.effective_trust == TrustLevel.UNTRUSTED

    def test_wrap_tool_allows(
        self,
        guard: ActionGuard,
        provenance: ProvenanceTracker,
        tagger: ContextTagger,
    ):
        owner_input = tagger.tag("cmd", Channel.OWNER_CLI)
        provenance.register(owner_input)

        def mock_shell(command: str) -> str:
            return f"executed: {command}"

        wrapped = guard.wrap_tool("shell_exec", mock_shell)
        result = wrapped(command="ls")
        assert result == "executed: ls"

    def test_wrap_tool_blocks_raises(
        self,
        guard: ActionGuard,
        provenance: ProvenanceTracker,
        tagger: ContextTagger,
    ):
        email_input = tagger.tag("attack", Channel.EXTERNAL_EMAIL)
        provenance.register(email_input)

        def mock_shell(command: str) -> str:
            return f"executed: {command}"

        wrapped = guard.wrap_tool("shell_exec", mock_shell)
        with pytest.raises(ActionBlockedError) as exc_info:
            wrapped(command="rm -rf /")
        assert exc_info.value.decision.allowed is False

    def test_decorator_form(
        self,
        guard: ActionGuard,
        provenance: ProvenanceTracker,
        tagger: ContextTagger,
    ):
        owner_input = tagger.tag("cmd", Channel.OWNER_CLI)
        provenance.register(owner_input)

        @guard.guard_decorator()
        def read_email(email_id: str) -> str:
            return f"content of {email_id}"

        result = read_email(email_id="001")
        assert result == "content of 001"

    def test_audit_log_records_decisions(
        self,
        guard: ActionGuard,
        provenance: ProvenanceTracker,
        tagger: ContextTagger,
    ):
        email_input = tagger.tag("email", Channel.EXTERNAL_EMAIL)
        provenance.register(email_input)

        guard.check(ToolCall(tool_name="read_email"))
        guard.check(ToolCall(tool_name="shell_exec"))

        entries = guard.audit.entries
        assert len(entries) == 2
        assert entries[0].action_taken == "allowed"
        assert entries[1].action_taken == "blocked"

    def test_on_block_hook_called(
        self,
        policy: PolicyEngine,
        provenance: ProvenanceTracker,
        tagger: ContextTagger,
    ):
        hook_calls = []

        def on_block(tc, decision):
            hook_calls.append(("blocked", tc.tool_name))
            return None

        guard = ActionGuard(
            policy=policy, provenance=provenance, on_block=on_block
        )
        email_input = tagger.tag("email", Channel.EXTERNAL_EMAIL)
        provenance.register(email_input)

        guard.check(ToolCall(tool_name="shell_exec"))
        assert len(hook_calls) == 1
        assert hook_calls[0] == ("blocked", "shell_exec")

    def test_on_allow_hook_called(
        self,
        policy: PolicyEngine,
        provenance: ProvenanceTracker,
        tagger: ContextTagger,
    ):
        hook_calls = []

        def on_allow(tc, decision):
            hook_calls.append(("allowed", tc.tool_name))
            return None

        guard = ActionGuard(
            policy=policy, provenance=provenance, on_allow=on_allow
        )
        email_input = tagger.tag("email", Channel.EXTERNAL_EMAIL)
        provenance.register(email_input)

        guard.check(ToolCall(tool_name="read_email"))
        assert len(hook_calls) == 1
        assert hook_calls[0] == ("allowed", "read_email")
