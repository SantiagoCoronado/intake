"""Minimal agent loop using the Anthropic SDK with tool use."""

from __future__ import annotations

import logging
from typing import Any

import anthropic

from demo.tools import TOOL_SCHEMAS, TOOLS

logger = logging.getLogger(__name__)


def run_agent_loop(
    messages: list[dict],
    system_prompt: str,
    tool_executor: dict[str, Any] | None = None,
    max_turns: int = 10,
    model: str = "claude-sonnet-4-20250514",
) -> list[dict]:
    """Run an agent loop with tool use.

    Args:
        messages: Initial messages to send.
        system_prompt: System prompt for the agent.
        tool_executor: Dict of {tool_name: callable}. If None, uses TOOLS directly.
        max_turns: Max number of agent turns.
        model: Model to use.

    Returns:
        Full message history.
    """
    client = anthropic.Anthropic()
    tools = tool_executor or TOOLS
    history = list(messages)

    for turn in range(max_turns):
        logger.info("--- Agent Turn %d ---", turn + 1)

        response = client.messages.create(
            model=model,
            max_tokens=1024,
            system=system_prompt,
            messages=history,
            tools=TOOL_SCHEMAS,
        )

        # Collect assistant response
        assistant_content = []
        tool_uses = []

        for block in response.content:
            if block.type == "text":
                assistant_content.append({"type": "text", "text": block.text})
                logger.info("Assistant: %s", block.text)
            elif block.type == "tool_use":
                assistant_content.append({
                    "type": "tool_use",
                    "id": block.id,
                    "name": block.name,
                    "input": block.input,
                })
                tool_uses.append(block)
                logger.info("Tool call: %s(%s)", block.name, block.input)

        history.append({"role": "assistant", "content": assistant_content})

        # If no tool calls, agent is done
        if not tool_uses:
            break

        # Execute tool calls and add results
        tool_results = []
        for tool_use in tool_uses:
            tool_fn = tools.get(tool_use.name)
            if tool_fn is None:
                result = f"Error: Unknown tool '{tool_use.name}'"
            else:
                try:
                    result = tool_fn(**tool_use.input)
                except Exception as e:
                    result = f"Error: {e}"
                    logger.error("Tool %s failed: %s", tool_use.name, e)

            tool_results.append({
                "type": "tool_result",
                "tool_use_id": tool_use.id,
                "content": str(result),
            })
            logger.info("Tool result for %s: %s", tool_use.name, result[:200])

        history.append({"role": "user", "content": tool_results})

        if response.stop_reason == "end_turn":
            break

    return history
