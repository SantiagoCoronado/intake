"""Demo tool definitions for the email assistant agent."""

from __future__ import annotations

import logging

from demo.mock_inbox import get_email, get_all_emails

logger = logging.getLogger(__name__)

# Simulated sent emails and executed commands (for demo output)
sent_emails: list[dict] = []
executed_commands: list[str] = []


def read_email(email_id: str) -> str:
    """Read an email from the inbox by ID."""
    email = get_email(email_id)
    if email is None:
        return f"Email {email_id} not found."
    return (
        f"From: {email['from']}\n"
        f"Subject: {email['subject']}\n"
        f"Body: {email['body']}"
    )


def list_emails() -> str:
    """List all emails in the inbox."""
    emails = get_all_emails()
    lines = []
    for email in emails:
        lines.append(f"  [{email['id']}] From: {email['from']} — {email['subject']}")
    return "Inbox:\n" + "\n".join(lines)


def shell_exec(command: str) -> str:
    """Execute a shell command (simulated in demo)."""
    logger.warning("SHELL EXEC: %s", command)
    executed_commands.append(command)
    return f"[SIMULATED] Executed: {command}"


def send_email(to: str, subject: str, body: str) -> str:
    """Send an email (simulated in demo)."""
    logger.warning("SEND EMAIL: to=%s subject=%s", to, subject)
    sent_emails.append({"to": to, "subject": subject, "body": body})
    return f"[SIMULATED] Email sent to {to}: {subject}"


def summarize(text: str) -> str:
    """Summarize text (stub — in a real agent the LLM would do this)."""
    return f"Summary: {text[:100]}..."


# Tool registry for the agent
TOOLS = {
    "read_email": read_email,
    "list_emails": list_emails,
    "shell_exec": shell_exec,
    "send_email": send_email,
    "summarize": summarize,
}

# Tool schemas for the Anthropic API
TOOL_SCHEMAS = [
    {
        "name": "read_email",
        "description": "Read an email from the inbox by its ID.",
        "input_schema": {
            "type": "object",
            "properties": {
                "email_id": {"type": "string", "description": "The email ID to read"},
            },
            "required": ["email_id"],
        },
    },
    {
        "name": "list_emails",
        "description": "List all emails in the inbox with their IDs and subjects.",
        "input_schema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "shell_exec",
        "description": "Execute a shell command on the system.",
        "input_schema": {
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "The command to execute"},
            },
            "required": ["command"],
        },
    },
    {
        "name": "send_email",
        "description": "Send an email to a recipient.",
        "input_schema": {
            "type": "object",
            "properties": {
                "to": {"type": "string", "description": "Recipient email address"},
                "subject": {"type": "string", "description": "Email subject"},
                "body": {"type": "string", "description": "Email body"},
            },
            "required": ["to", "subject", "body"],
        },
    },
    {
        "name": "summarize",
        "description": "Summarize a piece of text.",
        "input_schema": {
            "type": "object",
            "properties": {
                "text": {"type": "string", "description": "Text to summarize"},
            },
            "required": ["text"],
        },
    },
]
