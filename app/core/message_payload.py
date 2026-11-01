"""Helpers for applying input guardrails to Anthropic/OpenAI-shaped chat
payloads without needing to know every provider's full schema.

Both providers share the same core shape for what we care about:
`body["messages"]` is a list of `{"role": ..., "content": ...}`, where
`content` is either a plain string or a list of content blocks (Anthropic's
`{"type": "text", "text": "..."}`, OpenAI's multimodal parts). We only run
guardrails against `role == "user"` messages — that's the only content a
caller controls; assistant/system turns are the gateway/model's own.
"""
from __future__ import annotations

from app.guardrails import InputGuardrailReport, run_input_guardrails


def _extract_text(content) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for block in content:
            if isinstance(block, dict) and isinstance(block.get("text"), str):
                parts.append(block["text"])
        return "\n".join(parts)
    return ""


def sanitize_user_messages(body: dict) -> tuple[dict, list[InputGuardrailReport]]:
    """Runs guardrails on every user-role message in `body["messages"]`,
    replacing each message's content with its sanitized (PII-redacted) text.
    Raises the first `GuardrailViolation` encountered (from
    `run_input_guardrails`) — the caller is expected to let that propagate
    into a 400 response.

    Returns the (mutated-copy) body plus one report per user message, so the
    caller can log/audit what was found.
    """
    messages = body.get("messages")
    if not isinstance(messages, list):
        return body, []

    reports: list[InputGuardrailReport] = []
    new_messages = []
    for message in messages:
        if not isinstance(message, dict) or message.get("role") != "user":
            new_messages.append(message)
            continue

        text = _extract_text(message.get("content"))
        report = run_input_guardrails(text)
        reports.append(report)

        new_message = dict(message)
        new_message["content"] = report.sanitized_text
        new_messages.append(new_message)

    new_body = dict(body)
    new_body["messages"] = new_messages
    return new_body, reports
