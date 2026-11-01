"""Input guardrail pipeline (Layer 2).

`run_input_guardrails` is the single entrypoint the routing layer calls
before forwarding anything upstream: it validates size, redacts PII, and
screens for prompt injection, raising a `GuardrailViolation` subclass on any
blocking finding.
"""
from __future__ import annotations

from dataclasses import dataclass

from app.core.config import get_settings
from app.guardrails import pii_dlp, prompt_injection, token_bound
from app.guardrails.exceptions import (
    GuardrailViolation,
    InputTooLarge,
    InsecureCodeDetected,
    OutputSecretLeak,
    PromptInjectionDetected,
)

__all__ = [
    "GuardrailViolation",
    "InputTooLarge",
    "InsecureCodeDetected",
    "OutputSecretLeak",
    "PromptInjectionDetected",
    "run_input_guardrails",
    "InputGuardrailReport",
]


@dataclass
class InputGuardrailReport:
    sanitized_text: str
    token_count: int
    pii_redacted: bool
    pii_kinds: list[str]
    injection_score: float


def run_input_guardrails(text: str) -> InputGuardrailReport:
    settings = get_settings()

    # 1. Size check first — cheapest, and no point redacting/scanning a
    #    payload we're going to reject anyway.
    token_count = token_bound.validate_input_size(text, settings.max_input_tokens)

    # 2. Prompt injection / jailbreak screening runs on the *original* text
    #    (redaction placeholders could otherwise mask or mimic patterns).
    injection = prompt_injection.inspect(text)
    if injection.is_blocked:
        raise PromptInjectionDetected(score=injection.score, matched_patterns=injection.matched_patterns)

    # 3. PII/DLP redaction — the sanitized text is what actually gets
    #    forwarded upstream.
    redaction = pii_dlp.redact(text)

    return InputGuardrailReport(
        sanitized_text=redaction.redacted_text,
        token_count=token_count,
        pii_redacted=redaction.has_pii,
        pii_kinds=sorted({m.kind for m in redaction.matches}),
        injection_score=injection.score,
    )
