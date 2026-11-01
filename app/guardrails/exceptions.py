"""Exceptions raised by the input/output guardrail pipeline."""
from __future__ import annotations


class GuardrailViolation(Exception):
    """Base class for any blocking guardrail finding."""

    def __init__(self, code: str, message: str, details: dict | None = None):
        self.code = code
        self.message = message
        self.details = details or {}
        super().__init__(message)


class PromptInjectionDetected(GuardrailViolation):
    def __init__(self, score: float, matched_patterns: list[str]):
        super().__init__(
            code="prompt_injection_detected",
            message="Request blocked: potential prompt injection / jailbreak attempt.",
            details={"score": score, "matched_patterns": matched_patterns},
        )


class InputTooLarge(GuardrailViolation):
    def __init__(self, token_count: int, max_tokens: int):
        super().__init__(
            code="input_too_large",
            message=f"Input has {token_count} tokens, exceeding the limit of {max_tokens}.",
            details={"token_count": token_count, "max_tokens": max_tokens},
        )


class OutputSecretLeak(GuardrailViolation):
    def __init__(self, matched_patterns: list[str]):
        super().__init__(
            code="output_secret_leak",
            message="Response blocked: it appears to contain leaked credentials/secrets.",
            details={"matched_patterns": matched_patterns},
        )


class InsecureCodeDetected(GuardrailViolation):
    def __init__(self, matched_patterns: list[str]):
        super().__init__(
            code="insecure_code_detected",
            message="Response flagged: it contains potentially dangerous code patterns.",
            details={"matched_patterns": matched_patterns},
        )
