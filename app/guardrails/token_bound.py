"""Token-bound validation (Context/Buffer Overflow prevention).

Rather than depend on a specific provider's exact BPE tokenizer (Anthropic
and OpenAI use different ones, and downloading tokenizer files at runtime
would make the gateway depend on network access it may not have), this uses
a fast, dependency-free approximation: split into word/punctuation runs and
apply a conservative multiplier so we tend to OVER-count rather than let an
oversized payload through. This is a pre-flight guard, not a billing meter.
"""
from __future__ import annotations

import re

from app.guardrails.exceptions import InputTooLarge

_TOKEN_RE = re.compile(r"\w+|[^\w\s]", re.UNICODE)

# Real BPE tokenizers typically produce somewhat more tokens than a naive
# word/punctuation split (subword splitting, whitespace-prefix tokens).
# Bias the estimate upward so we err on the side of blocking too early
# rather than too late.
_SAFETY_MULTIPLIER = 1.3


def count_tokens_approx(text: str) -> int:
    raw = len(_TOKEN_RE.findall(text))
    return int(raw * _SAFETY_MULTIPLIER) + 1


def validate_input_size(text: str, max_tokens: int) -> int:
    """Returns the estimated token count, or raises InputTooLarge."""
    count = count_tokens_approx(text)
    if count > max_tokens:
        raise InputTooLarge(token_count=count, max_tokens=max_tokens)
    return count
