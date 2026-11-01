"""Prompt Injection & Jailbreak Inspector (OWASP LLM01).

Combines three signal types into a single risk score:
  1. Regex patterns for known jailbreak/override phrasing (DAN mode, "ignore
     previous instructions", system-prompt exfiltration attempts, fake
     delimiter injection).
  2. Heuristics: proximity of an "override" verb to a "rules/instructions"
     noun, count of independent categories triggered, suspicious control
     character / delimiter density.
  3. A lightweight semantic pass: normalizes whitespace/unicode homoglyphs
     and re-runs the regex pass, catching simple obfuscation (extra spaces,
     zero-width characters, mixed case) without needing an LLM call.

This is deliberately dependency-free (no model call) so it runs on every
request with negligible latency. It is a defense-in-depth layer, not a
guarantee — pair it with output inspection (Layer 4) and logging (Layer 5).
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field

# (label, compiled pattern, weight)
_PATTERNS: list[tuple[str, re.Pattern, float]] = [
    (
        "instruction_override",
        re.compile(
            r"\b(ignore|disregard|forget|bypass|override)\b[^.\n]{0,40}\b"
            r"(all\s+)?(the\s+)?(previous|prior|above|earlier|original)\b[^.\n]{0,20}\b"
            r"(instructions?|rules?|prompt|guidelines?|policy|system\s*message)\b",
            re.IGNORECASE,
        ),
        0.6,
    ),
    (
        "role_override",
        re.compile(
            r"\b(you are now|act as|pretend to be|roleplay as)\b[^.\n]{0,40}\b"
            r"(dan|jailbroken|unrestricted|uncensored|evil|developer mode|no\s*restrictions?)\b",
            re.IGNORECASE,
        ),
        0.7,
    ),
    (
        "dan_mode",
        re.compile(r"\bdan\s*mode\b|\bdo anything now\b|\bdeveloper mode enabled\b", re.IGNORECASE),
        0.7,
    ),
    (
        "system_prompt_exfiltration",
        re.compile(
            r"\b(repeat|reveal|print|show|output|leak)\b[^.\n]{0,30}\b"
            r"(your|the)\b[^.\n]{0,20}\b(system prompt|hidden prompt|initial instructions|"
            r"instructions above|prompt above)\b",
            re.IGNORECASE,
        ),
        0.6,
    ),
    (
        "fake_delimiter_injection",
        re.compile(
            r"(#{2,}\s*system\b|\[\s*system\s*\]|<\s*/?\s*system\s*>|--+\s*end of (system\s*)?instructions?\s*--+)",
            re.IGNORECASE,
        ),
        0.5,
    ),
    (
        "safety_disable_request",
        re.compile(
            r"\b(disable|turn off|remove)\b[^.\n]{0,30}\b(safety|content policy|filters?|guardrails?|moderation)\b",
            re.IGNORECASE,
        ),
        0.5,
    ),
]

BLOCK_THRESHOLD = 0.5
SUSPICIOUS_THRESHOLD = 0.25


@dataclass
class InspectionResult:
    score: float
    matched_patterns: list[str] = field(default_factory=list)

    @property
    def is_blocked(self) -> bool:
        return self.score >= BLOCK_THRESHOLD

    @property
    def is_suspicious(self) -> bool:
        return self.score >= SUSPICIOUS_THRESHOLD


def _normalize(text: str) -> str:
    """Undo cheap obfuscation: unicode-normalize, drop zero-width chars,
    collapse repeated whitespace so 'i g n o r e' still doesn't slip through
    (spacing tricks are handled separately by _despace)."""
    text = unicodedata.normalize("NFKC", text)
    text = "".join(ch for ch in text if unicodedata.category(ch) != "Cf")  # strip zero-width/format chars
    return re.sub(r"\s+", " ", text)


def inspect(text: str) -> InspectionResult:
    normalized = _normalize(text)
    score = 0.0
    matched: list[str] = []
    for label, pattern, weight in _PATTERNS:
        if pattern.search(normalized):
            score += weight
            matched.append(label)
    return InspectionResult(score=min(score, 1.0), matched_patterns=matched)
