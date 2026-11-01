"""PII & Data Loss Prevention (DLP).

Detects and redacts, before a request ever reaches an upstream AI provider:
  * emails
  * phone numbers (Greek mobile/landline + generic international/E.164)
  * ΑΦΜ (Greek tax registration number, 9 digits, checksum-validated)
  * credit card numbers (13-19 digits, Luhn-validated)

Matches are replaced with a stable placeholder (e.g. "[EMAIL_REDACTED_1]")
so the redacted text is still coherent for the model, and the mapping is
returned to the caller for audit logging (never sent upstream).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

# Greek mobile (69XXXXXXXX), Greek landline (2XXXXXXXXX), or a generic
# international number with an optional country code and 7-15 digits.
_PHONE_RE = re.compile(
    r"(?<!\d)(?:\+?30\s?)?(?:69\d{8}|2\d{9})(?!\d)"
    r"|(?<!\d)\+\d{1,3}[ .-]?\(?\d{2,4}\)?(?:[ .-]?\d{2,4}){2,4}(?!\d)"
)

_CREDIT_CARD_RE = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")

_AFM_RE = re.compile(r"(?<!\d)\d{9}(?!\d)")


def _luhn_valid(digits: str) -> bool:
    total = 0
    reversed_digits = digits[::-1]
    for i, ch in enumerate(reversed_digits):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _afm_valid(digits: str) -> bool:
    """Greek ΑΦΜ checksum: weighted sum of the first 8 digits mod 11 mod 10
    must equal the 9th digit. Filters out plain 9-digit numbers (phone
    fragments, IDs) that aren't really a ΑΦΜ."""
    if len(digits) != 9 or digits == "0" * 9:
        return False
    total = sum(int(d) * (2 ** (8 - i)) for i, d in enumerate(digits[:8]))
    return (total % 11) % 10 == int(digits[8])


@dataclass
class PIIMatch:
    kind: str
    original: str
    placeholder: str


@dataclass
class RedactionResult:
    redacted_text: str
    matches: list[PIIMatch] = field(default_factory=list)

    @property
    def has_pii(self) -> bool:
        return bool(self.matches)


def redact(text: str) -> RedactionResult:
    matches: list[PIIMatch] = []
    counters: dict[str, int] = {}

    def _next_placeholder(kind: str) -> str:
        counters[kind] = counters.get(kind, 0) + 1
        return f"[{kind}_REDACTED_{counters[kind]}]"

    def _sub_email(m: re.Match) -> str:
        placeholder = _next_placeholder("EMAIL")
        matches.append(PIIMatch("EMAIL", m.group(0), placeholder))
        return placeholder

    def _sub_credit_card(m: re.Match) -> str:
        digits = re.sub(r"[ -]", "", m.group(0))
        if not (13 <= len(digits) <= 19) or not _luhn_valid(digits):
            return m.group(0)
        placeholder = _next_placeholder("CREDIT_CARD")
        matches.append(PIIMatch("CREDIT_CARD", m.group(0), placeholder))
        return placeholder

    def _sub_afm(m: re.Match) -> str:
        if not _afm_valid(m.group(0)):
            return m.group(0)
        placeholder = _next_placeholder("AFM")
        matches.append(PIIMatch("AFM", m.group(0), placeholder))
        return placeholder

    def _sub_phone(m: re.Match) -> str:
        placeholder = _next_placeholder("PHONE")
        matches.append(PIIMatch("PHONE", m.group(0), placeholder))
        return placeholder

    # Order matters: credit cards (longer digit runs) before ΑΦΜ (9-digit)
    # before phone before email, so a long card number isn't first chewed up
    # by the 9-digit ΑΦΜ pattern.
    text = _EMAIL_RE.sub(_sub_email, text)
    text = _CREDIT_CARD_RE.sub(_sub_credit_card, text)
    text = _PHONE_RE.sub(_sub_phone, text)
    text = _AFM_RE.sub(_sub_afm, text)

    return RedactionResult(redacted_text=text, matches=matches)
