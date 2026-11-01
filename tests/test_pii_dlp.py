from __future__ import annotations

from app.guardrails import pii_dlp


def test_email_is_redacted():
    result = pii_dlp.redact("Contact me at john.doe@example.com for details.")
    assert result.has_pii
    assert "john.doe@example.com" not in result.redacted_text
    assert "[EMAIL_REDACTED_1]" in result.redacted_text
    assert result.matches[0].kind == "EMAIL"


def test_greek_mobile_phone_is_redacted():
    result = pii_dlp.redact("Call me on 6912345678 tomorrow.")
    assert result.has_pii
    assert "6912345678" not in result.redacted_text
    assert any(m.kind == "PHONE" for m in result.matches)


def test_valid_afm_is_redacted():
    # 099999999 is a well-known "test" ΑΦΜ that satisfies the checksum.
    afm = "099999999"
    result = pii_dlp.redact(f"My tax number is {afm}.")
    assert any(m.kind == "AFM" for m in result.matches)
    assert afm not in result.redacted_text


def test_random_9_digit_number_without_valid_checksum_is_not_flagged_as_afm():
    result = pii_dlp.redact("The order number is 123456789.")
    assert not any(m.kind == "AFM" for m in result.matches)


def test_valid_credit_card_is_redacted():
    # 4111 1111 1111 1111 is the standard Luhn-valid Visa test number.
    result = pii_dlp.redact("My card number is 4111 1111 1111 1111, please charge it.")
    assert any(m.kind == "CREDIT_CARD" for m in result.matches)
    assert "4111 1111 1111 1111" not in result.redacted_text


def test_invalid_card_like_number_is_left_alone():
    result = pii_dlp.redact("Reference code: 1234 5678 9012 3456")
    assert not any(m.kind == "CREDIT_CARD" for m in result.matches)


def test_clean_text_has_no_pii():
    result = pii_dlp.redact("Let's meet for coffee sometime next week.")
    assert not result.has_pii
    assert result.redacted_text == "Let's meet for coffee sometime next week."
