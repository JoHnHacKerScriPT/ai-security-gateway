from __future__ import annotations

import pytest

from app.guardrails.exceptions import InputTooLarge
from app.guardrails.token_bound import count_tokens_approx, validate_input_size


def test_short_text_counts_a_handful_of_tokens():
    count = count_tokens_approx("Hello, world!")
    assert 1 <= count <= 10


def test_validate_input_size_passes_under_limit():
    count = validate_input_size("short text", max_tokens=1000)
    assert count > 0


def test_validate_input_size_blocks_over_limit():
    huge_text = "word " * 5000
    with pytest.raises(InputTooLarge):
        validate_input_size(huge_text, max_tokens=100)
