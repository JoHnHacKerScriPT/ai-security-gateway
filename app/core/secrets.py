"""Secrets management & isolation.

Upstream provider credentials (Anthropic/OpenAI API keys) are read here and
*only* here — they are attached to the outbound request to the provider and
are never echoed back to the gateway's own clients, logged, or exposed
through any response.

This module is intentionally a thin seam: today it reads from environment
variables (via Settings, itself loaded from `.env`), but every call site
goes through `get_anthropic_api_key()` / `get_openai_api_key()` rather than
reading `settings.anthropic_api_key` directly, so swapping in a real vault
(HashiCorp Vault, AWS Secrets Manager, etc.) later only touches this file.
"""
from __future__ import annotations

from app.core.config import get_settings

_PLACEHOLDER_MARKERS = ("your-real-key-here", "your_real_key_here", "change-me")


class SecretNotConfigured(RuntimeError):
    def __init__(self, name: str):
        super().__init__(
            f"{name} is not configured (still a placeholder). "
            f"Set a real value in your .env file — see .env.example."
        )


def _require_real_value(name: str, value: str) -> str:
    if not value or any(marker in value for marker in _PLACEHOLDER_MARKERS):
        raise SecretNotConfigured(name)
    return value


def get_anthropic_api_key() -> str:
    return _require_real_value("ANTHROPIC_API_KEY", get_settings().anthropic_api_key)


def get_openai_api_key() -> str:
    return _require_real_value("OPENAI_API_KEY", get_settings().openai_api_key)
