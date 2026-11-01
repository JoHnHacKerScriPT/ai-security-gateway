"""Centralized configuration for the AI Security Gateway.

All runtime configuration is loaded from environment variables (see
.env.example). Never hardcode secrets here — this module only defines
*how* config is loaded, not the values themselves.
"""
from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # ---- App ----
    app_env: str = "development"
    log_level: str = "INFO"

    # ---- Auth ----
    jwt_secret: str = "insecure-dev-secret-change-me"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60
    gateway_api_keys: str = ""  # "key_id:key_secret,key_id2:key_secret2"

    # ---- Redis / rate limiting ----
    redis_url: str = "redis://localhost:6379/0"
    # Dev-only escape hatch: use fakeredis's in-process FakeAsyncRedis instead of a
    # real Redis connection. Never set this in production - see redis_client.py.
    use_fake_redis: bool = False
    rate_limit_requests: int = 60
    rate_limit_window_seconds: int = 60
    rate_limit_bucket_capacity: int = 60
    rate_limit_refill_per_second: float = 1.0

    # ---- Upstream providers ----
    anthropic_api_key: str = ""
    anthropic_base_url: str = "https://api.anthropic.com"
    openai_api_key: str = ""
    openai_base_url: str = "https://api.openai.com"
    upstream_timeout_seconds: float = 30.0
    upstream_max_retries: int = 2

    # ---- Guardrails ----
    max_input_tokens: int = 8000
    block_insecure_code_output: bool = True

    @property
    def api_keys_map(self) -> dict[str, str]:
        """Parse GATEWAY_API_KEYS ('id:secret,id2:secret2') into a dict."""
        result: dict[str, str] = {}
        for pair in self.gateway_api_keys.split(","):
            pair = pair.strip()
            if not pair or ":" not in pair:
                continue
            key_id, _, key_secret = pair.partition(":")
            result[key_id] = key_secret
        return result


@lru_cache
def get_settings() -> Settings:
    return Settings()
