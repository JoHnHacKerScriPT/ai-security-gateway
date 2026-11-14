"""Centralized configuration for the AI Security Gateway.

All runtime configuration is loaded from environment variables (see
.env.example). Never hardcode secrets here — this module only defines
*how* config is loaded, not the values themselves.
"""
from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Values that appear in docs/.env.example. A secret equal to one of these is
# public knowledge, so anyone could forge tokens with it.
_PLACEHOLDER_SECRETS = frozenset({"change-me-to-a-long-random-value", "insecure-dev-secret-change-me"})

# RFC 7518 §3.2: an HMAC key must be at least as long as the hash output.
_MIN_SECRET_BYTES = {"HS256": 32, "HS384": 48, "HS512": 64}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # ---- App ----
    app_env: str = "development"
    log_level: str = "INFO"

    # ---- Auth ----
    # No default on purpose: if JWT_SECRET is missing the app refuses to start
    # instead of silently signing tokens with a well-known fallback value.
    jwt_secret: str
    jwt_algorithm: Literal["HS256", "HS384", "HS512"] = "HS256"
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

    @model_validator(mode="after")
    def _validate_jwt_secret(self) -> Settings:
        if self.jwt_secret in _PLACEHOLDER_SECRETS:
            raise ValueError("JWT_SECRET is still a placeholder value; generate a real random secret.")
        min_bytes = _MIN_SECRET_BYTES[self.jwt_algorithm]
        if len(self.jwt_secret.encode("utf-8")) < min_bytes:
            raise ValueError(f"JWT_SECRET must be at least {min_bytes} bytes for {self.jwt_algorithm}.")
        return self

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
