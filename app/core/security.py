"""Authentication & authorization for the AI Security Gateway.

Supports two credential schemes on every request:
  * `Authorization: Bearer <JWT>` — signed with JWT_SECRET (HS256 by default).
  * `X-API-Key: <key_id>:<key_secret>` — validated against GATEWAY_API_KEYS.

Either scheme resolves to a `Principal` used downstream for rate limiting,
logging, and (later) per-tenant routing decisions.
"""
from __future__ import annotations

import hmac
import time
from dataclasses import dataclass

import jwt
from fastapi import HTTPException, Security, status
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer

from app.core.config import get_settings

# A token missing any of these is rejected, so a token minted without an
# expiry can never be valid forever.
_REQUIRED_CLAIMS = ["exp", "iat", "sub"]


@dataclass(frozen=True)
class Principal:
    subject: str
    auth_method: str  # "jwt" | "api_key"


# Declared purely so FastAPI/Swagger UI knows these schemes exist and renders
# the "Authorize" button + per-endpoint padlock. auto_error=False because the
# actual validation logic below still runs by hand (dual-scheme: either one is OK).
_bearer_scheme = HTTPBearer(auto_error=False, description="JWT issued by this gateway")
_api_key_scheme = APIKeyHeader(name="X-API-Key", auto_error=False, description="key_id:key_secret")


def create_access_token(subject: str, expire_minutes: int | None = None) -> str:
    """Issue a signed JWT for `subject`. Used by the gateway's own /auth/token
    endpoint (or by an operator minting tokens out-of-band)."""
    settings = get_settings()
    ttl = expire_minutes if expire_minutes is not None else settings.jwt_expire_minutes
    now = int(time.time())
    payload = {"sub": subject, "iat": now, "exp": now + ttl * 60}
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def _verify_jwt(token: str) -> Principal:
    settings = get_settings()
    try:
        # `algorithms` is a fixed allow-list from config, never taken from the
        # token header: that is what blocks "alg: none" and algorithm confusion.
        payload = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm],
            options={"require": _REQUIRED_CLAIMS},
        )
    except jwt.InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    subject = payload.get("sub")
    if not subject:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token missing subject")
    return Principal(subject=subject, auth_method="jwt")


def _verify_api_key(raw_key: str) -> Principal:
    settings = get_settings()
    key_id, _, key_secret = raw_key.partition(":")
    expected = settings.api_keys_map.get(key_id)
    if not expected or not hmac.compare_digest(expected, key_secret):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")
    return Principal(subject=key_id, auth_method="api_key")


async def get_current_principal(
    bearer: HTTPAuthorizationCredentials | None = Security(_bearer_scheme),
    x_api_key: str | None = Security(_api_key_scheme),
) -> Principal:
    """FastAPI dependency: accepts a Bearer JWT or an X-API-Key header.
    Exactly one working credential is required; neither present -> 401."""
    if bearer and bearer.credentials:
        return _verify_jwt(bearer.credentials)

    if x_api_key:
        return _verify_api_key(x_api_key)

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Missing credentials: provide 'Authorization: Bearer <jwt>' or 'X-API-Key'",
        headers={"WWW-Authenticate": "Bearer"},
    )
