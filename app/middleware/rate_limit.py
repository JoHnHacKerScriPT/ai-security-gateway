"""Redis-backed token-bucket rate limiting (Denial-of-Wallet / DoS protection).

Each caller identity (API key id, or JWT subject, combined with client IP) gets
its own bucket of `capacity` tokens that refills at `refill_per_second`. One
request costs one token. The bucket state (tokens, last-refill timestamp) is
stored in a Redis hash and updated atomically via a Lua script, so this is
safe across multiple gateway replicas sharing the same Redis instance.
"""
from __future__ import annotations

import time

import jwt
from redis.asyncio import Redis
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from app.core.config import get_settings
from app.observability.logging import log_security_event
from app.observability.metrics import RATE_LIMIT_TRIGGERED_TOTAL

# KEYS[1] = bucket key
# ARGV[1] = capacity, ARGV[2] = refill_per_second, ARGV[3] = now (float), ARGV[4] = cost, ARGV[5] = ttl_seconds
_RATE_LIMIT_LUA = """
local tokens = tonumber(redis.call('HGET', KEYS[1], 'tokens'))
local ts = tonumber(redis.call('HGET', KEYS[1], 'ts'))
local capacity = tonumber(ARGV[1])
local refill_rate = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local cost = tonumber(ARGV[4])
local ttl = tonumber(ARGV[5])

if tokens == nil then
  tokens = capacity
  ts = now
end

local delta = now - ts
if delta < 0 then delta = 0 end
tokens = math.min(capacity, tokens + delta * refill_rate)

local allowed = 0
if tokens >= cost then
  tokens = tokens - cost
  allowed = 1
end

redis.call('HSET', KEYS[1], 'tokens', tokens, 'ts', now)
redis.call('EXPIRE', KEYS[1], ttl)

return {allowed, tostring(tokens)}
"""

EXEMPT_PATHS = {"/health", "/metrics"}


def resolve_rate_limit_key(request: Request) -> str:
    """Best-effort caller identity for bucketing. Not a security decision —
    just picks which bucket a request draws from — so an unverified JWT
    subject is fine here; real credential verification happens in the auth
    dependency downstream."""
    client_ip = request.client.host if request.client else "unknown"
    identity = "anon"

    api_key = request.headers.get("x-api-key")
    if api_key:
        identity = f"apikey:{api_key.split(':', 1)[0]}"
    else:
        auth = request.headers.get("authorization", "")
        if auth.lower().startswith("bearer "):
            token = auth[7:]
            try:
                # Unverified on purpose: this only picks a bucket. The signature
                # is checked by the auth dependency before anything is served.
                claims = jwt.decode(token, options={"verify_signature": False})
                identity = f"jwt:{claims.get('sub', 'unknown')}"
            except jwt.InvalidTokenError:
                identity = "jwt:invalid"

    return f"{identity}:{client_ip}"


class RedisTokenBucketLimiter:
    """Uses plain EVAL (not EVALSHA/register_script) on purpose: redis-py's
    Script wrapper caches the script server-side and calls EVALSHA, falling
    back to EVAL only if it recognizes a NOSCRIPT error — but some
    Redis-protocol-compatible servers (e.g. fakeredis's TcpFakeServer, used
    for local dev without Docker) phrase that error slightly differently,
    so redis-py never triggers the fallback and every call fails. Sending
    the full script every time sidesteps that entirely and costs nothing
    meaningful (it's ~15 lines) — works identically against real Redis."""

    def __init__(self, redis: Redis, capacity: int, refill_per_second: float, ttl_seconds: int = 3600):
        self._redis = redis
        self._capacity = capacity
        self._refill_per_second = refill_per_second
        self._ttl_seconds = ttl_seconds

    async def allow(self, key: str, cost: float = 1.0) -> tuple[bool, float]:
        now = time.time()
        allowed, remaining = await self._redis.eval(
            _RATE_LIMIT_LUA,
            1,
            f"ratelimit:{key}",
            self._capacity,
            self._refill_per_second,
            now,
            cost,
            self._ttl_seconds,
        )
        return bool(int(allowed)), float(remaining)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Starlette middleware enforcing the token bucket on every non-exempt path."""

    def __init__(self, app, redis: Redis):
        super().__init__(app)
        settings = get_settings()
        self._limiter = RedisTokenBucketLimiter(
            redis=redis,
            capacity=settings.rate_limit_bucket_capacity,
            refill_per_second=settings.rate_limit_refill_per_second,
        )

    async def dispatch(self, request: Request, call_next):
        # scope["path"] is the path the router actually dispatches on.
        # request.url is rebuilt from the Host header too, and older Starlette
        # let a crafted Host make request.url.path read "/health" while the
        # request was routed to /v1/... (rate-limit bypass).
        if request.scope["path"] in EXEMPT_PATHS:
            return await call_next(request)

        key = resolve_rate_limit_key(request)
        allowed, remaining = await self._limiter.allow(key)

        if not allowed:
            RATE_LIMIT_TRIGGERED_TOTAL.inc()
            log_security_event("rate_limit_triggered", identity_key=key, path=request.url.path)
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded. Slow down."},
                headers={"Retry-After": "1"},
            )

        response = await call_next(request)
        response.headers["X-RateLimit-Remaining"] = f"{remaining:.2f}"
        return response
