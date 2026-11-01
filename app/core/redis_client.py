"""Shared async Redis connection, lazily created and cached per-process.

Dev-mode note: when settings.use_fake_redis is true, we hand out an
in-process fakeredis.aioredis.FakeRedis instead of a real network
connection. This is ONLY for local development on a machine without a
real Redis server available. It talks to fakeredis's Python object model
directly (no TCP/RESP wire protocol involved), which is the same code
path our test suite already exercises successfully. It intentionally
avoids fakeredis.TcpFakeServer, whose minimal hand-rolled RESP parser has
proven unreliable with larger multi-bulk commands (e.g. our Lua EVAL
script) on this project.

`fakeredis` is a dev-only dependency (see requirements-dev.txt) and is
imported lazily below so a production install (requirements.txt only)
never needs it importable at module load time.
"""
from __future__ import annotations

from redis.asyncio import Redis

from app.core.config import get_settings

_client: Redis | None = None


def get_redis() -> Redis:
    global _client
    if _client is None:
        settings = get_settings()
        if settings.use_fake_redis:
            from fakeredis.aioredis import FakeRedis as FakeAsyncRedisClient

            _client = FakeAsyncRedisClient(decode_responses=True)
        else:
            _client = Redis.from_url(settings.redis_url, decode_responses=True)
    return _client


async def close_redis() -> None:
    global _client
    if _client is not None:
        await _client.aclose()
        _client = None
