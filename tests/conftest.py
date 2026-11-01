from __future__ import annotations

import os

import pytest

# Force a predictable, permissive config before anything imports app.core.config.
os.environ.setdefault("JWT_SECRET", "test-secret")
os.environ.setdefault("GATEWAY_API_KEYS", "testkey:testsecret")
os.environ.setdefault("RATE_LIMIT_BUCKET_CAPACITY", "3")
os.environ.setdefault("RATE_LIMIT_REFILL_PER_SECOND", "0.001")  # effectively no refill during a test
os.environ.setdefault("ANTHROPIC_API_KEY", "sk-ant-test-key-0000000000000000")
os.environ.setdefault("OPENAI_API_KEY", "sk-test-key-0000000000000000")


@pytest.fixture
def app_and_redis():
    """Build a fresh FastAPI app wired to an in-memory fake Redis, so tests
    never touch a real Redis server."""
    import fakeredis.aioredis

    from app.core import redis_client
    from app.core.config import get_settings

    get_settings.cache_clear()
    fake = fakeredis.aioredis.FakeRedis(decode_responses=True)
    redis_client._client = fake  # reuse the module-level singleton slot

    from app.main import create_app

    app = create_app()
    return app, fake


@pytest.fixture
def client(app_and_redis):
    from fastapi.testclient import TestClient

    app, _redis = app_and_redis
    with TestClient(app) as c:
        yield c
