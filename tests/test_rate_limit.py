from __future__ import annotations


def test_requests_within_capacity_are_allowed(client):
    # conftest sets RATE_LIMIT_BUCKET_CAPACITY=3 and near-zero refill.
    for _ in range(3):
        resp = client.get("/v1/whoami", headers={"X-API-Key": "testkey:testsecret"})
        assert resp.status_code == 200
        assert "X-RateLimit-Remaining" in resp.headers


def test_requests_beyond_capacity_are_429(client):
    for _ in range(3):
        client.get("/v1/whoami", headers={"X-API-Key": "testkey:testsecret"})
    resp = client.get("/v1/whoami", headers={"X-API-Key": "testkey:testsecret"})
    assert resp.status_code == 429
    assert "Retry-After" in resp.headers


def test_buckets_are_isolated_per_identity(client):
    for _ in range(3):
        r = client.get("/v1/whoami", headers={"X-API-Key": "testkey:testsecret"})
        assert r.status_code == 200
    # A different caller identity must have its own, untouched bucket.
    from app.core.security import create_access_token

    token = create_access_token(subject="someone-else")
    resp = client.get("/v1/whoami", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200


def test_health_endpoint_is_exempt_from_rate_limiting(client):
    for _ in range(10):
        resp = client.get("/health")
        assert resp.status_code == 200
