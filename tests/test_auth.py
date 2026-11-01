from __future__ import annotations

from app.core.security import create_access_token


def test_health_is_public(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.text == "ok"


def test_whoami_rejects_missing_credentials(client):
    resp = client.get("/v1/whoami")
    assert resp.status_code == 401


def test_whoami_accepts_valid_api_key(client):
    resp = client.get("/v1/whoami", headers={"X-API-Key": "testkey:testsecret"})
    assert resp.status_code == 200
    body = resp.json()
    assert body == {"subject": "testkey", "auth_method": "api_key"}


def test_whoami_rejects_wrong_api_key_secret(client):
    resp = client.get("/v1/whoami", headers={"X-API-Key": "testkey:wrong-secret"})
    assert resp.status_code == 401


def test_whoami_rejects_unknown_api_key_id(client):
    resp = client.get("/v1/whoami", headers={"X-API-Key": "nosuchkey:whatever"})
    assert resp.status_code == 401


def test_whoami_accepts_valid_jwt(client):
    token = create_access_token(subject="alice")
    resp = client.get("/v1/whoami", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    body = resp.json()
    assert body == {"subject": "alice", "auth_method": "jwt"}


def test_whoami_rejects_garbage_jwt(client):
    resp = client.get("/v1/whoami", headers={"Authorization": "Bearer not-a-real-token"})
    assert resp.status_code == 401


def test_whoami_rejects_expired_jwt(client):
    token = create_access_token(subject="alice", expire_minutes=-1)
    resp = client.get("/v1/whoami", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401


def test_authorization_header_requires_bearer_scheme(client):
    resp = client.get("/v1/whoami", headers={"Authorization": "Basic dXNlcjpwYXNz"})
    assert resp.status_code == 401
