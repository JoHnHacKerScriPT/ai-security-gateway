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


# ---- JWT hardening (PyJWT migration) ----
import time  # noqa: E402

import jwt  # noqa: E402
import pytest  # noqa: E402
from pydantic import ValidationError  # noqa: E402

from app.core.config import Settings, get_settings  # noqa: E402


def _claims(**overrides):
    now = int(time.time())
    claims = {"sub": "alice", "iat": now, "exp": now + 60}
    claims.update(overrides)
    return {k: v for k, v in claims.items() if v is not None}


def test_jwt_without_exp_is_rejected(client):
    token = jwt.encode(_claims(exp=None), get_settings().jwt_secret, algorithm="HS256")
    resp = client.get("/v1/whoami", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401


def test_jwt_with_alg_none_is_rejected(client):
    token = jwt.encode(_claims(), None, algorithm="none")
    resp = client.get("/v1/whoami", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401


def test_jwt_signed_with_unexpected_algorithm_is_rejected(client):
    secret = get_settings().jwt_secret * 2  # long enough for HS512, same key material
    token = jwt.encode(_claims(), secret, algorithm="HS512")
    resp = client.get("/v1/whoami", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401


def test_jwt_signed_with_wrong_secret_is_rejected(client):
    token = jwt.encode(_claims(), "x" * 64, algorithm="HS256")
    resp = client.get("/v1/whoami", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401


def test_settings_require_jwt_secret(monkeypatch):
    monkeypatch.delenv("JWT_SECRET", raising=False)
    with pytest.raises(ValidationError):
        Settings(_env_file=None)


@pytest.mark.parametrize(
    "secret",
    ["change-me-to-a-long-random-value", "insecure-dev-secret-change-me", "too-short"],
)
def test_settings_reject_placeholder_or_short_secret(secret):
    with pytest.raises(ValidationError):
        Settings(_env_file=None, jwt_secret=secret)
