from unittest.mock import AsyncMock

import httpx
from fastapi.testclient import TestClient

import analytics
import auth_module
from auth_module import derive_master_password_hash


def test_health_route(client):
    response = client.get("/")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_vault_login_sends_client_headers_and_derived_password(monkeypatch, client):
    upstream = AsyncMock(return_value=httpx.Response(200, json={"access_token": "test-token"}))
    monkeypatch.setattr(auth_module, "vaultwarden_request", upstream)
    response = client.post(
        "/vault/login", json={"email": "Demo@Example.test", "password": "test-password"}
    )

    assert response.status_code == 200
    assert response.json()["access_token"] == "test-token"
    kwargs = upstream.await_args.kwargs
    assert kwargs["headers"]["Bitwarden-Client-Name"] == "web"
    assert kwargs["headers"]["Bitwarden-Client-Version"]
    assert kwargs["data"]["password"] == derive_master_password_hash(
        "test-password", "Demo@Example.test"
    )
    assert kwargs["data"]["password"] != "test-password"


def test_vault_login_exposes_safe_upstream_error(monkeypatch, client):
    upstream = AsyncMock(return_value=httpx.Response(
        400,
        json={"error": "invalid_grant", "error_description": "Username or password is incorrect."},
    ))
    monkeypatch.setattr(auth_module, "vaultwarden_request", upstream)

    response = client.post(
        "/vault/login", json={"email": "demo@example.test", "password": "wrong"}
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Username or password is incorrect."


def test_vault_login_maps_upstream_server_error_to_bad_gateway(monkeypatch, client):
    upstream = AsyncMock(return_value=httpx.Response(503, json={"error": "unavailable"}))
    monkeypatch.setattr(auth_module, "vaultwarden_request", upstream)

    response = client.post(
        "/vault/login", json={"email": "demo@example.test", "password": "test"}
    )

    assert response.status_code == 502


def test_vault_sync_requires_bearer_token(client):
    response = client.get("/vault/sync")

    assert response.status_code == 401


def test_vault_sync_forwards_token_and_normalizes_profile(monkeypatch, client):
    upstream = AsyncMock(return_value=httpx.Response(200, json={
        "Profile": {"Key": "encrypted-profile-key"}, "Ciphers": [{"Id": "cipher-1"}],
    }))
    monkeypatch.setattr(auth_module, "vaultwarden_request", upstream)

    response = client.get("/vault/sync", headers={"Authorization": "Bearer example-token"})

    assert response.status_code == 200
    assert response.json() == {
        "profile": {"key": "encrypted-profile-key"}, "ciphers": [{"Id": "cipher-1"}],
    }
    assert upstream.await_args.kwargs["authorization"] == "Bearer example-token"
    assert upstream.await_args.kwargs["params"] == {"excludeDomains": "true"}


def test_security_score_requires_token(client):
    response = client.get("/security-score")

    assert response.status_code == 401


def test_security_score_computes_metadata_summary(monkeypatch, client):
    upstream = AsyncMock(return_value=httpx.Response(200, json={"data": [
        {"id": "1", "type": 1, "creationDate": "2026-01-01"},
        {"id": "2", "type": 2},
    ]}))
    monkeypatch.setattr(analytics, "vaultwarden_request", upstream)

    response = client.get("/security-score", headers={"Authorization": "Bearer example-token"})

    assert response.status_code == 200
    assert response.json()["total_passwords"] == 2
    assert response.json()["total_logins"] == 1
    assert response.json()["security_score"] == 50


def test_backup_endpoint_explicitly_reports_not_implemented(client):
    response = client.post("/backup-vault", json={"key": "test-only"})

    assert response.status_code == 501
    assert "not implemented" in response.json()["detail"]


def test_login_form_validation_rejects_missing_password(client):
    response = client.post("/vault/login", json={"email": "demo@example.test"})

    assert response.status_code == 422