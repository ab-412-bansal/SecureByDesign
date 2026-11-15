import asyncio

import httpx
import pytest
from fastapi import HTTPException

import vaultwarden_client


class StubAsyncClient:
    def __init__(self, *, response=None, error=None):
        self.response = response
        self.error = error
        self.request_args = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        return False

    async def request(self, method, url, **kwargs):
        self.request_args = (method, url, kwargs)
        if self.error:
            raise self.error
        return self.response


def test_vaultwarden_client_builds_request_and_forwards_auth(monkeypatch):
    stub = StubAsyncClient(response=httpx.Response(200, json={"ok": True}))
    monkeypatch.setattr(vaultwarden_client.httpx, "AsyncClient", lambda **kwargs: stub)

    response = asyncio.run(vaultwarden_client.vaultwarden_request(
        "GET", "/api/sync", authorization="Bearer token", params={"excludeDomains": "true"}
    ))

    method, url, kwargs = stub.request_args
    assert response.status_code == 200
    assert method == "GET"
    assert url.endswith("/api/sync")
    assert kwargs["headers"]["Authorization"] == "Bearer token"
    assert kwargs["params"] == {"excludeDomains": "true"}


@pytest.mark.parametrize(
    ("error", "status_code"),
    [
        (httpx.ConnectError("offline"), 503),
        (httpx.TimeoutException("timed out"), 504),
    ],
)
def test_vaultwarden_client_maps_connection_errors(monkeypatch, error, status_code):
    stub = StubAsyncClient(error=error)
    monkeypatch.setattr(vaultwarden_client.httpx, "AsyncClient", lambda **kwargs: stub)

    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(vaultwarden_client.vaultwarden_request("GET", "/api/sync"))

    assert exc_info.value.status_code == status_code