import os
from typing import Any, Dict, Optional

import httpx
from fastapi import HTTPException


VAULTWARDEN_URL = os.getenv("VAULTWARDEN_URL", "http://vaultwarden:80").rstrip("/")
VERIFY_TLS = os.getenv("VAULTWARDEN_VERIFY_TLS", "false").lower() == "true"


async def vaultwarden_request(
    method: str,
    path: str,
    *,
    authorization: Optional[str] = None,
    headers: Optional[Dict[str, str]] = None,
    data: Optional[Dict[str, Any]] = None,
    params: Optional[Dict[str, str]] = None,
) -> httpx.Response:
    request_headers = dict(headers or {})
    if authorization:
        request_headers["Authorization"] = authorization
    try:
        async with httpx.AsyncClient(verify=VERIFY_TLS, timeout=20) as client:
            return await client.request(
                method,
                f"{VAULTWARDEN_URL}/{path.lstrip('/')}",
                headers=request_headers,
                data=data,
                params=params,
            )
    except httpx.ConnectError as exc:
        raise HTTPException(
            status_code=503,
            detail=f"Cannot connect to Vaultwarden at {VAULTWARDEN_URL}",
        ) from exc
    except httpx.TimeoutException as exc:
        raise HTTPException(status_code=504, detail="Vaultwarden request timed out") from exc