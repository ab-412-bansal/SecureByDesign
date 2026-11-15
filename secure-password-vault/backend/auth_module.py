import base64
import hashlib
import secrets
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials

from dependencies import bearer_scheme, get_auth
from schemas import VaultLoginRequest
from vaultwarden_client import vaultwarden_request


router = APIRouter()


def derive_master_password_hash(password: str, email: str, iterations: int = 600_000) -> str:
	master_key = hashlib.pbkdf2_hmac(
		"sha256", password.encode("utf-8"), email.lower().strip().encode("utf-8"), iterations
	)
	password_hash = hashlib.pbkdf2_hmac("sha256", master_key, password.encode("utf-8"), 1)
	return base64.b64encode(password_hash).decode("utf-8")


def require_auth(
	request: Request,
	credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
) -> str:
	authorization = get_auth(request, credentials)
	if not authorization:
		raise HTTPException(status_code=401, detail="A Bearer access token is required")
	return authorization


@router.post("/vault/login")
async def vault_login(req: VaultLoginRequest):
	response = await vaultwarden_request(
		"POST", "/identity/connect/token",
		headers={
			"Bitwarden-Client-Name": "web",
			"Bitwarden-Client-Version": "2025.10.0",
		},
		data={
			"grant_type": "password",
			"username": req.email,
			"password": derive_master_password_hash(req.password, req.email),
			"scope": "api offline_access",
			"client_id": "web",
			"deviceType": "10",
			"deviceIdentifier": secrets.token_hex(16),
			"deviceName": "security-backend",
			"devicePushToken": "",
		},
	)
	if response.status_code != 200:
		try:
			error_response = response.json()
		except ValueError:
			error_response = {}
		detail = error_response.get("error_description") or "Vaultwarden rejected the login"
		status_code = 401 if response.status_code in (400, 401) else 502
		raise HTTPException(status_code=status_code, detail=detail)
	data = response.json()
	return {
		"access_token": data.get("access_token"),
		"token_type": data.get("token_type", "Bearer"),
		"expires_in": data.get("expires_in"),
	}


@router.get("/vault/sync")
async def vault_sync(authorization: str = Depends(require_auth)):
	response = await vaultwarden_request(
		"GET", "/api/sync", authorization=authorization,
		params={"excludeDomains": "true"},
	)
	if response.status_code != 200:
		raise HTTPException(status_code=response.status_code, detail="Vaultwarden sync failed")
	data = response.json()
	profile = data.get("profile") or data.get("Profile") or {}
	ciphers = data.get("ciphers") or data.get("Ciphers") or []
	return {"profile": {"key": profile.get("key") or profile.get("Key")}, "ciphers": ciphers}


@router.get("/vault/ciphers")
async def vault_ciphers(authorization: str = Depends(require_auth)):
	response = await vaultwarden_request("GET", "/api/ciphers", authorization=authorization)
	if response.status_code != 200:
		raise HTTPException(status_code=response.status_code, detail="Vaultwarden cipher request failed")
	return response.json()


@router.get("/vault/sync-debug")
async def vault_sync_debug(authorization: str = Depends(require_auth)):
	response = await vaultwarden_request(
		"GET", "/api/sync", authorization=authorization,
		params={"excludeDomains": "true"},
	)
	if response.status_code != 200:
		raise HTTPException(status_code=response.status_code, detail="Vaultwarden sync failed")
	data = response.json()
	profile = data.get("profile") or data.get("Profile") or {}
	ciphers = data.get("ciphers") or data.get("Ciphers") or []
	return {
		"status_code": response.status_code,
		"top_level_keys": list(data) if isinstance(data, dict) else [],
		"profile_key_present": bool(profile.get("key") or profile.get("Key")),
		"cipher_count": len(ciphers),
	}
