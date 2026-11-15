from fastapi import APIRouter, Depends, HTTPException

from auth_module import require_auth
from vaultwarden_client import vaultwarden_request


router = APIRouter()


@router.get("/security-score")
async def security_score(authorization: str = Depends(require_auth)):
    response = await vaultwarden_request("GET", "/api/ciphers", authorization=authorization)
    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail="Vaultwarden cipher request failed")
    body = response.json()
    ciphers = body.get("data", body.get("Data", [])) if isinstance(body, dict) else body
    type_map = {1: "Login", 2: "Secure Note", 3: "Card", 4: "Identity"}
    total_logins = sum(1 for cipher in ciphers if cipher.get("type", cipher.get("Type")) == 1)
    items = [
        {
            "name": f"Item {index + 1}",
            "type": type_map.get(cipher.get("type", cipher.get("Type")), "Unknown"),
            "created": cipher.get("creationDate", cipher.get("CreationDate", "")),
            "id": cipher.get("id", cipher.get("Id", "")),
        }
        for index, cipher in enumerate(ciphers)
    ]
    score = min(100, 40 + total_logins * 10) if ciphers else 0
    return {"total_passwords": len(ciphers), "total_logins": total_logins, "security_score": score, "items": items}