from fastapi import FastAPI, HTTPException, Header, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Optional, Dict, Any, List
import uvicorn
import secrets
import string
import math
import httpx
import os
import hashlib
import base64

VAULTWARDEN_URL = os.getenv("VAULTWARDEN_URL", "https://nginx:9443")

# ── Security scheme — enables Authorize 🔓 button in Swagger ──
security = HTTPBearer(auto_error=False)

app = FastAPI(
    title="Security Intelligence API",
    version="1.0.0",
    root_path="/api",
    openapi_url="/openapi.json",
    docs_url="/docs",
    redoc_url="/redoc",
    swagger_ui_parameters={"persistAuthorization": True}  # keeps token after page refresh
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://localhost", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Helper: extract auth token from any source ────────────
def get_auth(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials]
) -> Optional[str]:
    """
    Read Bearer token from:
    1. HTTPBearer credentials (Swagger Authorize button)
    2. Raw Authorization header (any case)
    """
    if credentials and credentials.credentials:
        return f"Bearer {credentials.credentials}"
    return (
        request.headers.get("Authorization") or
        request.headers.get("authorization")
    )

# ── Models ────────────────────────────────────────────────
class VaultLoginRequest(BaseModel):
    email: str
    password: str

class PasswordAnalysisRequest(BaseModel):
    password: str

class VaultItem(BaseModel):
    id: str
    name: str
    username: Optional[str] = None
    password: Optional[str] = None
    type: str = "Login"

class BatchAnalysisRequest(BaseModel):
    items: List[VaultItem]

class BreachCheckRequest(BaseModel):
    password: Optional[str] = None
    email: Optional[str] = None

class LoginAlertRequest(BaseModel):
    user_id: str
    ip: str
    device: str
    location: Optional[str] = None
    time: str

class PasswordGenRequest(BaseModel):
    length: int = 16
    use_symbols: bool = True
    use_numbers: bool = True
    use_upper: bool = True
    use_lower: bool = True
    passphrase: bool = False
    site: Optional[str] = None

class AttackSimRequest(BaseModel):
    password: str
    attack_type: str

class BackupRequest(BaseModel):
    key: str
    schedule: Optional[str] = None

# ── KDF ───────────────────────────────────────────────────
def derive_master_password_hash(password: str, email: str, iterations: int = 600000) -> str:
    master_key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        email.lower().strip().encode('utf-8'),
        iterations
    )
    master_password_hash = hashlib.pbkdf2_hmac(
        'sha256',
        master_key,
        password.encode('utf-8'),
        1
    )
    return base64.b64encode(master_password_hash).decode('utf-8')

# ── Password Analysis ─────────────────────────────────────
BREACHED_PASSWORDS = [
    "password", "123456", "qwerty", "letmein", "admin", "welcome",
    "monkey", "dragon", "master", "123456789", "password1", "12345678",
    "abc123", "password123", "iloveyou", "1234567", "sunshine", "princess",
    "football", "charlie", "donald", "password2", "qwerty123", "1q2w3e4r"
]

def analyze_password(password: str) -> Dict[str, Any]:
    if not password:
        return {
            "strength_score": 0, "estimated_crack_time": "instant",
            "risk_level": "high", "entropy": 0, "issues": ["No password set"]
        }
    length = len(password)
    charset = 0
    has_lower  = any(c.islower() for c in password)
    has_upper  = any(c.isupper() for c in password)
    has_digit  = any(c.isdigit() for c in password)
    has_symbol = any(c in string.punctuation for c in password)
    if has_lower:  charset += 26
    if has_upper:  charset += 26
    if has_digit:  charset += 10
    if has_symbol: charset += len(string.punctuation)
    entropy = length * math.log2(charset) if charset else 0
    common_patterns = ["password", "1234", "qwerty", "letmein", "admin",
                       "welcome", "monkey", "dragon", "abc", "111", "000"]
    found_pattern = any(p in password.lower() for p in common_patterns)
    is_breached   = password.lower() in BREACHED_PASSWORDS
    issues = []
    if length < 8:    issues.append("Too short (min 8 chars)")
    if length < 12:   issues.append("Short password (12+ recommended)")
    if not has_upper: issues.append("No uppercase letters")
    if not has_lower: issues.append("No lowercase letters")
    if not has_digit: issues.append("No numbers")
    if not has_symbol:issues.append("No special characters")
    if found_pattern: issues.append("Contains common pattern")
    if is_breached:   issues.append("Found in known breached password list")
    risk_level = (
        "critical" if is_breached or entropy < 28 else
        "high"     if found_pattern or entropy < 40 else
        "medium"   if entropy < 60 else "low"
    )
    estimated_crack_time = (
        "instant" if entropy < 20 else "seconds" if entropy < 30 else
        "minutes" if entropy < 40 else "hours"   if entropy < 50 else
        "days"    if entropy < 60 else "years"
    )
    return {
        "strength_score": min(int(entropy), 100),
        "estimated_crack_time": estimated_crack_time,
        "risk_level": risk_level, "entropy": round(entropy, 2),
        "length": length, "has_upper": has_upper, "has_lower": has_lower,
        "has_digit": has_digit, "has_symbol": has_symbol,
        "is_breached": is_breached, "issues": issues
    }

# ── Root ──────────────────────────────────────────────────
@app.get("/")
def root():
    return {"status": "ok", "message": "Security Intelligence API is running"}

# ── Vaultwarden Login ─────────────────────────────────────
@app.post("/vault/login")
async def vault_login(req: VaultLoginRequest):
    """
    Login to Vaultwarden and receive a JWT access token.
    The plain password is hashed with PBKDF2-SHA256 (600k iterations) before being sent —
    your real password never leaves this server.
    Copy the access_token and use the Authorize 🔓 button at the top of this page.
    """
    hashed_password = derive_master_password_hash(req.password, req.email)
    async with httpx.AsyncClient(verify=False) as client:
        try:
            response = await client.post(
                f"{VAULTWARDEN_URL}/identity/connect/token",
                data={
                    "grant_type": "password",
                    "username": req.email,
                    "password": hashed_password,
                    "scope": "api offline_access",
                    "client_id": "web",
                    "deviceType": 10,
                    "deviceIdentifier": secrets.token_hex(16),
                    "deviceName": "security-backend",
                    "devicePushToken": ""
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            if response.status_code != 200:
                raise HTTPException(status_code=401, detail=f"Login failed: {response.text}")
            data = response.json()
            return {
                "access_token": data.get("access_token"),
                "token_type":   data.get("token_type", "Bearer"),
                "expires_in":   data.get("expires_in"),
            }
        except httpx.ConnectError as e:
            raise HTTPException(status_code=503, detail=f"Cannot connect to Vaultwarden: {str(e)}")

# ── Vault Sync Proxy ──────────────────────────────────────
@app.get("/vault/sync")
async def vault_sync(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
):
    """
    Proxy Vaultwarden sync — returns encrypted profile key and all vault ciphers.
    🔑 Requires auth: click Authorize 🔓 at top of page and paste your access_token first.
    """
    auth = get_auth(request, credentials)
    if not auth:
        raise HTTPException(
            status_code=401,
            detail="No token provided. Click the Authorize 🔓 button at the top of this page and paste your access_token."
        )
    async with httpx.AsyncClient(verify=False) as client:
        try:
            response = await client.get(
                f"{VAULTWARDEN_URL}/api/sync?excludeDomains=true",
                headers={"Authorization": auth}
            )
            if response.status_code == 401:
                raise HTTPException(status_code=401, detail="Token expired. Login again via POST /vault/login")
            if response.status_code != 200:
                raise HTTPException(status_code=502, detail=f"Sync failed: {response.text}")
            data    = response.json()
            profile = data.get("profile", {})
            ciphers = data.get("ciphers", [])
            return {
                "profile": {"key": profile.get("key")},
                "ciphers": [
                    {
                        "id":       c.get("id"),
                        "type":     c.get("type"),
                        "name":     c.get("name"),
                        "key":      c.get("key"),
                        "data":     c.get("data", {}),
                        "login":    c.get("login"),
                        "identity": c.get("identity"),
                    }
                    for c in ciphers
                ]
            }
        except httpx.ConnectError as e:
            raise HTTPException(status_code=503, detail=f"Cannot connect to Vaultwarden: {str(e)}")

# ── Vault Ciphers Proxy ───────────────────────────────────
@app.get("/vault/ciphers")
async def vault_ciphers(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
):
    """
    Proxy raw cipher list from Vaultwarden. Returns all encrypted vault items.
    🔑 Requires auth: click Authorize 🔓 at top of page and paste your access_token first.
    """
    auth = get_auth(request, credentials)
    if not auth:
        raise HTTPException(
            status_code=401,
            detail="No token provided. Click the Authorize 🔓 button at the top of this page and paste your access_token."
        )
    async with httpx.AsyncClient(verify=False) as client:
        try:
            response = await client.get(
                f"{VAULTWARDEN_URL}/api/ciphers",
                headers={"Authorization": auth}
            )
            if response.status_code == 401:
                raise HTTPException(status_code=401, detail="Token expired. Login again via POST /vault/login")
            if response.status_code != 200:
                raise HTTPException(status_code=502, detail=f"Fetch failed: {response.text}")
            return response.json()
        except httpx.ConnectError as e:
            raise HTTPException(status_code=503, detail=f"Cannot connect to Vaultwarden: {str(e)}")

# ── Security Score ────────────────────────────────────────
@app.get("/security-score")
async def api_security_score(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
):
    """
    Get vault item counts and metadata-based security score.
    🔑 Requires auth: click Authorize 🔓 at top of page and paste your access_token first.
    Returns zeroed stats if no token provided.
    """
    auth = get_auth(request, credentials)
    if not auth:
        return {
            "total_passwords": 0, "total_logins": 0,
            "security_score": 0, "items": [],
            "note": "Click Authorize 🔓 at top of Swagger page and paste your access_token"
        }
    async with httpx.AsyncClient(verify=False) as client:
        try:
            response = await client.get(
                f"{VAULTWARDEN_URL}/api/ciphers",
                headers={"Authorization": auth}
            )
            if response.status_code == 401:
                raise HTTPException(status_code=401, detail="Token expired. Login again.")
            if response.status_code != 200:
                raise HTTPException(status_code=502, detail=f"Vault error: {response.text}")
            body         = response.json()
            ciphers      = body.get("data", body.get("Data", [])) if isinstance(body, dict) else body
            type_map     = {1: "Login", 2: "Secure Note", 3: "Card", 4: "Identity"}
            total        = len(ciphers)
            total_logins = sum(1 for c in ciphers if c.get("type") == 1)
            items = [
                {
                    "name":    f"Item {i + 1}",
                    "type":    type_map.get(c.get("type"), "Unknown"),
                    "created": c.get("creationDate", ""),
                    "id":      c.get("id", "")
                }
                for i, c in enumerate(ciphers)
            ]
            score = min(100, 40 + total_logins * 10) if total > 0 else 0
            return {
                "total_passwords": total,
                "total_logins": total_logins,
                "security_score": score,
                "items": items,
            }
        except httpx.ConnectError as e:
            raise HTTPException(status_code=503, detail=f"Cannot connect to Vaultwarden: {str(e)}")

# ── Vault Sync Debug ──────────────────────────────────────
@app.get("/vault/sync-debug")
async def vault_sync_debug(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
):
    """
    Debug endpoint — inspect raw Vaultwarden sync response structure.
    🔑 Requires auth: click Authorize 🔓 at top of page first.
    """
    auth = get_auth(request, credentials)
    if not auth:
        raise HTTPException(status_code=401, detail="No token. Click Authorize 🔓 at top of page.")
    async with httpx.AsyncClient(verify=False) as client:
        response = await client.get(
            f"{VAULTWARDEN_URL}/api/sync?excludeDomains=true",
            headers={"Authorization": auth}
        )
        data       = response.json()
        top_keys   = list(data.keys()) if isinstance(data, dict) else "NOT A DICT"
        profile    = data.get("Profile") or data.get("profile") or {}
        ciphers    = data.get("Ciphers") or data.get("ciphers") or []
        first_login = next((c for c in ciphers if c.get("Type") == 1 or c.get("type") == 1), None)
        return {
            "status_code":               response.status_code,
            "top_level_keys":            top_keys,
            "profile_key_value":         (profile.get("Key") or profile.get("key") or "NOT FOUND")[:80],
            "cipher_count":              len(ciphers),
            "first_login_data_password": ((first_login or {}).get("data", {}).get("password", "NO PASSWORD"))[:60] if first_login else None,
            "raw_response_prefix":       response.text[:400]
        }

# ── Batch Vault Analysis ──────────────────────────────────
@app.post("/analyze-vault")
def api_analyze_vault(req: BatchAnalysisRequest):
    """
    Receive decrypted vault items from the frontend and return a per-item security report.
    The frontend decrypts items client-side using the master key, then sends plain-text here.
    Try with example: items with passwords '123456', 'K#9mP$2xQ@nL5', '123456' to see reuse detection.
    """
    results = []
    all_passwords = [item.password for item in req.items if item.password]
    password_counts: Dict[str, int] = {}
    for p in all_passwords:
        password_counts[p] = password_counts.get(p, 0) + 1

    weak_count = breached_count = reused_count = 0
    scores: List[int] = []

    for item in req.items:
        if item.type != "Login" or not item.password:
            results.append({
                "id": item.id, "name": item.name,
                "username": item.username, "type": item.type,
                "skipped": True, "reason": "Not a login item or no password"
            })
            continue
        analysis  = analyze_password(item.password)
        is_reused = password_counts.get(item.password, 0) > 1
        if is_reused:
            analysis["issues"].append("Password reused across multiple accounts")
            if analysis["risk_level"] == "low":
                analysis["risk_level"] = "medium"
        if analysis["risk_level"] in ("high", "critical"): weak_count += 1
        if analysis["is_breached"]:                        breached_count += 1
        if is_reused:                                      reused_count += 1
        scores.append(analysis["strength_score"])
        results.append({
            "id": item.id, "name": item.name,
            "username": item.username, "type": item.type,
            "skipped": False, "is_reused": is_reused, **analysis
        })

    total_logins = len([r for r in results if not r.get("skipped")])
    avg_score    = round(sum(scores) / len(scores)) if scores else 0
    if total_logins == 0:
        vault_score = 0
    else:
        penalty = (
            (weak_count     / total_logins * 40) +
            (reused_count   / total_logins * 30) +
            (breached_count / total_logins * 30)
        )
        vault_score = max(0, round(100 - penalty))

    return {
        "vault_score": vault_score, "average_score": avg_score,
        "total": len(req.items), "total_logins": total_logins,
        "weak_count": weak_count, "breached_count": breached_count,
        "reused_count": reused_count, "items": results
    }

# ── Single Password Analysis ──────────────────────────────
@app.post("/analyze-password")
def api_analyze_password(req: PasswordAnalysisRequest):
    """
    Analyse a single password. Returns strength score, entropy, risk level, crack time, and issues.
    Try: '123456' (critical/breached) vs 'K#9mP$2xQ@nL5vR!' (low risk) to see the contrast.
    """
    return analyze_password(req.password)

# ── Breach Check ──────────────────────────────────────────
@app.post("/check-breach")
def api_check_breach(req: BreachCheckRequest):
    """
    Check if a password or email appears in known data breaches.
    Try password: '123456' → compromised: true. Try email: 'test@pwned.com' → compromised: true.
    """
    breached, breach_type = False, None
    if req.password and req.password.lower() in BREACHED_PASSWORDS:
        breached, breach_type = True, "common_password"
    if req.email and req.email.endswith("@pwned.com"):
        breached, breach_type = True, "email_breached"
    return {"compromised": breached, "type": breach_type}

# ── Login Alert ───────────────────────────────────────────
SECURITY_EVENTS: List[Dict] = []

@app.post("/login-alert")
def api_login_alert(req: LoginAlertRequest):
    """
    Log a login event and detect if it's suspicious.
    Suspicious triggers: IP starts with 10. OR device = 'unknown'.
    Try ip='10.0.0.5' or device='unknown' to trigger alert: true.
    """
    suspicious = req.ip.startswith("10.") or req.device == "unknown"
    event = req.dict()
    event["suspicious"] = suspicious
    SECURITY_EVENTS.append(event)
    return {"alert": suspicious, "event": event}

# ── Password Generator ────────────────────────────────────
@app.post("/generate-password")
def api_generate_password(req: PasswordGenRequest):
    """
    Generate a cryptographically secure password using Python's secrets module (CSPRNG).
    Set passphrase: true for a memorable word-based password like 'vault-tiger-frost-pixel'.
    """
    if req.passphrase:
        words = ["correct","horse","battery","staple","random","secure",
                 "vault","cloud","tiger","river","storm","pixel","lunar","frost","amber"]
        pw = "-".join(secrets.choice(words) for _ in range(max(3, req.length // 6)))
    else:
        chars = ""
        if req.use_lower:   chars += string.ascii_lowercase
        if req.use_upper:   chars += string.ascii_uppercase
        if req.use_numbers: chars += string.digits
        if req.use_symbols: chars += string.punctuation
        if not chars:       chars = string.ascii_letters
        pw = "".join(secrets.choice(chars) for _ in range(req.length))
    return {"password": pw, **analyze_password(pw)}

# ── Attack Simulation ─────────────────────────────────────
@app.post("/simulate-attack")
def api_simulate_attack(req: AttackSimRequest):
    """
    Simulate how long an attack would take to crack a password.
    attack_type options: 'dictionary', 'brute_force', 'credential_stuffing'.
    Try 'hello123' with brute_force vs 'K#9mP$2xQ@nL5vR!' with brute_force to see the difference.
    """
    entropy = analyze_password(req.password)["strength_score"]
    t = (
        "seconds" if entropy < 30 else
        "minutes" if entropy < 40 else
        "hours"   if entropy < 60 else "years"
    )
    return {"attack_type": req.attack_type, "estimated_crack_time": t, "entropy": entropy}

# ── Backup ────────────────────────────────────────────────
@app.post("/backup-vault")
def api_backup_vault(req: BackupRequest):
    """
    Trigger an encrypted vault backup. Returns a unique backup filename each time.
    In production this would encrypt real vault data with AES-256 using the provided key.
    """
    backup_file = f"backup_{secrets.token_hex(4)}.enc"
    with open(backup_file, "w") as f:
        f.write("ENCRYPTED_DUMMY_DATA")
    return {"backup_file": backup_file, "status": "encrypted"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)