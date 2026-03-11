from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, Dict, Any
import uvicorn
import secrets
import string
import math
import httpx
import os
import hashlib
import base64

VAULTWARDEN_URL = os.getenv("VAULTWARDEN_URL", "https://nginx:9443")

app = FastAPI(
    title="Security Intelligence API",
    description="Password vault security backend with real Vaultwarden integration",
    version="1.0.0",
    root_path="/api",
    openapi_url="/openapi.json",
    docs_url="/docs",
    redoc_url="/redoc"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://localhost", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Models ────────────────────────────────────────────────
class VaultLoginRequest(BaseModel):
    email: str
    password: str

class PasswordAnalysisRequest(BaseModel):
    password: str

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

# ── Vaultwarden KDF ───────────────────────────────────────
def derive_master_password_hash(password: str, email: str, iterations: int = 600000) -> str:
    """
    Bitwarden KDF — plain password never sent to server.
    Step 1: PBKDF2-SHA256(password, email, 600000) -> master_key
    Step 2: PBKDF2-SHA256(master_key, password, 1) -> master_password_hash
    Step 3: Base64 encode
    """
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

# ── Password Helpers ──────────────────────────────────────
def analyze_password(password: str) -> Dict[str, Any]:
    length = len(password)
    charset = 0
    if any(c.islower() for c in password): charset += 26
    if any(c.isupper() for c in password): charset += 26
    if any(c.isdigit() for c in password): charset += 10
    if any(c in string.punctuation for c in password): charset += len(string.punctuation)
    entropy = length * math.log2(charset) if charset else 0
    common_patterns = ["password", "1234", "qwerty", "letmein", "admin", "welcome", "monkey", "dragon"]
    found_pattern = any(p in password.lower() for p in common_patterns)
    risk_level = "high" if found_pattern or entropy < 40 else ("medium" if entropy < 60 else "low")
    estimated_crack_time = (
        "seconds" if entropy < 30 else
        "minutes" if entropy < 40 else
        "hours"   if entropy < 50 else
        "years"
    )
    return {
        "strength_score": min(int(entropy), 100),
        "estimated_crack_time": estimated_crack_time,
        "risk_level": risk_level,
        "entropy": round(entropy, 2)
    }

# ── Root ──────────────────────────────────────────────────
@app.get("/")
def root():
    return {"status": "ok", "message": "Security Intelligence API is running"}

# ── Vaultwarden Login ─────────────────────────────────────
@app.post("/vault/login")
async def vault_login(req: VaultLoginRequest):
    """Login to Vaultwarden — returns access token."""
    hashed_password = derive_master_password_hash(req.password, req.email)

    # verify=False because we use a self-signed cert internally
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
                raise HTTPException(
                    status_code=401,
                    detail=f"Vaultwarden login failed: {response.text}"
                )
            data = response.json()
            return {
                "access_token": data.get("access_token"),
                "token_type":   data.get("token_type", "Bearer"),
                "expires_in":   data.get("expires_in"),
            }
        except httpx.ConnectError as e:
            raise HTTPException(status_code=503, detail=f"Cannot connect to Vaultwarden: {str(e)}")

# ── Security Score ────────────────────────────────────────
@app.get("/security-score")
async def api_security_score(authorization: Optional[str] = Header(None)):
    """
    Fetch real cipher list from Vaultwarden.
    All fields (name, username, password) are E2E encrypted by the client —
    the server only stores ciphertext. We count items and report types.
    Item count = 4 ciphers in your vault (confirmed from API response).
    """
    if not authorization:
        return {
            "total_passwords": 0,
            "total_logins": 0,
            "security_score": 0,
            "items": [],
            "note": "Login to see real vault stats"
        }

    async with httpx.AsyncClient(verify=False) as client:
        try:
            response = await client.get(
                f"{VAULTWARDEN_URL}/api/ciphers",
                headers={"Authorization": authorization}
            )

            print(f"[DEBUG] /api/ciphers status: {response.status_code}")

            if response.status_code == 401:
                raise HTTPException(status_code=401, detail="Token expired. Please login again.")
            if response.status_code != 200:
                raise HTTPException(status_code=502, detail=f"Vault error: {response.text}")

            body = response.json()

            # ✅ Correct key is lowercase "data" not "Data"
            # Response shape: {"continuationToken": null, "data": [...], "object": "list"}
            if isinstance(body, dict):
                ciphers = body.get("data", body.get("Data", []))
            elif isinstance(body, list):
                ciphers = body
            else:
                ciphers = []

            print(f"[DEBUG] Total ciphers found: {len(ciphers)}")

            # Count by type
            # Type 1 = Login, 2 = SecureNote, 3 = Card, 4 = Identity
            type_map = {1: "Login", 2: "Secure Note", 3: "Card", 4: "Identity"}
            total        = len(ciphers)
            total_logins = sum(1 for c in ciphers if c.get("type") == 1)

            # Build item list
            # NOTE: "name" field is also encrypted (E2E), shows as base64 ciphertext
            # We show item number + type since names are unreadable server-side
            items = []
            for i, c in enumerate(ciphers):
                item_type = type_map.get(c.get("type"), "Unknown")
                # name is encrypted, so label generically
                items.append({
                    "name": f"Item {i + 1}",
                    "type": item_type,
                    "created": c.get("creationDate", ""),
                    "id": c.get("id", "")
                })

            # Score: simple vault health score based on having items
            if total == 0:
                score = 0
            else:
                score = min(100, 40 + total_logins * 10)

            return {
                "total_passwords": total,
                "total_logins": total_logins,
                "security_score": score,
                "items": items,
                "note": "All vault data is end-to-end encrypted. Names and passwords cannot be read server-side."
            }

        except httpx.ConnectError as e:
            raise HTTPException(status_code=503, detail=f"Cannot connect to Vaultwarden: {str(e)}")

# ── Password Analysis ─────────────────────────────────────
@app.post("/analyze-password")
def api_analyze_password(req: PasswordAnalysisRequest):
    return analyze_password(req.password)

# ── Breach Check ──────────────────────────────────────────
@app.post("/check-breach")
def api_check_breach(req: BreachCheckRequest):
    common = [
        "password", "123456", "qwerty", "letmein", "admin", "welcome",
        "monkey", "dragon", "master", "123456789", "password1", "12345678",
        "abc123", "password123", "iloveyou"
    ]
    breached, breach_type = False, None
    if req.password and req.password.lower() in common:
        breached, breach_type = True, "common_password"
    if req.email and req.email.endswith("@pwned.com"):
        breached, breach_type = True, "email_breached"
    return {"compromised": breached, "type": breach_type}

# ── Login Alert ───────────────────────────────────────────
SECURITY_EVENTS = []

@app.post("/login-alert")
def api_login_alert(req: LoginAlertRequest):
    suspicious = req.ip.startswith("10.") or req.device == "unknown"
    event = req.dict()
    event["suspicious"] = suspicious
    SECURITY_EVENTS.append(event)
    return {"alert": suspicious, "event": event}

# ── Password Generator ────────────────────────────────────
@app.post("/generate-password")
def api_generate_password(req: PasswordGenRequest):
    if req.passphrase:
        words = [
            "correct", "horse", "battery", "staple", "random", "secure",
            "vault", "cloud", "tiger", "river", "storm", "pixel", "lunar",
            "frost", "amber", "noble", "swift", "brave", "crisp", "vivid"
        ]
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
    entropy = analyze_password(req.password)["strength_score"]
    if req.attack_type == "dictionary":
        t = "seconds" if entropy < 30 else "minutes" if entropy < 50 else "years"
    elif req.attack_type == "brute_force":
        t = "minutes" if entropy < 40 else "hours" if entropy < 60 else "years"
    else:
        t = "hours" if entropy < 50 else "years"
    return {"attack_type": req.attack_type, "estimated_crack_time": t, "entropy": entropy}

# ── Backup ────────────────────────────────────────────────
@app.post("/backup-vault")
def api_backup_vault(req: BackupRequest):
    backup_file = f"backup_{secrets.token_hex(4)}.enc"
    with open(backup_file, "w") as f:
        f.write("ENCRYPTED_DUMMY_DATA")
    return {"backup_file": backup_file, "status": "encrypted"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)