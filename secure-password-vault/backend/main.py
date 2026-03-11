from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, Dict, Any
import uvicorn
import secrets
import string
import math
import hashlib
import os

app = FastAPI(
    title="Security Intelligence API",
    description="Password vault security backend",
    version="1.0.0",
    root_path="/api",
    openapi_url="/openapi.json",
    docs_url="/docs",
    redoc_url="/redoc"
)

# ✅ Add CORS so frontend can talk to backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://localhost", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ✅ Add a root endpoint so /api/ doesn't 404
@app.get("/")
def root():
    return {"status": "ok", "message": "Security Intelligence API is running"}

# --- Models ---
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
    custom_rules: Optional[Dict[str, Any]] = None

class AttackSimRequest(BaseModel):
    password: str
    attack_type: str  # 'dictionary', 'brute_force', 'credential_stuffing'

class BackupRequest(BaseModel):
    key: str
    schedule: Optional[str] = None

# --- Password Strength Analyzer ---
def analyze_password(password: str) -> Dict[str, Any]:
    length = len(password)
    charset = 0
    if any(c.islower() for c in password):
        charset += 26
    if any(c.isupper() for c in password):
        charset += 26
    if any(c.isdigit() for c in password):
        charset += 10
    if any(c in string.punctuation for c in password):
        charset += len(string.punctuation)
    entropy = length * math.log2(charset) if charset else 0
    common_patterns = ["password", "1234", "qwerty", "letmein", "admin"]
    found_pattern = any(p in password.lower() for p in common_patterns)
    risk_level = "high" if found_pattern or entropy < 40 else ("medium" if entropy < 60 else "low")
    estimated_crack_time = "seconds" if entropy < 30 else ("minutes" if entropy < 40 else ("hours" if entropy < 50 else "years"))
    return {
        "strength_score": min(int(entropy), 100),
        "estimated_crack_time": estimated_crack_time,
        "risk_level": risk_level
    }

# --- Breach Detection ---
def check_breach(password: Optional[str], email: Optional[str]) -> Dict[str, Any]:
    breached = False
    breach_type = None
    if password and password.lower() in ["password", "123456", "qwerty"]:
        breached = True
        breach_type = "common_password"
    if email and email.endswith("@pwned.com"):
        breached = True
        breach_type = "email_breached"
    return {"compromised": breached, "type": breach_type}

# --- Security Score ---
def get_security_score() -> Dict[str, Any]:
    return {
        "total_passwords": 10,
        "weak_passwords": 2,
        "reused_passwords": 1,
        "breached_passwords": 1,
        "security_score": 78,
        "recent_logins": [
            {"user_id": "1", "ip": "1.2.3.4", "time": "2026-03-11T10:00:00"}
        ]
    }

# --- Suspicious Login Detection ---
SECURITY_EVENTS = []
def log_login_alert(data: LoginAlertRequest):
    suspicious = data.ip.startswith("10.") or data.device == "unknown"
    event = data.dict()
    event["suspicious"] = suspicious
    SECURITY_EVENTS.append(event)
    return {"alert": suspicious, "event": event}

# --- Password Generator ---
def generate_password(req: PasswordGenRequest) -> Dict[str, Any]:
    if req.passphrase:
        words = ["correct", "horse", "battery", "staple", "random", "secure", "vault", "cloud"]
        pw = "-".join(secrets.choice(words) for _ in range(max(3, req.length // 6)))
    else:
        chars = ''
        if req.use_lower:
            chars += string.ascii_lowercase
        if req.use_upper:
            chars += string.ascii_uppercase
        if req.use_numbers:
            chars += string.digits
        if req.use_symbols:
            chars += string.punctuation
        if not chars:
            chars = string.ascii_letters
        pw = ''.join(secrets.choice(chars) for _ in range(req.length))
    entropy = len(pw) * math.log2(len(set(pw))) if pw else 0
    return {"password": pw, "entropy": entropy}

# --- Attack Simulation ---
def simulate_attack(req: AttackSimRequest) -> Dict[str, Any]:
    entropy = analyze_password(req.password)["strength_score"]
    if req.attack_type == "dictionary":
        time = "seconds" if entropy < 30 else "minutes"
    elif req.attack_type == "brute_force":
        time = "minutes" if entropy < 40 else "years"
    else:
        time = "hours" if entropy < 50 else "years"
    return {"attack_type": req.attack_type, "estimated_crack_time": time}

# --- Encrypted Backup ---
def backup_vault(req: BackupRequest) -> Dict[str, Any]:
    backup_file = f"backup_{secrets.token_hex(4)}.enc"
    with open(backup_file, "w") as f:
        f.write("ENCRYPTED_DUMMY_DATA")
    return {"backup_file": backup_file, "status": "encrypted"}

# --- API Endpoints ---
@app.post("/analyze-password")
def api_analyze_password(req: PasswordAnalysisRequest):
    return analyze_password(req.password)

@app.post("/check-breach")
def api_check_breach(req: BreachCheckRequest):
    return check_breach(req.password, req.email)

@app.get("/security-score")
def api_security_score():
    return get_security_score()

@app.post("/login-alert")
def api_login_alert(req: LoginAlertRequest):
    return log_login_alert(req)

@app.post("/generate-password")
def api_generate_password(req: PasswordGenRequest):
    return generate_password(req)

@app.post("/simulate-attack")
def api_simulate_attack(req: AttackSimRequest):
    return simulate_attack(req)

@app.post("/backup-vault")
def api_backup_vault(req: BackupRequest):
    return backup_vault(req)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)