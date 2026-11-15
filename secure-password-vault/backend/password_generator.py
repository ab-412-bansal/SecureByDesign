import math
import secrets
import string

from fastapi import APIRouter, HTTPException

from password_strength import analyze_password
from schemas import PasswordGenRequest


router = APIRouter()
WORDS = [
    "correct", "horse", "battery", "staple", "random", "secure", "vault",
    "cloud", "tiger", "river", "storm", "pixel", "lunar", "frost", "amber",
]


@router.post("/generate-password")
def generate_password(req: PasswordGenRequest):
    if req.passphrase:
        word_count = max(3, min(8, req.length // 6))
        password = "-".join(secrets.choice(WORDS) for _ in range(word_count))
        entropy = word_count * math.log2(len(WORDS))
    else:
        alphabet = ""
        if req.use_lower:
            alphabet += string.ascii_lowercase
        if req.use_upper:
            alphabet += string.ascii_uppercase
        if req.use_numbers:
            alphabet += string.digits
        if req.use_symbols:
            alphabet += string.punctuation
        if not alphabet:
            raise HTTPException(status_code=422, detail="Select at least one character class")
        password = "".join(secrets.choice(alphabet) for _ in range(req.length))
        entropy = req.length * math.log2(len(alphabet))
    return {"password": password, "entropy": round(entropy, 2), **analyze_password(password)}