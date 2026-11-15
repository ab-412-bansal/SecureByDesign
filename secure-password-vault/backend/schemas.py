from typing import List, Literal, Optional

from pydantic import BaseModel, Field


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
    length: int = Field(default=16, ge=8, le=128)
    use_symbols: bool = True
    use_numbers: bool = True
    use_upper: bool = True
    use_lower: bool = True
    passphrase: bool = False
    site: Optional[str] = None


class AttackSimRequest(BaseModel):
    password: str = Field(min_length=1, max_length=256)
    attack_type: Literal[
        "dictionary",
        "rule_based",
        "mask",
        "brute_force",
        "offline_fast_hash",
        "offline_slow_hash",
        "online_rate_limited",
        "credential_stuffing",
    ]


class BackupRequest(BaseModel):
    key: str
    schedule: Optional[str] = None