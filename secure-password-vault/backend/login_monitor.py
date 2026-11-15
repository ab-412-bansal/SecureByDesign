from typing import Dict, List

from fastapi import APIRouter

from schemas import LoginAlertRequest


router = APIRouter()
SECURITY_EVENTS: List[Dict] = []


@router.post("/login-alert")
def login_alert(req: LoginAlertRequest):
	suspicious = req.ip.startswith("10.") or req.device.strip().lower() == "unknown"
	event = req.model_dump()
	event["suspicious"] = suspicious
	SECURITY_EVENTS.append(event)
	return {"alert": suspicious, "event": event}
