from fastapi import APIRouter

from schemas import BreachCheckRequest


router = APIRouter()
BREACHED_PASSWORDS = {
	"password", "123456", "qwerty", "letmein", "admin", "welcome",
	"monkey", "dragon", "master", "123456789", "password1", "12345678",
	"abc123", "password123", "iloveyou", "1234567", "sunshine", "princess",
	"football", "charlie", "donald", "password2", "qwerty123", "1q2w3e4r",
}


def is_password_breached(password: str) -> bool:
	return password.lower() in BREACHED_PASSWORDS


@router.post("/check-breach")
def check_breach(req: BreachCheckRequest):
	password_breached = bool(req.password and is_password_breached(req.password))
	email_breached = bool(req.email and req.email.lower().endswith("@pwned.com"))
	return {
		"compromised": password_breached or email_breached,
		"type": "common_password" if password_breached else "email_breached" if email_breached else None,
	}
