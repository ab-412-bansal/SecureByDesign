import math
import string
from typing import Any, Dict, List

from fastapi import APIRouter

from breach_detection import is_password_breached
from schemas import BatchAnalysisRequest, PasswordAnalysisRequest


router = APIRouter()


def analyze_password(password: str) -> Dict[str, Any]:
	if not password:
		return {
			"strength_score": 0, "estimated_crack_time": "instant",
			"risk_level": "critical", "entropy": 0, "issues": ["No password set"],
		}
	length = len(password)
	has_lower = any(char.islower() for char in password)
	has_upper = any(char.isupper() for char in password)
	has_digit = any(char.isdigit() for char in password)
	has_symbol = any(char in string.punctuation for char in password)
	charset = (26 if has_lower else 0) + (26 if has_upper else 0)
	charset += (10 if has_digit else 0) + (len(string.punctuation) if has_symbol else 0)
	entropy = length * math.log2(charset) if charset else 0
	patterns = ("password", "1234", "qwerty", "letmein", "admin", "welcome", "monkey", "dragon", "abc", "111", "000")
	found_pattern = any(pattern in password.lower() for pattern in patterns)
	breached = is_password_breached(password)
	issues: List[str] = []
	if length < 8:
		issues.append("Too short (minimum 8 characters)")
	elif length < 12:
		issues.append("Short password (12+ characters recommended)")
	if not has_upper:
		issues.append("No uppercase letters")
	if not has_lower:
		issues.append("No lowercase letters")
	if not has_digit:
		issues.append("No numbers")
	if not has_symbol:
		issues.append("No special characters")
	if found_pattern:
		issues.append("Contains a common pattern")
	if breached:
		issues.append("Found in the bundled common-password list")
	risk_level = (
		"critical" if breached or entropy < 28 else "high" if found_pattern or entropy < 40
		else "medium" if entropy < 60 else "low"
	)
	crack_time = (
		"instant" if entropy < 20 else "seconds" if entropy < 30 else
		"minutes" if entropy < 40 else "hours" if entropy < 50 else
		"days" if entropy < 60 else "years"
	)
	return {
		"strength_score": min(int(entropy), 100), "estimated_crack_time": crack_time,
		"risk_level": risk_level, "entropy": round(entropy, 2), "length": length,
		"has_upper": has_upper, "has_lower": has_lower, "has_digit": has_digit,
		"has_symbol": has_symbol, "is_breached": breached, "issues": issues,
	}


@router.post("/analyze-password")
def analyze_single_password(req: PasswordAnalysisRequest):
	return analyze_password(req.password)


@router.post("/analyze-vault")
def analyze_vault(req: BatchAnalysisRequest):
	password_counts: Dict[str, int] = {}
	for item in req.items:
		if item.password:
			password_counts[item.password] = password_counts.get(item.password, 0) + 1
	results = []
	scores = []
	weak_count = breached_count = reused_count = 0
	for item in req.items:
		if item.type != "Login" or not item.password:
			results.append({
				"id": item.id, "name": item.name, "username": item.username,
				"type": item.type, "skipped": True,
				"reason": "Not a login item or no password",
			})
			continue
		analysis = analyze_password(item.password)
		is_reused = password_counts[item.password] > 1
		if is_reused:
			analysis["issues"].append("Password reused across multiple accounts")
			if analysis["risk_level"] == "low":
				analysis["risk_level"] = "medium"
			reused_count += 1
		weak_count += int(analysis["risk_level"] in ("high", "critical"))
		breached_count += int(analysis["is_breached"])
		scores.append(analysis["strength_score"])
		results.append({
			"id": item.id, "name": item.name, "username": item.username,
			"type": item.type, "skipped": False, "is_reused": is_reused, **analysis,
		})
	total_logins = len(scores)
	average_score = round(sum(scores) / total_logins) if total_logins else 0
	penalty = 0 if not total_logins else (
		weak_count / total_logins * 40 + reused_count / total_logins * 30
		+ breached_count / total_logins * 30
	)
	return {
		"vault_score": max(0, round(100 - penalty)) if total_logins else 0,
		"average_score": average_score, "total": len(req.items),
		"total_logins": total_logins, "weak_count": weak_count,
		"breached_count": breached_count, "reused_count": reused_count, "items": results,
	}
