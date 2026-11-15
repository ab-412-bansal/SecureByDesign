import math
from typing import Any, Dict, Optional

from fastapi import APIRouter

from breach_detection import BREACHED_PASSWORDS, is_password_breached
from password_strength import analyze_password
from schemas import AttackSimRequest


router = APIRouter()
ATTACK_PROFILES: Dict[str, Dict[str, Any]] = {
	"dictionary": {
		"guesses_per_second": 1e8,
		"candidate_limit": 1e6,
		"note": "Candidate-list estimate; assumes the password is in the modeled list.",
	},
	"rule_based": {
		"guesses_per_second": 1e8,
		"candidate_limit": 1e8,
		"note": "Candidate-list estimate; assumes transformations include the password.",
	},
	"mask": {
		"guesses_per_second": 1e8,
		"candidate_limit": 1e10,
		"note": "Candidate-list estimate; assumes the pattern is known and includes the password.",
	},
	"brute_force": {
		"guesses_per_second": 1e10,
		"candidate_limit": None,
		"note": "Uniform-random search-space estimate at an illustrative offline rate.",
	},
	"offline_fast_hash": {
		"guesses_per_second": 1e10,
		"candidate_limit": None,
		"note": "Illustrative fast-hash offline rate; real rates depend on hash and hardware.",
	},
	"offline_slow_hash": {
		"guesses_per_second": 1e3,
		"candidate_limit": None,
		"note": "Illustrative slow-hash offline rate; real rates depend on hash and hardware.",
	},
	"online_rate_limited": {
		"guesses_per_second": 10 / 60,
		"candidate_limit": None,
		"note": "Assumes a strict limit of 10 attempts per minute; actual controls vary.",
	},
}
SUPPORTED_ATTACKS = set(ATTACK_PROFILES) | {"credential_stuffing"}
_LOG10_SECONDS_PER_YEAR = math.log10(365.25 * 24 * 60 * 60)


def _format_scientific(log10_value: float) -> str:
	if log10_value < -2:
		return "<0.01"
	exponent = math.floor(log10_value)
	mantissa = 10 ** (log10_value - exponent)
	return f"{mantissa:.2f}e{exponent:+d}"


def _format_duration(log10_seconds: float) -> str:
	if log10_seconds < 0:
		return "<1 second"
	if log10_seconds < math.log10(60):
		return f"{10 ** log10_seconds:.2g} seconds"
	if log10_seconds < math.log10(3600):
		return f"{10 ** (log10_seconds - math.log10(60)):.2g} minutes"
	if log10_seconds < math.log10(86400):
		return f"{10 ** (log10_seconds - math.log10(3600)):.2g} hours"
	if log10_seconds < _LOG10_SECONDS_PER_YEAR:
		return f"{10 ** (log10_seconds - math.log10(86400)):.2g} days"
	log10_years = log10_seconds - _LOG10_SECONDS_PER_YEAR
	if log10_years >= 6:
		return f"~10^{math.floor(log10_years)} years"
	return f"{10 ** log10_years:.2g} years"


def estimate_attack(password: str, attack_type: str) -> Dict[str, Any]:
	analysis = analyze_password(password)
	entropy_bits = float(analysis["entropy"])
	if analysis["is_breached"]:
		effective_entropy_bits = 0.0
	elif "Contains a common pattern" in analysis["issues"]:
		effective_entropy_bits = max(0.0, entropy_bits - 12.0)
	else:
		effective_entropy_bits = entropy_bits

	if attack_type == "credential_stuffing":
		known_match = is_password_breached(password)
		return {
			"attack_type": attack_type,
			"estimated_crack_time": "known local-list match" if known_match else "not estimated",
			"estimated_guesses": "1 (local-list match)" if known_match else "not estimated",
			"estimated_seconds_log10": None,
			"entropy_bits": round(entropy_bits, 2),
			"effective_entropy_bits": round(effective_entropy_bits, 2),
			"risk_level": "critical" if known_match else "unknown",
			"is_breached": known_match,
			"candidate_limit": len(BREACHED_PASSWORDS),
			"guesses_per_second": None,
			"model_note": "Checks only the bundled demo password list; it performs no credential attempts and is not a breach lookup.",
		}

	profile = ATTACK_PROFILES[attack_type]
	candidate_limit: Optional[int] = profile["candidate_limit"]
	if candidate_limit is None:
		log2_expected_guesses = max(0.0, effective_entropy_bits - 1.0)
	else:
		log2_candidate_count = min(effective_entropy_bits, math.log2(candidate_limit))
		log2_expected_guesses = max(0.0, log2_candidate_count - 1.0)

	log10_expected_guesses = log2_expected_guesses * math.log10(2)
	log10_seconds = log10_expected_guesses - math.log10(profile["guesses_per_second"])
	risk_level = (
		"critical" if analysis["is_breached"] or effective_entropy_bits < 28 else
		"high" if effective_entropy_bits < 40 else
		"medium" if effective_entropy_bits < 60 else "low"
	)
	return {
		"attack_type": attack_type,
		"estimated_crack_time": _format_duration(log10_seconds),
		"estimated_guesses": _format_scientific(log10_expected_guesses),
		"estimated_seconds_log10": round(log10_seconds, 3),
		"entropy_bits": round(entropy_bits, 2),
		"effective_entropy_bits": round(effective_entropy_bits, 2),
		"risk_level": risk_level,
		"is_breached": analysis["is_breached"],
		"candidate_limit": candidate_limit,
		"guesses_per_second": profile["guesses_per_second"],
		"model_note": profile["note"] + " Estimates are illustrative and no attack is executed.",
	}


@router.post("/simulate-attack")
def simulate_attack(req: AttackSimRequest):
	return estimate_attack(req.password, req.attack_type)
