import pytest

from attack_simulator import SUPPORTED_ATTACKS
from breach_detection import is_password_breached
from login_monitor import SECURITY_EVENTS
from password_generator import WORDS
from password_strength import analyze_password


def test_empty_password_is_critical():
    result = analyze_password("")

    assert result["strength_score"] == 0
    assert result["risk_level"] == "critical"
    assert result["estimated_crack_time"] == "instant"
    assert result["issues"] == ["No password set"]


def test_common_password_is_marked_breached_and_critical():
    result = analyze_password("password123")

    assert is_password_breached("PASSWORD123")
    assert result["is_breached"] is True
    assert result["risk_level"] == "critical"
    assert any("bundled common-password list" in issue for issue in result["issues"])


def test_long_mixed_password_receives_low_risk_score():
    result = analyze_password("Violet!Harbor_27Qx")

    assert result["length"] == 18
    assert result["has_upper"] is True
    assert result["has_lower"] is True
    assert result["has_digit"] is True
    assert result["has_symbol"] is True
    assert result["risk_level"] == "low"
    assert result["strength_score"] == 100


def test_breach_route_handles_password_email_and_clean_values(client):
    password_result = client.post("/check-breach", json={"password": "qwerty"})
    email_result = client.post("/check-breach", json={"email": "demo@PWNED.COM"})
    clean_result = client.post("/check-breach", json={"password": "a-never-listed-value"})

    assert password_result.json() == {"compromised": True, "type": "common_password"}
    assert email_result.json() == {"compromised": True, "type": "email_breached"}
    assert clean_result.json() == {"compromised": False, "type": None}


def test_generator_obeys_length_and_character_selection(client):
    response = client.post(
        "/generate-password",
        json={"length": 24, "use_lower": True, "use_upper": False, "use_numbers": False, "use_symbols": False},
    )
    result = response.json()

    assert response.status_code == 200
    assert len(result["password"]) == 24
    assert result["password"].islower()
    assert result["entropy"] > 0


def test_generator_passphrase_uses_known_words(client):
    response = client.post("/generate-password", json={"length": 18, "passphrase": True})
    words = response.json()["password"].split("-")

    assert response.status_code == 200
    assert len(words) == 3
    assert set(words) <= set(WORDS)


def test_generator_rejects_no_character_classes(client):
    response = client.post(
        "/generate-password",
        json={"length": 16, "use_lower": False, "use_upper": False, "use_numbers": False, "use_symbols": False},
    )

    assert response.status_code == 422
    assert "Select at least one" in response.json()["detail"]


@pytest.mark.parametrize("attack_type", sorted(SUPPORTED_ATTACKS))
def test_attack_simulator_accepts_each_documented_type(client, attack_type):
    response = client.post(
        "/simulate-attack", json={"password": "password123", "attack_type": attack_type}
    )

    assert response.status_code == 200
    assert response.json()["attack_type"] == attack_type
    assert response.json()["estimated_crack_time"]


def test_attack_simulator_rejects_unknown_type(client):
    response = client.post(
        "/simulate-attack", json={"password": "anything", "attack_type": "unknown"}
    )

    assert response.status_code == 422


def test_attack_simulator_estimate_increases_with_password_entropy(client):
    weak = client.post(
        "/simulate-attack", json={"password": "abcdefghij", "attack_type": "brute_force"}
    ).json()
    strong = client.post(
        "/simulate-attack", json={"password": "Violet!Harbor_27Qx", "attack_type": "brute_force"}
    ).json()

    assert strong["estimated_seconds_log10"] > weak["estimated_seconds_log10"]
    assert strong["effective_entropy_bits"] > weak["effective_entropy_bits"]


def test_online_rate_limit_is_slower_than_fast_offline_hash(client):
    password = "Violet!Harbor_27Qx"
    online = client.post(
        "/simulate-attack", json={"password": password, "attack_type": "online_rate_limited"}
    ).json()
    offline = client.post(
        "/simulate-attack", json={"password": password, "attack_type": "offline_fast_hash"}
    ).json()

    assert online["estimated_seconds_log10"] > offline["estimated_seconds_log10"]
    assert "10 attempts per minute" in online["model_note"]


def test_candidate_based_attack_reports_candidate_limit(client):
    response = client.post(
        "/simulate-attack", json={"password": "a-unique-test-string", "attack_type": "dictionary"}
    )

    assert response.status_code == 200
    assert response.json()["candidate_limit"] == 1_000_000
    assert "assumes the password is in" in response.json()["model_note"]


def test_credential_stuffing_only_reports_local_list_presence(client):
    found = client.post(
        "/simulate-attack", json={"password": "password123", "attack_type": "credential_stuffing"}
    ).json()
    not_found = client.post(
        "/simulate-attack", json={"password": "unique-demo-value", "attack_type": "credential_stuffing"}
    ).json()

    assert found["estimated_crack_time"] == "known local-list match"
    assert found["is_breached"] is True
    assert not_found["estimated_crack_time"] == "not estimated"
    assert not_found["estimated_seconds_log10"] is None


def test_attack_simulator_rejects_oversized_password(client):
    response = client.post(
        "/simulate-attack", json={"password": "a" * 257, "attack_type": "brute_force"}
    )

    assert response.status_code == 422


def test_login_alert_flags_suspicious_network_or_device_and_records_event(client):
    response = client.post(
        "/login-alert",
        json={"user_id": "demo", "ip": "10.0.0.4", "device": "Chrome", "time": "2026-01-01T10:00:00"},
    )

    assert response.status_code == 200
    assert response.json()["alert"] is True
    assert len(SECURITY_EVENTS) == 1
    assert SECURITY_EVENTS[0]["suspicious"] is True


def test_login_alert_accepts_normal_event(client):
    response = client.post(
        "/login-alert",
        json={"user_id": "demo", "ip": "192.0.2.10", "device": "Firefox", "time": "2026-01-01T10:00:00"},
    )

    assert response.status_code == 200
    assert response.json()["alert"] is False