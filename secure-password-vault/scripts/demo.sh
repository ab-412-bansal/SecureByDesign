#!/bin/bash
# Demo workflow for Secure Password Vault Platform
set -e

cd "$(dirname "$0")/.."
echo "1. Registering user via Vaultwarden UI..."
echo "2. Storing password..."
echo "3. Analyzing password strength via backend API..."
curl -X POST http://localhost/api/analyze-password -H "Content-Type: application/json" -d '{"password": "password123"}'
echo "4. Checking breach status..."
curl -X POST http://localhost/api/check-breach -H "Content-Type: application/json" -d '{"password": "password123"}'
echo "5. Simulating suspicious login..."
curl -X POST http://localhost/api/login-alert -H "Content-Type: application/json" -d '{"user_id": "1", "ip": "10.0.0.5", "device": "unknown", "time": "2026-03-11T11:00:00"}'
echo "6. Fetching updated security dashboard..."
curl http://localhost/api/security-score
echo "--- Demo complete ---"
