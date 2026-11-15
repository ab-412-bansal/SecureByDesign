#!/bin/bash
# Demo workflow for Secure Password Vault Platform
set -e

BASE_URL="${BASE_URL:-https://localhost}"
CURL=(curl --insecure --fail --silent --show-error)

echo "Backend health:"
"${CURL[@]}" "$BASE_URL/api/"
echo

echo "Password strength analysis:"
"${CURL[@]}" -X POST "$BASE_URL/api/analyze-password" \
	-H "Content-Type: application/json" -d '{"password":"password123"}'
echo

echo "Local common-password breach check:"
"${CURL[@]}" -X POST "$BASE_URL/api/check-breach" \
	-H "Content-Type: application/json" -d '{"password":"password123"}'
echo

echo "Suspicious login detection:"
"${CURL[@]}" -X POST "$BASE_URL/api/login-alert" \
	-H "Content-Type: application/json" \
	-d "{\"user_id\":\"demo\",\"ip\":\"10.0.0.5\",\"device\":\"unknown\",\"time\":\"$(date -Iseconds)\"}"
echo

echo "Password generation:"
"${CURL[@]}" -X POST "$BASE_URL/api/generate-password" \
	-H "Content-Type: application/json" -d '{"length":20}'
echo

echo "Demo checks completed. Dashboard: $BASE_URL/"
echo "Vaultwarden: https://localhost:9443/"
echo "Security score requires a Vaultwarden bearer token; log in through the dashboard first."
