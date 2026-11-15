#!/bin/bash
# Full local setup for Secure Password Vault Platform
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_DIR"

if [ ! -f nginx/certs/cert.pem ] || [ ! -f nginx/certs/key.pem ]; then
	echo "Missing local TLS files: nginx/certs/cert.pem and nginx/certs/key.pem" >&2
	echo "Generate a local certificate/key pair before starting Nginx." >&2
	exit 1
fi

echo "Building and starting all services..."
docker compose up --build -d

echo "---"
echo "Dashboard:          https://localhost/"
echo "Vaultwarden:        https://localhost:9443/"
echo "Vaultwarden admin:  https://localhost:9443/admin"
echo "Backend API docs:   https://localhost/api/docs"
echo "A browser warning is expected for a self-signed local certificate."
echo "---"
