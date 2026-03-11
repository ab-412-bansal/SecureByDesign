#!/bin/bash
# Full local setup for Secure Password Vault Platform
set -e

# Build and run all containers
cd "$(dirname "$0")/.."
echo "Building and starting all services..."
docker-compose up --build -d

echo "---"
echo "Vaultwarden: http://localhost/vault/"
echo "Admin: http://localhost/vault/admin (see ADMIN_TOKEN)"
echo "Backend API: http://localhost/api/"
echo "Frontend Dashboard: http://localhost/"
echo "---"
