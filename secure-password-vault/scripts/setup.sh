#!/bin/bash
# Setup script for Secure Password Vault Platform
set -e

# Step 1: Start Vaultwarden
cd "$(dirname "$0")/../vaultwarden"
echo "Starting Vaultwarden via Docker Compose..."
docker-compose up -d

echo "Vaultwarden should now be running at http://localhost:8080"
echo "Admin panel: http://localhost:8080/admin (see ADMIN_TOKEN in docker-compose.yml)"
