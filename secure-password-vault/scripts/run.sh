#!/bin/bash
# Run all services for Secure Password Vault Platform
set -e

# Start Vaultwarden
cd "$(dirname "$0")/../vaultwarden"
docker-compose up -d

# (Later: Start backend, frontend, nginx, db)

echo "All core services started."
