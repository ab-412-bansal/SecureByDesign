#!/bin/bash
# Build and run all containers for Secure Password Vault Platform
cd "$(dirname "$0")/.."
docker-compose up --build -d
