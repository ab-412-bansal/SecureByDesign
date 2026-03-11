#!/bin/bash
# Stop all containers
cd "$(dirname "$0")/.."
docker-compose down
