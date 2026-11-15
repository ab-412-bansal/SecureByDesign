#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

if ! command -v python3 >/dev/null 2>&1 && ! command -v python >/dev/null 2>&1; then
  echo "Python is not available in this Bash environment." >&2
  echo "On Windows, run scripts/test.ps1 from PowerShell instead." >&2
  exit 127
fi

PYTHON="$(command -v python3 || command -v python)"

echo "Running backend tests..."
(
  cd "$PROJECT_DIR/backend"
  "$PYTHON" -m pytest tests -q
)

echo "Installing locked frontend dependencies and building..."
(
  cd "$PROJECT_DIR/frontend"
  npm ci
  npm audit --omit=dev
  npm run build
)

echo "Validating Docker Compose..."
docker compose -f "$PROJECT_DIR/docker-compose.yml" config -q

echo "Checking shell script syntax..."
for script in "$PROJECT_DIR"/scripts/*.sh; do
  bash -n "$script"
done

echo "All available project checks passed."