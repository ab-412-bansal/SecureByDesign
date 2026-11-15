#!/bin/bash
# Setup script for Secure Password Vault Platform
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
exec bash "$SCRIPT_DIR/full_setup.sh"
