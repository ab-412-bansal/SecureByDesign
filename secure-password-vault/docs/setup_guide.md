# Setup Guide

## Prerequisites
- Docker Desktop with the Linux container engine running
- Docker Compose v2 (`docker compose`)
- Bash (only needed to run the helper scripts)
- OpenSSL to create local development TLS files

## Quick Start
1. Clone the repository and change into the project directory.
2. Create the local TLS certificate files required by Nginx (do not commit these files):
   ```bash
   mkdir -p nginx/certs
   openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
     -keyout nginx/certs/key.pem \
     -out nginx/certs/cert.pem \
     -subj "/CN=localhost" \
     -addext "subjectAltName=DNS:localhost"
   ```
3. The demo admin token defaults to `changeme_admin_token`. To preserve this default, do not create a `.env` file. To override it, copy `.env.example` to `.env` (`cp .env.example .env` in Bash or `Copy-Item .env.example .env` in PowerShell) and set `ADMIN_TOKEN` to a long random value, for example one generated with `openssl rand -base64 48`.
4. Start all services from the project root:
   ```bash
   docker compose up --build -d
   ```
   Or use `bash scripts/full_setup.sh`; it checks for the TLS files first.
5. Check container status with `docker compose ps`.

## Access URLs
- Dashboard: <https://localhost/>
- Vaultwarden: <https://localhost:9443/>
- Vaultwarden admin: <https://localhost:9443/admin> (demo token: `changeme_admin_token`, unless overridden in `.env`)
- Backend API documentation: <https://localhost/api/docs>

The local certificate is self-signed, so browsers show a warning. This is for local development only.

## Configuration
- Vaultwarden settings are in the root `docker-compose.yml`; `ADMIN_TOKEN` defaults to the demo token and can be overridden in the ignored local `.env` file.
- Vaultwarden data is stored locally in `vaultwarden/vw-data/` and is excluded from Git.
- Do not expose this local demo or admin page to the internet.

## Stopping Services
```bash
docker compose down
```

This stops containers without deleting local Vaultwarden data or named database volumes.

---

For full architecture, see [architecture.md](architecture.md)
