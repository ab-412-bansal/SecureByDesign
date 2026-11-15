
# SecureByDesign

SecureByDesign is a local demonstration project combining Vaultwarden with a React dashboard and a FastAPI security-analysis API. It is intended for learning and demonstration, not production password management.

## What Works

- Vaultwarden provides the encrypted password-vault service.
- The dashboard can log in to Vaultwarden and analyze decrypted vault login items.
- Password strength estimates and vault reuse analysis are available through the backend.
- The breach check compares passwords to a small bundled list of common passwords; it does not query a breach service or a full breach corpus.
- Password generation uses Python's `secrets` module.
- Login-alert and attack-estimate endpoints are demonstrations; the attack simulator does not perform cracking attempts.
- Nginx provides local HTTPS routing using a self-signed certificate.

## Important Limitations

- Vault analysis sends decrypted password values from the browser to the FastAPI backend. Do not use real or sensitive vault credentials with this demo.
- Login events are stored in memory and disappear when the backend restarts.
- Vaultwarden stores its data in local SQLite files under `secure-password-vault/vaultwarden/vw-data/`. PostgreSQL is included in Compose but the backend does not currently use it; analytics are not persisted.
- `/api/backup-vault` returns HTTP 501. Encrypted backup and restore are not implemented.
- The security score is a simple demonstration metric, not a validated risk rating.
- Local TLS certificates are self-signed. This setup is not production-ready or intended to be exposed to the internet.

## Start Locally

See [the setup guide](secure-password-vault/docs/setup_guide.md). In brief, create local TLS certificate files under `secure-password-vault/nginx/certs/`, then run from the project directory:

```bash
docker compose up --build -d
```

Access:

- Dashboard: <https://localhost/>
- Vaultwarden: <https://localhost:9443/>
- API documentation: <https://localhost/api/docs>

The Vaultwarden admin page is at <https://localhost:9443/admin>; the local demo token defaults to `changeme_admin_token`. Set `ADMIN_TOKEN` in the ignored `.env` file to override it. Do not expose this default publicly. Accept the browser warning for the self-signed certificate. See [the setup guide](secure-password-vault/docs/setup_guide.md), [API guide](secure-password-vault/docs/api.md), [architecture](secure-password-vault/docs/architecture.md), and [threat model](secure-password-vault/docs/threat_model.md) for details.

## Run Tests and Checks

Install the backend test dependencies, then run the appropriate verification script from the project directory.

PowerShell on Windows:

```powershell
cd C:\SecureByDesign\secure-password-vault
python -m pip install -r backend/requirements-test.txt
.\scripts\test.ps1
```

Bash on Linux/macOS (or WSL with Python installed in WSL):

```bash
cd secure-password-vault
python3 -m pip install -r backend/requirements-test.txt
bash scripts/test.sh
```

Both scripts run backend pytest tests, install the locked frontend dependencies, audit production npm dependencies, build the frontend, validate Docker Compose, and syntax-check the shell scripts. They do not need live Vaultwarden credentials.

## Repository Layout

- Project source and Compose configuration: [secure-password-vault/](secure-password-vault/)
- Documentation: [secure-password-vault/docs/](secure-password-vault/docs/)
- Workspace ignore rules: [`.gitignore`](.gitignore)

No project license file is currently included. Review dependency and upstream licenses before redistribution.
