
# SecureByDesign

**One place to manage your logins and important account details, with security analysis built around the vault.**

SecureByDesign brings a self-hosted Vaultwarden password vault together with a security dashboard. Store and organize login items in the vault, then review password risks, reuse, and security findings in one workflow. The project is designed to demonstrate how password management and practical security insights can work side by side.

## Explore the Dashboard

- **Overview:** See the vault security score and counts for weak, breached, and reused login passwords.
- **Security Report:** Review individual login items, strength estimates, detected issues, and password details.
- **Tools:** Analyze a password, generate a strong password, and compare estimated attack scenarios.
- **Vault access:** Sign in with your Vaultwarden account; the dashboard syncs the encrypted vault and prepares login items for analysis.

## Security Analysis Tools

- **Password strength:** Entropy estimate, length and character-class checks, common-pattern warnings, risk level, and estimated crack time.
- **Reuse analysis:** Detect identical passwords used by multiple login items in the analyzed vault.
- **Breach-list check:** Compare passwords against the bundled demo list of commonly exposed passwords.
- **Password generator:** Generate random passwords or memorable passphrases.
- **Attack estimator:** Compare dictionary, rule-based, mask, brute-force, offline-hash, online-rate-limited, and credential-stuffing exposure scenarios. It estimates; it does not run attacks.
- **Login alert demo:** Submit a sample login event and see the suspicious-login heuristic in action.

## How It Fits Together

```text
Browser dashboard ── HTTPS ── Nginx ── React UI
		├─────── FastAPI analysis API
		└─────── Vaultwarden ── local SQLite vault
```

Docker Compose runs Vaultwarden, the React dashboard, FastAPI, PostgreSQL, and Nginx. Vaultwarden owns and persists vault data; the dashboard and API provide the analysis experience.

## Run Locally

Requirements: Docker Desktop with Linux containers, Docker Compose v2, and local TLS certificate files. See the [setup guide](secure-password-vault/docs/setup_guide.md) for the full steps.

From `secure-password-vault/`, start the stack:

```powershell
docker compose up --build -d
```

Open:

- **Dashboard:** <https://localhost/>
- **Vaultwarden:** <https://localhost:9443/>
- **Vaultwarden admin:** <https://localhost:9443/admin> (demo token: `changeme_admin_token`)
- **API explorer:** <https://localhost/api/docs>

The local HTTPS certificate is self-signed, so your browser will show a development-certificate warning.

## Project Checks

From a PowerShell terminal in `secure-password-vault/`:

```powershell
python -m pip install -r backend/requirements-test.txt
.\scripts\test.ps1
```

The test runner executes the backend tests, frontend build and production-dependency audit, Compose validation, and shell syntax checks.

## Project Guides

- [Setup and access](secure-password-vault/docs/setup_guide.md)
- [API endpoints](secure-password-vault/docs/api.md)
- [Architecture](secure-password-vault/docs/architecture.md)
- [Security model](secure-password-vault/docs/security_model.md)
- [Threat model](secure-password-vault/docs/threat_model.md)
- [AI-assisted development and contributions](secure-password-vault/docs/ai_assisted_development.md)

> **Demo use:** The bundled breach list and login alerts are local demo features, attack results are estimates, and vault analysis sends decrypted login fields to the analysis API. Use a disposable vault and test credentials, not real account passwords. Backup/restore is not implemented yet.
