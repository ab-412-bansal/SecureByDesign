# Threat Model

## Assets and Data Flows
- Vaultwarden account and vault data (persisted by Vaultwarden in local SQLite files)
- Master password and access token submitted during dashboard login
- Decrypted vault item fields sent from the browser to FastAPI for analysis
- In-memory demo login-alert events

## Threats
- Brute force and credential stuffing
- Phishing and social engineering
- Insider threats
- Data breaches (vault, analytics, backups)
- Malicious admin actions

## Current Controls and Gaps
- Vault encryption is provided by Vaultwarden/Bitwarden-compatible clients; this project does not independently validate that implementation.
- A local self-signed TLS certificate encrypts connections to the local reverse proxy, but is not a trusted public certificate.
- Password checks use a small bundled list and heuristics, not a comprehensive or k-anonymity breach service.
- Login alert detection is a basic demo heuristic; events are volatile and not a durable audit trail.
- Backups, restore, persistent analytics, and custom rate limiting are not implemented.
- Decrypted item values are visible to the backend during analysis; do not use real credentials in the demo.

---

See [security_model.md](security_model.md) for more details.
