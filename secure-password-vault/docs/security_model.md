# Security Model

## Implemented Behavior
- Vaultwarden provides its Bitwarden-compatible encrypted vault service.
- Password generation uses Python's cryptographically secure `secrets` module.
- Password analysis uses length, character classes, entropy estimates, and common-pattern heuristics.
- Breach checking compares against a short bundled common-password list; it does not use k-anonymity or a current breach corpus.
- Login alerts use a basic IP/device heuristic and are stored in memory only.
- Nginx provides local HTTPS using a self-signed certificate.

## Important Security Limitations
- The dashboard decrypts vault entries in the browser, then sends decrypted password fields to FastAPI for analysis. The backend therefore sees those submitted passwords.
- `/backup-vault` returns HTTP 501. No encrypted backup or restore exists in this project yet.
- The attack simulator estimates time; it does not execute dictionary, brute-force, or credential-stuffing attacks.
- No custom rate limiting or durable audit-event storage is implemented by this backend.
- Vaultwarden data is stored in its local SQLite directory; analytics and login alerts have no persistent database.
- The self-signed local TLS setup is not suitable for internet exposure or production use.

## Safe Demonstration Use
Use a disposable local Vaultwarden account and test-only credentials. Do not connect a production vault or submit real passwords to the analysis API. Replace the example admin token before local use, and never expose the default configuration publicly.

---

See [architecture.md](architecture.md) for system overview.
