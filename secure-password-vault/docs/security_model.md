# Security Model

## Core Principles
- Zero-knowledge encryption (Vaultwarden)
- Encrypted backups (AES-256)
- Secure password generation
- Breach detection (k-anonymity, local datasets)
- Suspicious login monitoring
- Role-based access (admin panel)

## Threat Mitigations
- Brute force: Rate limiting, strong password policies
- Credential stuffing: Breach detection, login alerts
- Insider threats: Audit logs, admin controls
- Data loss: Encrypted backup/restore

## Data Security
- All secrets encrypted at rest (Vaultwarden)
- Analytics data stored securely (PostgreSQL/SQLite)
- Backups encrypted with user-supplied key

## Admin Controls
- User/organization management
- Security settings via admin panel

---

See [architecture.md](architecture.md) for system overview.
