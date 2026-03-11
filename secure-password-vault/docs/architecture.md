# Architecture Overview

## System Architecture Diagram

```
Client Layer
(Web UI + Bitwarden Browser Extension)

↓

Reverse Proxy
(Nginx)

↓

Vaultwarden Server
(Password Vault Core)

↓

Security Intelligence Layer
(Custom Modules)
    ├─ Password Strength Analyzer
    ├─ Breach Detection System
    ├─ Suspicious Login Detection
    ├─ Security Analytics Dashboard
    ├─ Password Generator
    ├─ Attack Simulation Engine
    └─ Encrypted Backup Manager

↓

Database Layer
(SQLite or PostgreSQL)
```

## Components
- **Vaultwarden**: Core password vault (Bitwarden-compatible)
- **Nginx**: Reverse proxy for secure routing
- **FastAPI Backend**: Security analytics and intelligence API
- **Frontend Dashboard**: Security analytics UI
- **Database**: Stores vault and analytics data

## Data Flow
1. User interacts with Web UI or Bitwarden extension
2. Requests routed via Nginx to Vaultwarden and Security API
3. Security modules analyze, monitor, and log events
4. Analytics and alerts shown in dashboard

---

See [security_model.md](security_model.md) for security details.
