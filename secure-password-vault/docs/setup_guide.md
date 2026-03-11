# Setup Guide

## Prerequisites
- Docker & Docker Compose
- Bash (for setup scripts)

## Quick Start
1. Clone the repository
2. Run the setup script:
   ```bash
   cd scripts
   bash setup.sh
   ```
3. Access Vaultwarden:
   - Web: http://localhost:8080
   - Admin: http://localhost:8080/admin (see ADMIN_TOKEN in docker-compose.yml)

## Configuration
- Vaultwarden admin token is set in `vaultwarden/docker-compose.yml`
- Data is stored in `vaultwarden/vw-data/`

## Stopping Services
```bash
cd vaultwarden
docker-compose down
```

---

For full architecture, see [architecture.md](architecture.md)
