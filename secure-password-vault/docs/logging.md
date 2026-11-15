# Logging and Error Handling

## Backend (FastAPI)
- Uvicorn emits access/startup logs to container stdout/stderr.
- Login-alert events are stored in process memory and are lost when the backend restarts.
- No durable audit log or event persistence is currently implemented.
- API errors use HTTP responses; do not enable logging of passwords, bearer tokens, or decrypted vault contents.

## Vaultwarden
- Logs to stdout (see Docker logs)

## Frontend
- Errors shown in dashboard UI

---

Inspect logs with `docker compose logs backend` and `docker compose logs vaultwarden`. The API does not currently log every security operation as an audit event.
