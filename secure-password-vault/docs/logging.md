# Logging and Error Handling

## Backend (FastAPI)
- All endpoints log requests and errors
- Security events are logged in-memory (extend to DB for production)
- Error responses use HTTPException with details

## Vaultwarden
- Logs to stdout (see Docker logs)

## Frontend
- Errors shown in dashboard UI

---

For more, see backend/main.py and Vaultwarden documentation.
