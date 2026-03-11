# Demo Workflow Script

1. **User registers**
   - Register via Vaultwarden web UI or Bitwarden extension
2. **Password stored**
   - Add a new password entry
3. **Password strength analyzed**
   - Backend analyzes password via `/analyze-password` endpoint
4. **Breach scan performed**
   - Backend checks password/email via `/check-breach`
5. **Suspicious login detected**
   - Login from new device/IP triggers `/login-alert` and logs event
6. **Security dashboard updated**
   - Dashboard displays updated analytics and alerts

---

*Run all services via Docker Compose. See [setup_guide.md](setup_guide.md) for details.*
