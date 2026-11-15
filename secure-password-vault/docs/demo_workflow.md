# Demo Workflow Script

1. Start the stack and open `https://localhost:9443/`; create a **disposable test account**.
2. Add test-only login items in Vaultwarden.
3. Open `https://localhost/`, sign in with the test account, and inspect the analysis report.
4. Submit test strings to `/api/analyze-password` and `/api/check-breach` in the API docs. The breach route only checks a small local common-password list.
5. Submit a test event to `/api/login-alert` using IP `10.0.0.5` or device `unknown` to trigger its demo heuristic.
6. Run `bash scripts/demo.sh` for API health, analysis, breach-list, login-alert, and password-generator examples.

The demo script does not register users, modify the vault, fetch authenticated security scores, or demonstrate backups. Vault analysis sends decrypted item fields to the backend; do not use real credentials.

---

See [setup_guide.md](setup_guide.md) for startup instructions. Backup/restore is not implemented.
