# Test Data for Demo

These are examples only. Use a disposable account and never reuse real credentials.

## Passwords
- password123 (weak, breached)
- S3cure!Passw0rd (strong)
- qwerty (weak, breached)

## Logins
- IP: 1.2.3.4, Device: Chrome, Time: 2026-03-11T10:00:00
- IP: 10.0.0.5, Device: unknown, Time: 2026-03-11T11:00:00 (suspicious)

---

The `/check-breach` endpoint recognizes some common passwords from a bundled local list. It does not query real breach services. Login alert examples trigger a simple demo heuristic, not geolocation or device fingerprint analysis.
