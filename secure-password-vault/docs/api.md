# Security API

The API is served behind Nginx at `https://localhost/api`. Interactive OpenAPI docs are at `https://localhost/api/docs`.

## Routes

| Method and route | Purpose and limitations |
|---|---|
| `POST /vault/login` | Exchanges email/master password for a Vaultwarden access token. |
| `GET /vault/sync` | Authenticated proxy to Vaultwarden sync. |
| `GET /vault/ciphers` | Authenticated proxy to vault ciphers. |
| `GET /security-score` | Authenticated, metadata-based demo score; not the dashboard's decrypted-item analysis. |
| `POST /analyze-password` | Estimates password entropy and risk using heuristics. |
| `POST /analyze-vault` | Accepts decrypted login items and returns strength/reuse analysis. Password values are sent to the backend. |
| `POST /check-breach` | Checks a small local common-password list and a demo `@pwned.com` email suffix; no external breach lookup. |
| `POST /login-alert` | Applies a simple heuristic (IP begins `10.` or device is `unknown`); events are in memory only. |
| `POST /generate-password` | Generates a random password or passphrase. |
| `POST /simulate-attack` | Estimates guesses/time for `dictionary`, `rule_based`, `mask`, `brute_force`, `offline_fast_hash`, `offline_slow_hash`, `online_rate_limited`, and `credential_stuffing`. It executes no attack; rates and candidate limits are illustrative assumptions. The credential-stuffing option only checks the bundled demo password list. |
| `POST /backup-vault` | Returns HTTP 501; backup is not implemented. |

The API docs show required request models and authentication. Do not submit real vault passwords to this demo service.
