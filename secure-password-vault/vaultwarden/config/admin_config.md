# Vaultwarden Admin Configuration

The root `docker-compose.yml` uses the demo token `changeme_admin_token` unless `ADMIN_TOKEN` is overridden in `.env`. This default preserves the demo setup only; replace it before any non-demo use and never expose the admin endpoint publicly. Generate a replacement with `openssl rand -base64 48`.

With the local stack running, the admin page is <https://localhost:9443/admin>. The TLS certificate is self-signed for local development.

For upstream options and the recommended Argon2 PHC token format, see the [Vaultwarden admin-page guide](https://github.com/dani-garcia/vaultwarden/wiki/Enabling-admin-page).
