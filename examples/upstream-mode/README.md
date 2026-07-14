# Upstream Mode Example

This is the **recommended** deployment mode. oauth2-proxy handles OIDC authentication and forwards requests directly to the bridge as an upstream.

## Benefits

- Simpler setup — no reverse proxy config between oauth2-proxy and the bridge
- oauth2-proxy injects identity headers directly (`X-Forwarded-*`)

## Request Flow

```
Browser → Reverse Proxy (TLS) → oauth2-proxy → emby-web-oidc-bridge → Emby
```

## oauth2-proxy (this mode)

Identity resolution, username sync, and multi-subdomain cookies are documented in the main [Identity Resolution](../../README.md#identity-resolution), [Username Changes at the IdP](../../README.md#username-changes-at-the-idp), and [Multi-Subdomain SSO](../../README.md#multi-subdomain-sso) sections.

Settings required **in addition to** the shared ones in the main README:

| Setting | Purpose |
|---------|---------|
| `set_authorization_header = true` | Forward ID token as `Authorization` |
| `pass_user_headers = true` | Forward `X-Forwarded-*` identity headers |
| `pass_access_token = true` | Forward access token for userinfo profile image lookup |

All are enabled in the example `oauth2-proxy.cfg`. Optional multi-subdomain cookie settings are in the commented block at the bottom of that file.

## Setup

1. **Configure your OIDC provider** — create a client application and note the client ID, secret, and issuer URL.

2. **Edit `oauth2-proxy.cfg`** — replace placeholder values (`client_id`, `client_secret`, `oidc_issuer_url`, `cookie_secret`, `redirect_url`).

3. **Edit `docker-compose.yml`** — replace `EMBY_API_KEY`, `TEMPLATE_USER_NAME`, and `TRUSTED_PROXIES` if needed.

4. **Create a template user in Emby** — permissions and settings are copied to all bridge-provisioned users.

5. **Start the stack:** `docker compose up -d`

6. **Put a TLS-terminating reverse proxy in front** (Caddy, Nginx, Traefik) pointing to `oauth2-proxy:4180`.

## Notes

- The bridge container runs as read-only with `no-new-privileges`.
- The `bridge-data` volume persists the SQLite database across restarts.
- Emby is not included — point `EMBY_API_URL` at your existing instance.
