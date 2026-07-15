# Forward Auth Mode Example

Caddy (or Nginx/Traefik) routes traffic and uses oauth2-proxy only for authentication decisions via a subrequest to `/oauth2/auth`.

## Trade-offs

- More setup — configure header forwarding in your reverse proxy
- More flexible routing — the reverse proxy controls all traffic
- Fits existing multi-service Caddy/Nginx/Traefik deployments

## Request Flow

```
Browser → Caddy → (auth subrequest: oauth2-proxy) → emby-web-oidc-bridge → Emby
```

## oauth2-proxy + Caddy (this mode)

Identity resolution, username sync, and multi-subdomain cookies are documented in the main [Identity Resolution](../../README.md#identity-resolution), [Username Changes at the IdP](../../README.md#username-changes-at-the-idp), and [Multi-Subdomain SSO](../../README.md#multi-subdomain-sso) sections.

Settings required **in addition to** the shared ones in the main README:

| Setting | Purpose |
|---------|---------|
| `set_xauthrequest = true` | Expose `X-Auth-Request-*` headers on `/oauth2/auth` |
| `set_authorization_header = true` | Include ID token on the auth response |
| `pass_user_headers = true` | Include identity headers as fallback |
| `pass_access_token = true` | Include access token for userinfo profile image lookup |

Caddy must copy these to the bridge — see `copy_headers` in the `Caddyfile`.

All oauth2-proxy flags are enabled in the example `oauth2-proxy.cfg`. Optional multi-subdomain cookie settings are in the commented block at the bottom of that file.

## Setup

1. **Configure your OIDC provider** — create a client application and note the client ID, secret, and issuer URL.

2. **Edit `oauth2-proxy.cfg`** — replace placeholder values (`client_id`, `client_secret`, `oidc_issuer_url`, `cookie_secret`, `redirect_url`).

3. **Edit `Caddyfile`** — replace `emby.example.com` with your domain.

4. **Edit `docker-compose.yml`** — replace `EMBY_API_KEY`, `TEMPLATE_USER_NAME`, and `TRUSTED_PROXIES` if needed.

5. **Create a template user in Emby** — permissions and settings are copied to all bridge-provisioned users.

6. **Start the stack:** `docker compose up -d`

## Notes

- Caddy handles TLS automatically via Let's Encrypt.
- The bridge container runs as read-only with `no-new-privileges`.
- The `bridge-data` volume persists the SQLite database across restarts.
- Emby is not included — point `EMBY_API_URL` at your existing instance.
