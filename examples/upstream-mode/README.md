# Upstream Mode Example

This is the **recommended** deployment mode. oauth2-proxy handles OIDC authentication and forwards requests directly to the bridge as an upstream.

## Benefits

- Profile image sync from OIDC claims works automatically
- Simpler setup — no separate reverse proxy config needed between oauth2-proxy and the bridge
- All identity headers (`X-Forwarded-Email`, `X-Forwarded-User`, `X-Forwarded-Picture`) are set by oauth2-proxy

## Request Flow

```
Browser → Reverse Proxy (TLS) → oauth2-proxy → emby-web-oidc-bridge → Emby
```

## Setup

1. **Configure your OIDC provider** — create a client application and note the client ID, secret, and issuer URL.

2. **Edit `oauth2-proxy.cfg`** — replace all placeholder values:
   - `client_id` / `client_secret` — from your OIDC provider
   - `oidc_issuer_url` — your provider's issuer URL
   - `cookie_secret` — generate with: `python3 -c 'import os,base64; print(base64.urlsafe_b64encode(os.urandom(32)).decode())'`
   - `redirect_url` — your public URL + `/oauth2/callback`

3. **Edit `docker-compose.yml`** — replace:
   - `EMBY_API_KEY` — admin API key from Emby (Dashboard → API Keys)
   - `TEMPLATE_USER_NAME` — name of the Emby user to use as a template
   - `TRUSTED_PROXIES` — Docker network subnet (default `172.18.0.0/16` works for most setups)

4. **Create a template user in Emby** — this user's permissions and settings are copied to all new users created by the bridge.

5. **Start the stack:**
   ```bash
   docker compose up -d
   ```

6. **Put a TLS-terminating reverse proxy in front** (Caddy, Nginx, Traefik) pointing to `oauth2-proxy:4180`.

## Notes

- The bridge container runs as read-only with no-new-privileges for security.
- The `bridge-data` volume persists the SQLite database across restarts.
- Emby is not included in this compose file — point `EMBY_API_URL` to your existing Emby instance.
