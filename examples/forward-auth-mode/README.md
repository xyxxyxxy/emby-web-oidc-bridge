# Forward Auth Mode Example

This setup uses a reverse proxy (Caddy) with oauth2-proxy as a forward_auth provider. The reverse proxy handles routing and uses oauth2-proxy only for authentication decisions.

## Trade-offs

- **No profile image sync** — oauth2-proxy's `set_xauthrequest` does not include the picture claim in the auth response
- More flexible routing — your reverse proxy controls all traffic
- Works well if you already have Caddy/Nginx/Traefik managing multiple services

## Request Flow

```
Browser → Caddy → (auth subrequest: oauth2-proxy) → emby-web-oidc-bridge → Emby
```

## Setup

1. **Configure your OIDC provider** — create a client application and note the client ID, secret, and issuer URL.

2. **Edit `oauth2-proxy.cfg`** — replace all placeholder values:
   - `client_id` / `client_secret` — from your OIDC provider
   - `oidc_issuer_url` — your provider's issuer URL
   - `cookie_secret` — generate with: `python3 -c 'import os,base64; print(base64.urlsafe_b64encode(os.urandom(32)).decode())'`
   - `redirect_url` — your public URL + `/oauth2/callback`

3. **Edit `Caddyfile`** — replace `emby.example.com` with your actual domain.

4. **Edit `docker-compose.yml`** — replace:
   - `EMBY_API_KEY` — admin API key from Emby (Dashboard → API Keys)
   - `TEMPLATE_USER_NAME` — name of the Emby user to use as a template
   - `TRUSTED_PROXIES` — Docker network subnet (default `172.18.0.0/16` works for most setups)

5. **Create a template user in Emby** — this user's permissions and settings are copied to all new users created by the bridge.

6. **Start the stack:**
   ```bash
   docker compose up -d
   ```

## Notes

- Caddy handles TLS automatically via Let's Encrypt.
- The bridge container runs as read-only with no-new-privileges for security.
- The `bridge-data` volume persists the SQLite database across restarts.
- Emby is not included in this compose file — point `EMBY_API_URL` to your existing Emby instance.
- Profile image sync is **not available** in this mode. Use [upstream mode](../upstream-mode/) if you need it.
