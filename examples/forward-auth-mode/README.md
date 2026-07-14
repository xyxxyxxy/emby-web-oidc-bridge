# Forward Auth Mode Example

This setup uses a reverse proxy (Caddy) with oauth2-proxy as a forward_auth provider. The reverse proxy handles routing and uses oauth2-proxy only for authentication decisions.

## Trade-offs

- Slightly more complex setup — requires configuring header forwarding in Caddy
- More flexible routing — your reverse proxy controls all traffic
- Works well if you already have Caddy/Nginx/Traefik managing multiple services
- Profile image sync on session establishment via JWT ID token (`set_authorization_header = true`)

## How Identity is Extracted

The bridge extracts user identity from the JWT ID token forwarded via the `Authorization` header. Caddy copies this header from the oauth2-proxy auth response.

| Claim | Purpose |
|-------|---------|
| `sub` | Stable user identifier (required) — links OIDC identity to Emby account |
| `preferred_username` | Emby username (required) |
| `picture` | Profile image URL synced to Emby on session establishment |
| `email` | Optional — used in establishment logs only |

The bridge requires `preferred_username`. It does not use `name` or `email` as username fallbacks.

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
- Profile image sync on session establishment via JWT ID token (the `Authorization` header carries the ID token with the `picture` claim).
