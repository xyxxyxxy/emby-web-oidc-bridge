# emby-web-oidc-bridge

A lightweight Go service that enables OIDC single sign-on for Emby's web interface via [oauth2-proxy](https://oauth2-proxy.github.io/oauth2-proxy/).

## Architecture

```
┌─────────┐     ┌──────────────┐     ┌─────────────┐     ┌──────┐
│ Browser │────▶│ oauth2-proxy │────▶│   Bridge    │────▶│ Emby │
└─────────┘     └──────────────┘     └─────────────┘     └──────┘
                                            │
                                            ▼
                                       ┌────────┐
                                       │ SQLite │
                                       └────────┘
```

## Motivation

Emby doesn't support SSO or OpenID Connect natively, and the [feature request](https://emby.media/community/topic/114493-sso-openid/) doesn't look like it's going anywhere soon. Since a full SSO solution across all Emby clients (TV apps, mobile, etc.) is non-trivial, this bridge takes a pragmatic approach: it enables OIDC authentication for the web interface, and provides generated credentials for TV/mobile apps where OAuth flows aren't supported.

## How It Works

```
Browser → oauth2-proxy → emby-web-oidc-bridge → Emby Server
```

1. **oauth2-proxy** handles the actual OIDC authentication with your identity provider
2. **The Bridge** reads the OIDC identity from forwarded headers and the JWT ID token, auto-provisions users in Emby, authenticates them, and proxies requests through
3. **Emby** sees a normal authenticated session

Users are identified by their OIDC `sub` (subject) claim — a stable, unique identifier that never changes. The Emby account username is derived from OIDC claims in this order: `preferred_username` > `name` > `email`. If a username/email changes in the OIDC provider, the bridge automatically syncs the change to Emby without creating a duplicate account.

Users are automatically provisioned on first login with settings copied from a configurable template user. A simple account page (`/account`) shows generated credentials for use in TV/mobile apps.

## Features

- Automatic user provisioning from OIDC identity
- Seamless web login (no username/password entry)
- Template-based user creation (inherit permissions from a configured user)
- Profile image sync from OIDC claims (both modes, see [Profile Image Sync](#profile-image-sync))
- Account page showing credentials for TV/mobile apps
- Trusted proxy IP validation
- Username derived from `preferred_username` > `name` > `email` with uniqueness fallback
- Automatic sync of username/email changes from OIDC provider to Emby

## Security Model

- Emby is expected to be hosted behind oauth2-proxy (or a VPN for direct access)
- The bridge only accepts forwarded headers from IPs in the `TRUSTED_PROXIES` list
- The generated password is not security-critical — it exists solely for TV/mobile app authentication where OAuth flows aren't supported
- Passwords are 8 lowercase alphanumeric characters, optimized for easy entry on TV remotes
- Passwords are stored in plaintext in SQLite (by design — they're not secrets)

## Policy Management

The bridge enforces minimal policy overrides to function correctly, while leaving all other settings under admin control.

**On user creation:** The template user's full policy is applied (library access, parental controls, IsHidden, etc.).

**On every login:** The bridge fetches the user's current policy from Emby and only enforces two fields:

| Policy Field | Enforced Value | Reason |
|-------------|-------|--------|
| `IsDisabled` | `false` | Access is managed via the OIDC provider. If a user can authenticate through oauth2-proxy, they should have access. Revoke access at the identity provider, not in Emby. |
| `EnableUserPreferenceAccess` | `false` | Prevents users from changing their password or profile image in Emby, since these are managed by the bridge. |

All other policy fields (library access, parental controls, `IsHidden`, remote access, etc.) are fully controlled by the admin per-user after creation. The bridge will not overwrite them.

**Important:** If you disable a user in Emby's admin UI, the bridge will re-enable them on their next login. To revoke access, remove the user from your OIDC provider or oauth2-proxy's allowed list instead.

## Quick Start

Full example configurations with docker-compose, oauth2-proxy config, and setup instructions are available in the [`examples/`](examples/) folder:

- **[`examples/upstream-mode/`](examples/upstream-mode/)** — Recommended. oauth2-proxy forwards directly to the bridge.
- **[`examples/forward-auth-mode/`](examples/forward-auth-mode/)** — Caddy/Nginx forward_auth pattern. Profile image sync via JWT.

Minimal standalone configuration:

```yaml
services:
  emby-bridge:
    image: ghcr.io/xyxxyxxy/emby-web-oidc-bridge:latest
    environment:
      EMBY_API_URL: http://emby:8096/emby
      EMBY_API_KEY: your-emby-api-key
      TEMPLATE_USER_NAME: template
      TRUSTED_PROXIES: "172.18.0.0/16"
      DATABASE_PATH: /data/users.db
    volumes:
      - bridge-data:/data
    read_only: true
    security_opt:
      - no-new-privileges:true

volumes:
  bridge-data:
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `EMBY_API_URL` | Yes | — | Emby server URL (e.g., `http://emby:8096/emby`) |
| `EMBY_API_KEY` | Yes | — | Emby admin API key |
| `TEMPLATE_USER_NAME` | Yes | — | Emby user whose settings are copied to new users |
| `TRUSTED_PROXIES` | Yes | — | Comma-separated IPs/CIDRs allowed to set forwarded headers |
| `BRIDGE_PORT` | No | `8080` | Port the bridge listens on |
| `DATABASE_PATH` | No | `/data/users.db` | Path to the SQLite database file |
| `OIDC_ISSUER_URL` | No | — | OIDC issuer URL (enables profile image sync via userinfo/JWT) |

## oauth2-proxy Configuration

The bridge accepts user identity from either `X-Forwarded-Email` or `X-Auth-Request-Email` headers. How these get set depends on your deployment topology.

### Option A: Upstream mode (recommended)

oauth2-proxy handles auth and forwards requests directly to the bridge. No separate reverse proxy needed between oauth2-proxy and the bridge.

```
Browser → Reverse Proxy → oauth2-proxy → bridge → Emby
```

**oauth2-proxy config:**

```ini
upstreams = ["http://emby-bridge:8080"]
pass_user_headers = true
set_authorization_header = true
```

`pass_user_headers = true` makes oauth2-proxy set `X-Forwarded-Email`, `X-Forwarded-User`, and `X-Forwarded-Picture` on requests forwarded to the upstream. `set_authorization_header = true` forwards the ID token as `Authorization: Bearer <token>`, which the bridge decodes to extract `sub`, `preferred_username`, `name`, and `picture` claims.

Set `TRUSTED_PROXIES` in the bridge to the IP/subnet that oauth2-proxy connects from.

See [`examples/upstream-mode/`](examples/upstream-mode/) for a complete setup.

### Option B: Forward auth mode (Caddy, Nginx, Traefik)

Your reverse proxy handles routing and uses oauth2-proxy only for auth decisions via a subrequest. The reverse proxy then forwards the request to the bridge with the identity headers copied from the auth response.

```
Browser → Caddy → (auth check: oauth2-proxy) → bridge → Emby
```

**oauth2-proxy config:**

```ini
set_xauthrequest = true
set_authorization_header = true
```

This makes oauth2-proxy return `X-Auth-Request-Email`, `X-Auth-Request-User`, and the ID token as `Authorization` header in the `/oauth2/auth` response.

**Caddy example:**

```caddyfile
emby.example.com {
    handle /oauth2/* {
        reverse_proxy oauth2-proxy:4180
    }

    handle {
        forward_auth oauth2-proxy:4180 {
            uri /oauth2/auth
            copy_headers X-Auth-Request-User X-Auth-Request-Email X-Auth-Request-Preferred-Username Authorization

            @error status 401
            handle_response @error {
                redir * /oauth2/sign_in?rd={scheme}://{host}{uri}
            }
        }

        reverse_proxy emby-bridge:8080
    }
}
```

Set `TRUSTED_PROXIES` in the bridge to the IP/subnet that Caddy connects from.

See [`examples/forward-auth-mode/`](examples/forward-auth-mode/) for a complete setup.

### Header Priority

The bridge extracts user identity from headers and the JWT ID token. The OIDC `sub` claim is required as the stable user identifier.

**Identity (sub) — required:**
1. `X-Forwarded-Sub` / `X-Auth-Request-Sub` header
2. `sub` claim from JWT ID token (via `Authorization: Bearer <token>` or `X-Forwarded-Access-Token`)

**Emby username — resolved in order (first available, unique name wins):**
1. `preferred_username` from JWT ID token
2. `X-Forwarded-Preferred-Username` / `X-Auth-Request-Preferred-Username` header
3. `name` from JWT ID token
4. `X-Forwarded-User` / `X-Auth-Request-User` header (only if ≠ sub)
5. `X-Forwarded-Email` / `X-Auth-Request-Email` (final fallback, always unique)

If the preferred username is already taken by another Emby user during account creation, the bridge automatically falls through to the next candidate.

**Other headers:**
- `X-Forwarded-Email` / `X-Auth-Request-Email` — user's email (stored for fallback)
- `X-Forwarded-Picture` / `X-Auth-Request-Picture` — profile image URL (optional)

### Profile Image Sync

The bridge syncs the user's OIDC profile picture to Emby on every login. It tries multiple methods in order:

1. `X-Forwarded-Picture` / `X-Auth-Request-Picture` headers (if forwarded by proxy)
2. JWT ID token decoding (if `Authorization: Bearer <id_token>` header is present)
3. OIDC userinfo endpoint (if `OIDC_ISSUER_URL` is set and an access token is forwarded)

**Option A (upstream mode):** Set `pass_user_headers = true`, `set_authorization_header = true`, and `OIDC_ISSUER_URL`. Works via all methods.

**Option B (forward_auth mode):** Set `set_authorization_header = true` in oauth2-proxy, copy the `Authorization` header in Caddy, and set `OIDC_ISSUER_URL`. Works via method 2 (JWT decoding).

Both modes support profile image sync when configured correctly. Your OIDC provider must include the `picture` claim in the ID token (add `profile` scope if needed).

### Request Flow

1. Request arrives from oauth2-proxy with identity headers / JWT
2. Bridge checks source IP against `TRUSTED_PROXIES` (403 if untrusted)
3. Bridge extracts `sub` claim from headers or JWT (401 if missing)
4. Bridge resolves Emby username from `preferred_username` > `name` > `email`
5. Bridge looks up user in local SQLite database by `sub`
6. If new user: provisions in Emby (creates account with available username, sets password, applies template policy)
7. If existing user with changed name/email: syncs the change to Emby
8. Authenticates with Emby using stored credentials
9. Proxies the request to Emby with the authenticated session

### Routes

| Route | Purpose |
|-------|---------|
| `/health` | Health check (DB + Emby connectivity) |
| `/account` | Shows generated credentials for TV/mobile apps |
| `/*` | Reverse proxy to Emby (after auth) |

## Building

```bash
docker build -t emby-web-oidc-bridge .
```

The resulting image is ~10MB (distroless base, static binary, no shell).

## Development

All development happens inside Docker — no Go toolchain required on the host.

```bash
# Run tests
docker run --rm -v $(pwd):/app -w /app golang:1.23-alpine go test ./...

# Run vet
docker run --rm -v $(pwd):/app -w /app golang:1.23-alpine go vet ./...

# Build locally
docker build -t emby-auth-bridge .
```

See [AGENT.md](AGENT.md) for full development guidelines.

## License

See [LICENSE](LICENSE).
