# emby-web-oidc-bridge

A lightweight Go service that enables OIDC single sign-on for Emby's web interface via [oauth2-proxy](https://oauth2-proxy.github.io/oauth2-proxy/).

## Table of Contents

- [How It Works](#how-it-works)
- [Features](#features)
- [Quick Start](#quick-start)
- [Environment Variables](#environment-variables)
- [oauth2-proxy Configuration](#oauth2-proxy-configuration)
  - [Identity Resolution](#identity-resolution)
  - [Profile Image Sync](#profile-image-sync)
  - [Request Flow](#request-flow)
  - [Routes](#routes)
- [Security Model](#security-model)
- [Policy Management](#policy-management)
- [Hidden UI Elements](#hidden-ui-elements)
- [Watchparty Integration](#watchparty-integration)
- [Building](#building)
- [Development](#development)
- [License](#license)

## How It Works

```
Browser → oauth2-proxy → emby-web-oidc-bridge → Emby
```

1. **oauth2-proxy** handles the actual OIDC authentication with your identity provider
2. **The Bridge** reads the OIDC identity from forwarded headers and the JWT ID token, auto-provisions users in Emby, authenticates them, and proxies requests through
3. **Emby** sees a normal authenticated session

Users are identified by their OIDC `sub` (subject) claim — a stable, unique identifier that never changes. The Emby account username is derived from OIDC claims in this order: `preferred_username` > `name` > `email`. If a username/email changes in the OIDC provider, the bridge automatically syncs the change to Emby without creating a duplicate account.

Users are automatically provisioned on first login with settings copied from a configurable template user. A simple account page (`/account`) shows generated credentials for use in TV/mobile apps.

## Features

- Automatic user provisioning from OIDC identity
- Stable user identity via OIDC `sub` claim (username/email changes don't create duplicates)
- Seamless web login (no username/password entry)
- Template-based user creation (inherit permissions from a configured user)
- Profile image sync from OIDC claims
- Session cache with automatic invalidation on user deletion (401 detection)
- Sign Out and Switch User buttons hidden from Emby web UI
- Account page showing credentials for TV/mobile apps
- Optional [watchparty integration](#watchparty-integration)
- Trusted proxy IP validation
- Single static binary (~10MB Docker image)

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
| `EMBY_WATCHPARTY_URL` | No | — | Internal URL of the [emby-watchparty](https://github.com/Oratorian/emby-watchparty) service (e.g., `http://emby-watchparty:5000`). Enables the `/watchparty/` route when set. |

## oauth2-proxy Configuration

The bridge requires oauth2-proxy to forward the JWT ID token (via `set_authorization_header = true`) so it can extract the `sub`, `preferred_username`, `name`, `email`, and `picture` claims. Two deployment modes are supported:

- **[Upstream mode](examples/upstream-mode/)** (recommended) — oauth2-proxy forwards directly to the bridge
- **[Forward auth mode](examples/forward-auth-mode/)** — Caddy/Nginx/Traefik handles routing, oauth2-proxy handles auth decisions

See the example READMEs for complete oauth2-proxy configs, docker-compose files, and Caddyfile examples.

### Identity Resolution

The bridge extracts user identity from the JWT ID token and forwarded headers:

| Claim/Header | Purpose |
|---|---|
| `sub` | Stable user identifier (required) — links OIDC identity to Emby account |
| `preferred_username` | First choice for Emby username |
| `name` | Second choice for Emby username |
| `email` | Final fallback for Emby username (always unique) |
| `picture` | Profile image URL synced to Emby |

If the preferred username is already taken by another Emby user during account creation, the bridge automatically falls through to the next candidate.

### Profile Image Sync

The bridge syncs the user's OIDC profile picture to Emby. It tries in order:

1. `X-Forwarded-Picture` / `X-Auth-Request-Picture` headers
2. `picture` claim from JWT ID token
3. OIDC userinfo endpoint (if `OIDC_ISSUER_URL` is set)

Both deployment modes support profile image sync when configured correctly. Your OIDC provider must include the `picture` claim (add `profile` scope if needed).

### Request Flow

1. Request arrives from oauth2-proxy with identity headers / JWT
2. Bridge checks source IP against `TRUSTED_PROXIES` (403 if untrusted)
3. Bridge extracts `sub` claim from headers or JWT (401 if missing)
4. Bridge resolves Emby username from `preferred_username` > `name` > `email`
5. Bridge looks up user in local SQLite database by `sub`
6. If new user: provisions in Emby (creates account, sets password, applies template policy)
7. If existing user with changed name/email: syncs the change to Emby
8. Authenticates with Emby using stored credentials
9. Proxies the request to Emby with the authenticated session

### Routes

| Route | Purpose |
|-------|---------|
| `/health` | Health check (DB + Emby connectivity) |
| `/account` | Shows generated credentials for TV/mobile apps |
| `/api/credentials` | Returns authenticated user's Emby credentials as JSON (internal API used by auto-login script and account page) |
| `/web/index.html` | Emby web UI with injected credentials |
| `/watchparty/*` | Reverse proxy to watchparty service (optional, enabled when `EMBY_WATCHPARTY_URL` is set) |
| `/*` | Reverse proxy to Emby (after auth) |

## Security Model

- Emby is expected to be hosted behind oauth2-proxy (or a VPN for direct access)
- The bridge only accepts forwarded headers from IPs in the `TRUSTED_PROXIES` list
- The generated password is not security-critical — it exists solely for TV/mobile app authentication where OAuth flows aren't supported
- Passwords are 8 lowercase alphanumeric characters, optimized for easy entry on TV remotes
- Passwords are stored in plaintext in SQLite (by design — they're not secrets)

## Policy Management

The bridge enforces minimal policy overrides to function correctly, while leaving all other settings under admin control.

**On user creation:** The template user's full policy is applied (library access, parental controls, IsHidden, etc.).

**On every login:** The bridge fetches the user's current policy from Emby and only enforces two fields if they differ from the expected values (skipping unnecessary API calls):

| Policy Field | Enforced Value | Reason |
|-------------|-------|--------|
| `IsDisabled` | `false` | Access is managed via the OIDC provider. If a user can authenticate through oauth2-proxy, they should have access. Revoke access at the identity provider, not in Emby. |
| `EnableUserPreferenceAccess` | `false` | Prevents users from changing their password or profile image in Emby, since these are managed by the bridge. |

All other policy fields (library access, parental controls, `IsHidden`, remote access, etc.) are fully controlled by the admin per-user after creation. The bridge will not overwrite them.

**Important:** If you disable a user in Emby's admin UI, the bridge will re-enable them on their next login. To revoke access, remove the user from your OIDC provider or oauth2-proxy's allowed list instead.

## Hidden UI Elements

The bridge hides the following buttons from the Emby web interface since they don't apply when authentication is managed through OIDC:

| Button | Reason |
|--------|--------|
| **Sign Out** | Logging out of Emby makes no sense behind the bridge — the user would be re-authenticated immediately via oauth2-proxy. To sign out, users should log out of the OIDC provider directly. |
| **Switch User** | User identity is determined by the OIDC session, not by Emby's local user selection. Switching users requires authenticating as a different identity at the OIDC provider. |

These buttons are hidden via CSS injected into the Emby web page. They are not removed from the DOM, so admin users accessing Emby directly (not through the bridge) will still see them.

## Watchparty Integration

The bridge provides optional integration with [emby-watchparty](https://github.com/Oratorian/emby-watchparty) (2.0-Rework branch), a synchronized watch-together service for Emby. This feature is disabled by default.

When `EMBY_WATCHPARTY_URL` is set, the bridge serves the watchparty UI at `/watchparty/` and handles authentication automatically. The user's display name is set via localStorage on first visit, and the bridge's auto-login script fills the watchparty login form with the user's Emby credentials.

### Configuration

The watchparty container (`emby-watchparty`) must be configured with:

- `APP_PREFIX=/watchparty` — required for sub-path routing

The bridge injects a script into watchparty HTML responses that detects the login form via MutationObserver, fetches credentials from `/api/credentials`, and submits the form. The party creator is automatically made host. No manual login is required.

No new environment variables are needed on the bridge side — `EMBY_WATCHPARTY_URL` enables both the proxy and the auto-login behavior.

### Requirements

All watchparty users must be authenticated members behind oauth2-proxy. Guest or spectator mode (anonymous party joining) is not available since all users must complete OIDC authentication before accessing the watchparty UI.

See `docker-compose.yml` for a commented-out example ready to enable.

## Building

```bash
docker build -t emby-web-oidc-bridge .
```

The resulting image is ~10MB (distroless base, static binary, no shell).

## Development

All development happens inside Docker — no Go toolchain required on the host.

```bash
# Run tests
docker run --rm -v $(pwd):/app -w /app golang:1.24-alpine go test ./...

# Run vet
docker run --rm -v $(pwd):/app -w /app golang:1.24-alpine go vet ./...

# Build locally
docker build -t emby-auth-bridge .
```

See [AGENT.md](AGENT.md) for full development guidelines.

## License

See [LICENSE](LICENSE).
