# emby-web-oidc-bridge

A lightweight Go service that enables OIDC single sign-on for Emby's web interface via [oauth2-proxy](https://oauth2-proxy.github.io/oauth2-proxy/).

## Table of Contents

- [How It Works](#how-it-works)
- [Features](#features)
- [Quick Start](#quick-start)
- [Environment Variables](#environment-variables)
- [oauth2-proxy Configuration](#oauth2-proxy-configuration)
  - [Identity Resolution](#identity-resolution)
  - [Username Changes at the IdP](#username-changes-at-the-idp)
  - [Multi-Subdomain SSO](#multi-subdomain-sso)
  - [Profile Image Sync](#profile-image-sync)
  - [Request Flow](#request-flow)
  - [Routes](#routes)
- [Security Model](#security-model)
- [Policy Management](#policy-management)
- [Hidden UI Elements](#hidden-ui-elements)
- [Watchparty Integration (Experimental)](#watchparty-integration-experimental)
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

Users are identified by their OIDC `sub` (subject) claim — a stable, unique identifier that never changes. The Emby account username is set from the OIDC `preferred_username` claim. If `preferred_username` changes at the identity provider, the bridge syncs the Emby username on the next session establishment (bridge restart, Emby 401, or first visit after cache miss).

Users are automatically provisioned on first login with settings copied from a configurable template user. A simple account page (`/account`) shows generated credentials for use in TV/mobile apps.

After the first request establishes a session, the bridge reuses the cached Emby token for subsequent requests without calling the Emby API. Session re-establishment (provision, authenticate, profile sync, policy enforcement) runs only when the in-memory session is missing or invalidated.

## Features

- Automatic user provisioning from OIDC identity
- Stable user identity via OIDC `sub` claim (username/email changes don't create duplicates)
- Seamless web login (no username/password entry)
- Template-based user creation (inherit permissions from a configured user)
- Profile image sync from OIDC claims (on session establishment)
- In-memory session token cache (no TTL; invalidated on Emby 401 or bridge restart)
- Structured log on each session establishment (`emby session established`)
- Sign Out and Switch User buttons hidden from Emby web UI
- Account page showing credentials for TV/mobile apps
- Optional, experimental [watchparty integration](#watchparty-integration-experimental)
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
| `EMBY_WATCHPARTY_URL` | No | — | **Experimental.** Internal URL of the [emby-watchparty](https://github.com/Oratorian/emby-watchparty) service (e.g., `http://emby-watchparty:5000`). Enables the `/watchparty/` route when set. |

## oauth2-proxy Configuration

The bridge requires oauth2-proxy to forward the JWT ID token (via `set_authorization_header = true`) and identity headers (via `pass_user_headers = true` and `pass_access_token = true`) so it can extract the `sub`, `preferred_username`, `email`, and `picture` claims. Two deployment modes are supported:

- **[Upstream mode](examples/upstream-mode/)** (recommended) — oauth2-proxy forwards directly to the bridge
- **[Forward auth mode](examples/forward-auth-mode/)** — Caddy/Nginx/Traefik handles routing, oauth2-proxy handles auth decisions

See the example READMEs for complete oauth2-proxy configs, docker-compose files, and Caddyfile examples.

### Identity Resolution

The bridge resolves identity from the JWT ID token (`Authorization: Bearer …`) and forwarded headers. When both are present, the **ID token takes precedence** for `preferred_username` — proxy headers can lag behind IdP username changes.

| Claim/Header | Purpose |
|---|---|
| `sub` | Stable user identifier (required) — links OIDC identity to Emby account |
| `preferred_username` | Emby username (required) |
| `picture` | Profile image URL synced to Emby |
| `email` | Optional — used in establishment logs only, not stored in database |

**Resolution order for `preferred_username`:**

1. `preferred_username` claim from the ID token (`Authorization` header)
2. `X-Forwarded-Preferred-Username` / `X-Auth-Request-Preferred-Username` (fallback)

The access token is never used for the Emby username. If the ID token and proxy header disagree, the bridge uses the ID token and logs a warning.

`preferred_username` is required. The bridge does not fall back to `name` or `email` for the Emby username.

If the preferred username is already taken by another Emby user during account creation, provisioning fails.

**Required oauth2-proxy settings:**

| Setting | Purpose |
|---------|---------|
| `set_authorization_header = true` | Forward ID token as `Authorization` (primary identity source) |
| `pass_user_headers = true` | Forward `X-Forwarded-*` / `X-Auth-Request-*` headers (fallback) |
| `pass_access_token = true` | Forward access token for userinfo profile image lookup |

In forward auth mode, your reverse proxy must copy these headers from the oauth2-proxy auth response to the upstream request (see [Caddyfile example](examples/forward-auth-mode/Caddyfile)).

### Username Changes at the IdP

When a user renames their account at the identity provider, the bridge syncs the Emby username to the new `preferred_username` on **session establishment** only (not on every request). For the sync to see the new name:

1. The user must obtain a **fresh ID token** from oauth2-proxy (stale oauth2-proxy sessions can keep old claims even after an IdP rename).
2. Call **`/oauth2/sign_out`** on the oauth2-proxy host — logging out of the IdP alone may leave the oauth2-proxy cookie active.
3. Log in again so the bridge re-establishes its in-memory Emby session.

If you run multiple services behind the same oauth2-proxy, use a shared session cookie (see [Multi-Subdomain SSO](#multi-subdomain-sso)) so one sign-out clears all services.

### Multi-Subdomain SSO

If one oauth2-proxy instance protects multiple hosts (e.g. `emby.example.com`, `docs.example.com`), configure a **shared session cookie** so login and logout apply to all services:

```ini
# Shared SSO across subdomains (HTTPS required)
cookie_name = "__Secure-oauth2_proxy"   # use __Secure-, not __Host- (host-only)
cookie_secure = true
cookie_samesite = "lax"
cookie_domains = [".example.com"]       # leading dot — NOT "*.example.com"

# Allow post-logout redirects (rd=) to your services and IdP end-session URL
whitelist_domains = [".example.com", "auth.example.com"]
```

Important:

- **`__Host-` cookies are per-host** — each subdomain gets its own session; logging out on one host does not log out others.
- **`cookie_domains` does not support `*` wildcards** — use `.parent.domain` (e.g. `.proxy.example.com`). A value like `*.proxy.example.com` creates per-host cookies instead of a shared one.
- **`whitelist_domains`** accepts `.` or `*.` prefixes for subdomains; this is separate from `cookie_domains` syntax.
- After changing cookie name or domain, delete old oauth2-proxy cookies once, then log in again.

See the commented optional block in [`examples/upstream-mode/oauth2-proxy.cfg`](examples/upstream-mode/oauth2-proxy.cfg) for a full reference.

### Profile Image Sync

On **session establishment** (first visit, bridge restart, or after Emby invalidates the token with 401), the bridge syncs the user's OIDC profile picture to Emby. It resolves the picture URL in order:

1. `X-Forwarded-Picture` / `X-Auth-Request-Picture` headers
2. `picture` claim from JWT ID token
3. OIDC userinfo endpoint (if `OIDC_ISSUER_URL` is set)

Mid-session avatar changes are applied on the next session establishment. Your OIDC provider must include the `picture` claim (add `profile` scope if needed).

### Request Flow

1. Request arrives from oauth2-proxy with identity headers / JWT
2. Bridge checks source IP against `TRUSTED_PROXIES` (403 if untrusted)
3. Bridge extracts `sub` claim from headers or JWT (401 if missing)
4. Bridge requires `preferred_username` for the Emby username (401 if missing)
5. **If a cached Emby session exists:** attach token and proxy — no Emby management API calls
6. **Otherwise (session establishment):**
   - Look up user in local SQLite database by `sub`
   - If new user: provision in Emby (create account, set password, apply template policy)
   - If existing user with username drift: reset linked account name to `preferred_username`
   - Authenticate with Emby and store token in memory
   - Async: sync profile image (if picture URL present) and enforce policy fields
   - Log `emby session established` with `reason` (`first_login` or `returning_user`)
7. Proxy the request to Emby with the authenticated session

### Routes

| Route | Purpose |
|-------|---------|
| `/health` | Health check (DB + Emby connectivity) |
| `/account` | Shows generated credentials for TV/mobile apps |
| `/api/credentials` | Returns authenticated user's Emby credentials as JSON (internal API used by auto-login script and account page) |
| `/web/index.html` | Emby web UI with injected credentials |
| `/watchparty/*` | **Experimental.** Reverse proxy to watchparty service (optional, enabled when `EMBY_WATCHPARTY_URL` is set) |
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

**On session establishment:** The bridge fetches the user's current policy from Emby and only enforces two fields if they differ from the expected values (skipping unnecessary API calls):

| Policy Field | Enforced Value | Reason |
|-------------|-------|--------|
| `IsDisabled` | `false` | Access is managed via the OIDC provider. If a user can authenticate through oauth2-proxy, they should have access. Revoke access at the identity provider, not in Emby. |
| `EnableUserPreferenceAccess` | `false` | Prevents users from changing their password or profile image in Emby, since these are managed by the bridge. |

All other policy fields (library access, parental controls, `IsHidden`, remote access, etc.) are fully controlled by the admin per-user after creation. The bridge will not overwrite them.

**Important:** If you disable a user in Emby's admin UI, the bridge will re-enable them on their next session establishment. To revoke access, remove the user from your OIDC provider or oauth2-proxy's allowed list instead.

## Hidden UI Elements

The bridge hides the following buttons from the Emby web interface since they don't apply when authentication is managed through OIDC:

| Button | Reason |
|--------|--------|
| **Sign Out** | Logging out of Emby only ends the bridge's cached Emby session — oauth2-proxy would re-authenticate the user immediately. To sign out, use **`/oauth2/sign_out`** on the oauth2-proxy host (optionally with an `rd=` redirect to your IdP's end-session URL). See [Multi-Subdomain SSO](#multi-subdomain-sso) if you protect multiple subdomains. |
| **Switch User** | User identity is determined by the OIDC session, not by Emby's local user selection. Switching users requires signing out via oauth2-proxy and authenticating as a different identity at the IdP. |

These buttons are hidden via CSS injected into the Emby web page. They are not removed from the DOM, so admin users accessing Emby directly (not through the bridge) will still see them.

## Watchparty Integration (Experimental)

The bridge provides optional, **experimental** integration with [emby-watchparty](https://github.com/Oratorian/emby-watchparty), a synchronized watch-together service for Emby. This feature is disabled by default and may change as watchparty v2 evolves.

When `EMBY_WATCHPARTY_URL` is set, the bridge serves the watchparty UI at `/watchparty/` and handles authentication automatically. The user's display name is set via localStorage on first visit, and the bridge's auto-login script fills credential fields when creating a party.

### Configuration

The watchparty container (`emby-watchparty`) must be configured with:

- `APP_PREFIX=/watchparty` — required for sub-path routing

In the watchparty admin panel (**Security** section), enable **Require Login to Create Party** (recommended). With this enabled, party creation prompts for Emby credentials; the bridge auto-fills and submits them so the creator becomes host without manual login. This setting is hot-reloadable — no container restart required.

The bridge injects a script into watchparty HTML responses that detects login forms via MutationObserver, fetches credentials from `/api/credentials`, and submits the form.

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
