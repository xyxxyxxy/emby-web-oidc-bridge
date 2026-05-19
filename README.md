# emby-web-oidc-bridge

A lightweight Go service that enables OIDC single sign-on for Emby's web interface via [oauth2-proxy](https://oauth2-proxy.github.io/oauth2-proxy/).

## Motivation

Emby doesn't support SSO or OpenID Connect natively, and the [feature request](https://emby.media/community/topic/114493-sso-openid/) doesn't look like it's going anywhere soon. Since a full SSO solution across all Emby clients (TV apps, mobile, etc.) is non-trivial, this bridge takes a pragmatic approach: it enables OIDC authentication for the web interface, and provides generated credentials for TV/mobile apps where OAuth flows aren't supported.

## How It Works

```
Browser → oauth2-proxy → emby-web-oidc-bridge → Emby Server
```

1. **oauth2-proxy** handles the actual OIDC authentication with your identity provider
2. **The Bridge** reads the forwarded headers (`X-Forwarded-Email`, `X-Forwarded-User`, `X-Forwarded-Picture`), auto-provisions users in Emby, authenticates them, and proxies requests through
3. **Emby** sees a normal authenticated session

Users are automatically provisioned on first login with settings copied from a configurable template user. A simple account page (`/account`) shows generated credentials for use in TV/mobile apps.

## Features

- Automatic user provisioning from OIDC identity
- Seamless web login (no username/password entry)
- Template-based user creation (inherit permissions from a configured user)
- Profile image sync from OIDC claims
- Account page showing credentials for TV/mobile apps
- Health check endpoint (`/health`)
- Trusted proxy IP validation
- Single static binary (~10MB Docker image)

## Quick Start

### Docker Compose

```yaml
services:
  emby-bridge:
    image: emby-web-oidc-bridge:latest
    environment:
      EMBY_API_URL: http://emby:8096/emby
      EMBY_API_KEY: your-emby-api-key
      TEMPLATE_USER_NAME: template
      TRUSTED_PROXIES: 172.16.0.0/12
      # BRIDGE_PORT: 8080        # optional, default: 8080
      # DATABASE_PATH: /data/users.db  # optional, default: ./data/users.db
    volumes:
      - bridge-data:/data
    ports:
      - "8080:8080"

volumes:
  bridge-data:
```

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `EMBY_API_URL` | Yes | — | Emby server URL (e.g., `http://emby:8096/emby`) |
| `EMBY_API_KEY` | Yes | — | Emby admin API key |
| `TEMPLATE_USER_NAME` | Yes | — | Emby user whose settings are copied to new users |
| `TRUSTED_PROXIES` | Yes | — | Comma-separated IPs/CIDRs allowed to set forwarded headers |
| `BRIDGE_PORT` | No | `8080` | Port the bridge listens on |
| `DATABASE_PATH` | No | `/data/users.db` | Path to the SQLite database file |

### Prerequisites

1. A running Emby server with an API key
2. A template user configured in Emby with the desired default permissions
3. oauth2-proxy (or similar) configured to forward email headers (see [oauth2-proxy Configuration](#oauth2-proxy-configuration))

## oauth2-proxy Configuration

The bridge accepts user identity from either `X-Forwarded-Email` or `X-Auth-Request-Email` headers. How these get set depends on your deployment topology.

### Option A: oauth2-proxy as upstream forwarder (simpler)

In this setup, oauth2-proxy handles auth and forwards requests directly to the bridge. No separate reverse proxy needed between oauth2-proxy and the bridge.

```
Browser → Reverse Proxy → oauth2-proxy → bridge → Emby
```

**oauth2-proxy config:**

```ini
upstreams = ["http://emby-bridge:8080"]
pass_user_headers = true
```

`pass_user_headers = true` makes oauth2-proxy set `X-Forwarded-Email`, `X-Forwarded-User`, and `X-Forwarded-Groups` on requests forwarded to the upstream.

Set `TRUSTED_PROXIES` in the bridge to the IP that oauth2-proxy connects from.

### Option B: Reverse proxy with forward_auth subrequest (Caddy, Nginx, Traefik)

In this setup, your reverse proxy handles routing and uses oauth2-proxy only for auth decisions via a subrequest. The reverse proxy then forwards the request to the bridge with the identity headers copied from the auth response.

```
Browser → Caddy → (auth check: oauth2-proxy) → bridge → Emby
```

**oauth2-proxy config:**

```ini
# Required for forward_auth/subrequest mode
set_xauthrequest = true
```

This makes oauth2-proxy return `X-Auth-Request-Email` and `X-Auth-Request-User` in the `/oauth2/auth` response headers.

**Caddy example:**

```caddyfile
emby.example.com {
    # Handle oauth2-proxy callback routes
    handle /oauth2/* {
        reverse_proxy oauth2-proxy:4180
    }

    # Auth check + forward to bridge
    handle {
        forward_auth oauth2-proxy:4180 {
            uri /oauth2/auth

            # Copy identity headers from auth response to upstream request
            copy_headers X-Auth-Request-User X-Auth-Request-Email
            
            @error status 401
            handle_response @error {
                redir * /oauth2/sign_in?rd={scheme}://{host}{uri}
            }
        }

        reverse_proxy emby-bridge:8080
    }
}
```

Set `TRUSTED_PROXIES` in the bridge to the IP that Caddy connects from.

### Header Priority

The bridge checks headers in this order:
1. `X-Forwarded-Email` (set by oauth2-proxy upstream mode)
2. `X-Auth-Request-Email` (set by oauth2-proxy forward_auth mode)

The first non-empty value wins. The same fallback applies to the user/display name header.

## Architecture

```
┌──────────┐     ┌──────────────┐     ┌───────────────────┐     ┌──────────┐
│  Browser │────▶│ oauth2-proxy │────▶│ emby-web-oidc-bridge │────▶│   Emby   │
└──────────┘     └──────────────┘     └───────────────────┘     └──────────┘
                                              │
                                              ▼
                                        ┌──────────┐
                                        │  SQLite  │
                                        └──────────┘
```

### Request Flow

1. Request arrives from oauth2-proxy with `X-Forwarded-Email` header
2. Bridge checks source IP against `TRUSTED_PROXIES` (403 if untrusted)
3. Bridge extracts email from header (401 if missing)
4. Bridge looks up user in local SQLite database
5. If new user: provisions in Emby (creates account, sets password, applies template policy)
6. Authenticates with Emby using stored credentials
7. Proxies the request to Emby with the authenticated session

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

## Security Model

- Emby is expected to be hosted behind oauth2-proxy (or a VPN for direct access)
- The generated password is not security-critical — it exists solely for TV/mobile app authentication where OAuth flows aren't supported
- Passwords are 8 lowercase alphanumeric characters, optimized for easy entry on TV remotes
- Passwords are stored in plaintext in SQLite (by design — they're not secrets)
- The bridge only accepts forwarded headers from IPs in the `TRUSTED_PROXIES` list

## License

See [LICENSE](LICENSE).
