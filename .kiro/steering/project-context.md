---
description: Project overview, tech stack, layout, design decisions, and development constraints for the emby-web-oidc-bridge service.
inclusion: auto
---

# Project Context

## What This Is

emby-web-oidc-bridge is a Go service that enables OIDC SSO for Emby's web interface via oauth2-proxy. It auto-provisions users, authenticates them transparently, and proxies requests to Emby.

## Tech Stack

- **Language**: Go 1.23 (stdlib-heavy, minimal dependencies)
- **Database**: SQLite via `zombiezen.com/go/sqlite` (pure-Go, no CGO)
- **Testing**: `pgregory.net/rapid` for property-based tests, stdlib `testing` for unit/integration
- **HTTP**: stdlib `net/http`, `net/http/httputil.ReverseProxy`
- **Logging**: stdlib `log/slog` (JSON structured)
- **Container**: distroless static image, nonroot user

## Development Constraint

**All Go commands MUST run inside Docker.** No Go toolchain on the host.

```bash
# Tests
docker run --rm -v $(pwd):/app -w /app golang:1.23-alpine go test ./...

# Build
docker build -t emby-auth-bridge .

# Vet
docker run --rm -v $(pwd):/app -w /app golang:1.23-alpine go vet ./...

# Add dependency
docker run --rm -v $(pwd):/app -w /app golang:1.23-alpine go get <package>
```

## Project Layout

```
cmd/bridge/main.go           # Entry point
internal/config/             # Env var loading
internal/emby/               # Emby REST API client
internal/db/                 # SQLite operations
internal/middleware/          # TrustedProxy + Auth middleware
internal/handler/            # Health, Account, Proxy handlers
internal/password/           # Password generation
internal/integration/        # Integration tests
```

## Key Design Decisions

- No retry logic on Emby API calls
- Plaintext password storage (by design — not security-critical)
- Two-step password update: reset to blank, then set new password
- Auth token shared via `handler.WithAuthToken(ctx)` / `handler.AuthTokenFromContext(ctx)`
- Non-blocking goroutines for profile image sync and policy updates
- Re-provisions user if Emby auth fails (handles deleted users)
- Accepts both `X-Forwarded-Email` and `X-Auth-Request-Email` headers

## Environment Variables

| Variable | Required | Default |
|----------|----------|---------|
| `EMBY_API_URL` | Yes | — |
| `EMBY_API_KEY` | Yes | — |
| `TEMPLATE_USER_NAME` | Yes | — |
| `TRUSTED_PROXIES` | Yes | — |
| `BRIDGE_PORT` | No | `8080` |
| `DATABASE_PATH` | No | `/data/users.db` |

## Running Locally

```bash
docker compose up --build
docker compose logs -f
```

To reset the database: `docker compose down -v && docker compose up -d`
