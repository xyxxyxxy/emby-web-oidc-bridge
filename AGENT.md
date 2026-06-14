# AI Agent Guidelines

This document provides guidance for AI agents working on the emby-web-oidc-bridge project.

## Project Overview

**emby-web-oidc-bridge** is a lightweight Go service that sits between oauth2-proxy and Emby Server. It reads OIDC session headers set by oauth2-proxy, auto-provisions users in Emby, authenticates them transparently, and proxies requests to the Emby web interface. It also serves a simple account page where users can view their generated credentials for TV/mobile apps.

## Tech Stack

- **Language**: Go 1.24
- **Module path**: `github.com/xyxxyxxy/emby-web-oidc-bridge`
- **HTTP**: Go stdlib `net/http`, `net/http/httputil.ReverseProxy`
- **Database**: SQLite via `zombiezen.com/go/sqlite` (pure-Go, no CGO)
- **Testing**: Go stdlib `testing`, `pgregory.net/rapid` for property-based tests
- **Logging**: Go stdlib `log/slog` (JSON structured logging)
- **Templates**: Go stdlib `html/template`
- **Container**: Multi-stage Dockerfile with `gcr.io/distroless/static-debian12:nonroot`

## Project Structure

```
cmd/bridge/main.go              # Entry point, server startup, config validation
internal/config/config.go       # Env var loading and validation
internal/emby/client.go         # Emby API client (net/http)
internal/emby/models.go         # JSON request/response structs, error types
internal/db/sqlite.go           # Database operations (zombiezen.com/go/sqlite)
internal/middleware/proxy.go    # Trusted proxy IP check
internal/middleware/auth.go     # Header extraction + user provisioning/auth + session cache
internal/handler/health.go      # Health check endpoint
internal/handler/account.go     # Account page (html/template)
internal/handler/autologin.go   # Credential injection into Emby web UI
internal/handler/proxy.go       # Reverse proxy to Emby (httputil.ReverseProxy)
internal/password/gen.go        # Password generation (crypto/rand)
internal/integration/           # Integration tests
```

## Development Environment

**All development MUST happen inside Docker containers.** No Go toolchain, dependencies, or build tools will be installed on the host machine.

- **Building**: `docker build -t emby-auth-bridge .`
- **Running tests**: `docker run --rm -v $(pwd):/app -w /app golang:1.24-alpine go test ./...`
- **Running vet**: `docker run --rm -v $(pwd):/app -w /app golang:1.24-alpine go vet ./...`
- **Adding dependencies**: `docker run --rm -v $(pwd):/app -w /app golang:1.24-alpine go get <package>`
- **Tidying modules**: `docker run --rm -v $(pwd):/app -w /app golang:1.24-alpine go mod tidy`
- **Formatting**: `docker run --rm -v $(pwd):/app -w /app golang:1.24-alpine gofmt -w .`
- **Running the app**: `docker compose up` (requires env vars configured)

Do NOT run `go build`, `go test`, `go mod tidy`, or any Go commands directly on the host. Always wrap them in Docker.

## Core Principles

- **Single static binary**: No runtime dependencies, trivial deployment
- **No external HTTP framework**: stdlib `net/http` is production-ready
- **No retry logic**: Emby API calls are not retried — failures are logged and returned immediately
- **Plaintext password storage**: Passwords are not security-critical (8-char alphanumeric for TV remotes)
- **In-memory session cache**: 15-minute TTL per OIDC sub; evicted on logout or Emby 401
- **Non-blocking side effects**: Profile image sync and policy updates run in goroutines

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `EMBY_API_URL` | Yes | — | Emby server URL (e.g., `http://emby:8096/emby`) |
| `EMBY_API_KEY` | Yes | — | Emby admin API key |
| `TEMPLATE_USER_NAME` | Yes | — | Name of the template user in Emby |
| `TRUSTED_PROXIES` | Yes | — | Comma-separated IPs/CIDRs |
| `BRIDGE_PORT` | No | `8080` | Port the Bridge listens on |
| `DATABASE_PATH` | No | `/data/users.db` | Path to SQLite database file |

## Routes

| Route | Method | Middleware | Purpose |
|-------|--------|-----------|---------|
| `/health` | GET | None | Health check (DB + Emby connectivity) |
| `/account` | GET | TrustedProxy | Account page showing credentials |
| `/{$}` | GET | TrustedProxy → Auth | Redirect to `/web/index.html` |
| `/web/index.html` | GET | TrustedProxy → Auth | Emby page with injected credentials |
| `/*` | ALL | TrustedProxy → Auth | Reverse proxy to Emby |

## Testing

- **Unit tests**: Each package has `_test.go` files using Go stdlib `testing`
- **Property-based tests**: `_property_test.go` files using `pgregory.net/rapid` (100 iterations minimum)
- **Integration tests**: `internal/integration/` tests the full middleware chain
- **Run all tests**: `docker run --rm -v $(pwd):/app -w /app golang:1.24-alpine go test ./...`
- **Test databases**: Use in-memory SQLite (`file:testN?mode=memory&cache=shared`) with atomic counters for unique URIs

## Code Conventions

- Error wrapping: `fmt.Errorf("operation: %w", err)`
- Structured logging: `slog.Info/Warn/Error` with key-value pairs
- Context propagation: Pass `context.Context` through all layers
- Auth token sharing: `handler.WithAuthSession(ctx, token, userID, serverID)` / `handler.AuthTokenFromContext(ctx)`
- OIDC sub in context: `handler.WithAuthSub(ctx, sub)` / `handler.AuthSubFromContext(ctx)`
- Session cache: In-memory `sync.Map` keyed by OIDC sub with 15-min TTL; evicted on 401 from Emby
- Middleware pattern: `func(http.Handler) http.Handler`

## Development Workflow

This project uses **conventional commits**.

### Commit Message Format

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <subject>
```

**Types:** `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `chore`, `ci`

**Scopes:** `auth`, `proxy`, `db`, `config`, `emby`, `health`, `account`, `docker`, `deps`

## Security Considerations

- Never log passwords or API keys
- Validate all OIDC headers come from trusted proxies only
- Use `crypto/rand` for password generation
- Run container as non-root (distroless:nonroot)
- No shell in production image (distroless)

## When Making Changes

1. Make changes and write/update tests
2. **Always run tests before committing**: `docker run --rm -v $(pwd):/app -w /app golang:1.24-alpine go test ./...`
3. Run vet in Docker: `docker run --rm -v $(pwd):/app -w /app golang:1.24-alpine go vet ./...`
4. Verify Docker build: `docker build -t emby-auth-bridge .`
5. Review `AGENT.md` and update if routes, files, design decisions, or conventions have changed
6. Review `README.md` and update if user-facing behavior, features, routes, environment variables, or deployment instructions have changed
7. Commit with conventional commit message
