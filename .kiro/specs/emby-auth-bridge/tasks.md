# Implementation Plan: Emby Authentication Bridge

## Overview

Implement the Emby Authentication Bridge as a Go service using stdlib `net/http`, `net/http/httputil.ReverseProxy`, and `zombiezen.com/go/sqlite`. The implementation follows a bottom-up approach: scaffolding → config → utilities → data layer → API client → middleware → handlers → wiring → Docker → tests.

## Tasks

- [ ] 1. Project scaffolding and core interfaces
  - [x] 1.1 Initialize Go module and directory structure
    - Create `go.mod` with module path and Go 1.23
    - Add dependencies: `zombiezen.com/go/sqlite`, `pgregory.net/rapid` (test-only)
    - Create directory structure: `cmd/bridge/`, `internal/config/`, `internal/emby/`, `internal/db/`, `internal/middleware/`, `internal/handler/`, `internal/password/`
    - Create placeholder `main.go` in `cmd/bridge/`
    - _Requirements: 13.1_

- [ ] 2. Configuration loading
  - [x] 2.1 Implement environment variable loading and validation
    - Create `internal/config/config.go` with `Config` struct and `Load()` function
    - Read EMBY_API_URL, EMBY_API_KEY, TEMPLATE_USER_NAME, TRUSTED_PROXIES (required)
    - Read BRIDGE_PORT (default: 8080), DATABASE_PATH (default: ./data/users.db)
    - Return error naming the specific missing variable when a required var is absent
    - Implement `ParseTrustedProxies()` to parse comma-separated IPs/CIDRs into `[]*net.IPNet`
    - _Requirements: 11.1, 11.2, 11.3, 11.4, 11.5, 11.6, 11.7_

  - [x] 2.2 Write property test for config validation error reporting
    - **Property 6: Missing config error reporting**
    - **Validates: Requirements 11.7**

- [ ] 3. Password generation
  - [x] 3.1 Implement password generator
    - Create `internal/password/gen.go` with `Generate()` function
    - Generate exactly 8 characters from charset `[a-z0-9]`
    - Use `crypto/rand` for secure random generation
    - _Requirements: 3.1_

  - [x] 3.2 Write property test for password format invariant
    - **Property 1: Password format invariant**
    - **Validates: Requirements 3.1**

- [ ] 4. SQLite database layer
  - [x] 4.1 Implement SQLite database operations
    - Create `internal/db/sqlite.go` with `DB` struct
    - Implement `Open()` to open/create database and initialize schema (CREATE TABLE IF NOT EXISTS)
    - Implement `FindUser(email)` to query user by email
    - Implement `InsertUser(email, embyUserID, password)` to insert a new record
    - Implement `IsHealthy()` to verify database connectivity
    - Implement `Close()` for cleanup
    - Schema: `users(email TEXT PRIMARY KEY, emby_user_id TEXT NOT NULL, password TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT (datetime('now')))`
    - _Requirements: 9.1, 9.2, 9.3, 9.4_

  - [x] 4.2 Write property test for database round-trip consistency
    - **Property 3: Database user record round-trip**
    - **Validates: Requirements 3.4, 9.3**

  - [x] 4.3 Write property test for password stability
    - **Property 4: Password stability**
    - **Validates: Requirements 3.6**

- [ ] 5. Emby API client
  - [x] 5.1 Implement Emby API client
    - Create `internal/emby/client.go` with `Client` struct and all methods
    - Implement `NewClient(baseURL, apiKey)` constructor
    - Implement `FindUserByName(ctx, name)` — GET `/Users/Query?api_key={key}`
    - Implement `CreateUser(ctx, name, copyFromUserID)` — POST `/Users/New?api_key={key}` with CopyFromUserId and UserCopyOptions
    - Implement `AuthenticateByName(ctx, username, password)` — POST `/Users/AuthenticateByName` with X-Emby-Authorization header
    - Implement `UpdatePassword(ctx, userID, newPassword)` — POST `/Users/{Id}/Password?api_key={key}`
    - Implement `UpdatePolicy(ctx, userID, policy)` — POST `/Users/{Id}/Policy?api_key={key}`
    - Implement `SetProfileImage(ctx, userID, imageURL)` — fetch image from URL, POST bytes to `/Users/{Id}/Images/Primary?api_key={key}`
    - Implement `Ping(ctx)` — GET `/System/Info?api_key={key}`
    - No retry logic on any API call
    - _Requirements: 10.1, 10.2, 10.3, 10.4, 10.5, 10.6, 10.7_

  - [x] 5.2 Write unit tests for Emby API client
    - Test each method with `net/http/httptest` mock server
    - Test error handling for 4xx and 5xx responses
    - Test X-Emby-Authorization header format
    - _Requirements: 10.6, 10.7_

- [x] 6. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 7. Trusted proxy middleware
  - [x] 7.1 Implement trusted proxy IP check middleware
    - Create `internal/middleware/proxy.go`
    - Implement `TrustedProxy(trusted []*net.IPNet) func(http.Handler) http.Handler`
    - Implement `IsIPTrusted(ip net.IP, trusted []*net.IPNet) bool`
    - Extract client IP from `RemoteAddr` (strip port)
    - Return 403 Forbidden for untrusted IPs
    - Log rejected requests with source IP via `slog`
    - _Requirements: 1.1, 1.2_

  - [x] 7.2 Write property test for trusted proxy IP matching
    - **Property 2: Trusted proxy IP matching**
    - **Validates: Requirements 1.2**

- [ ] 8. Auth middleware (header extraction + user provisioning)
  - [x] 8.1 Implement auth middleware
    - Create `internal/middleware/auth.go`
    - Extract X-Forwarded-Email (required — 401 if missing)
    - Extract X-Forwarded-User and X-Forwarded-Picture (optional)
    - Lookup user in SQLite by email
    - If user exists in DB: authenticate with Emby using stored password
    - If user not in DB: check if user exists in Emby
      - If exists in Emby but not DB: generate password, update in Emby, store in DB
      - If doesn't exist anywhere: generate password, create user with template, set password, update policy (enable user, disable prefs), store in DB
    - After auth: set profile image if X-Forwarded-Picture present (non-blocking failure)
    - After auth: disable EnableUserPreferenceAccess (non-blocking failure)
    - Store auth token in request context for proxy handler
    - Use `log/slog` for structured logging of all operations
    - _Requirements: 1.3, 1.4, 1.5, 2.1, 2.2, 2.3, 2.4, 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 4.2, 4.4, 5.1, 5.2, 6.1, 6.2, 6.3, 7.1, 7.4, 7.5, 7.6, 12.1, 12.2_

  - [x] 8.2 Write unit tests for auth middleware
    - Test header extraction (valid, missing email, missing optional headers)
    - Test existing user flow (DB lookup → authenticate)
    - Test new user provisioning flow (create → set password → policy → store)
    - Test adopted user flow (exists in Emby, not in DB)
    - Test Emby API unreachable returns 503
    - Use `net/http/httptest` for mock Emby API
    - _Requirements: 1.3, 1.4, 2.4, 3.5, 7.4, 7.5_

- [ ] 9. Health check handler
  - [x] 9.1 Implement health check endpoint
    - Create `internal/handler/health.go`
    - Implement `Health(database *db.DB, embyClient *emby.Client) http.HandlerFunc`
    - Check SQLite connectivity via `db.IsHealthy()`
    - Check Emby connectivity via `embyClient.Ping(ctx)`
    - Return 200 OK when both healthy
    - Return 503 Service Unavailable when either is unreachable
    - _Requirements: 14.1, 14.2, 14.3, 14.4, 14.5_

- [ ] 10. Account page handler
  - [x] 10.1 Implement account page handler
    - Create `internal/handler/account.go`
    - Implement `Account(database *db.DB) http.HandlerFunc`
    - Verify user is authenticated via X-Forwarded-Email header (401 if missing)
    - Lookup user in database by email
    - Render HTML page using `html/template` showing email and plaintext password
    - _Requirements: 8.1, 8.2, 8.3, 8.4_

  - [x] 10.2 Write property test for account page credential display
    - **Property 5: Account page credential display**
    - **Validates: Requirements 8.1, 8.2**

- [ ] 11. Reverse proxy handler
  - [x] 11.1 Implement reverse proxy to Emby
    - Create `internal/handler/proxy.go`
    - Implement `Proxy(embyURL string) http.Handler`
    - Use `net/http/httputil.ReverseProxy` with Director function
    - Preserve request headers and body content
    - Forward authenticated session from context
    - _Requirements: 7.2, 7.3_

- [ ] 12. Main server wiring
  - [x] 12.1 Implement main entry point and server startup
    - Create `cmd/bridge/main.go`
    - Load config via `config.Load()`
    - Open database via `db.Open(cfg.DatabasePath)`
    - Create Emby client via `emby.NewClient(cfg.EmbyAPIURL, cfg.EmbyAPIKey)`
    - Validate template user exists in Emby at startup (exit if not found)
    - Register routes: `/health` (no middleware), `/account` (trusted proxy + header check), `/*` (full middleware chain → proxy)
    - Compose middleware: `trustedProxy(auth(proxyHandler))`
    - Start HTTP server on configured port
    - Use `log/slog` for startup logging
    - _Requirements: 4.1, 4.3, 11.7, 12.3, 13.2, 13.3, 13.4_

- [x] 13. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 14. Dockerfile
  - [x] 14.1 Create multi-stage Dockerfile
    - Build stage: `golang:1.23-alpine`, copy source, `CGO_ENABLED=0 go build -ldflags="-s -w" -o /bridge ./cmd/bridge`
    - Final stage: `gcr.io/distroless/static-debian12:nonroot`
    - Copy binary from builder
    - EXPOSE 8080
    - ENTRYPOINT ["/bridge"]
    - _Requirements: 13.1, 13.2, 13.4, 13.5_

- [ ] 15. Integration tests
  - [x] 15.1 Write integration tests for full request flow
    - Test complete provisioning flow: request → trusted proxy check → header extraction → user creation → auth → proxy
    - Test existing user login flow
    - Test adopted user flow (exists in Emby, not in DB)
    - Use `net/http/httptest` for mock Emby API server
    - Use in-memory SQLite (`:memory:`) for database
    - Verify correct Emby API calls are made in order
    - _Requirements: 1.2, 1.3, 1.4, 2.1, 2.2, 2.3, 3.1, 3.2, 3.3, 3.4, 7.1, 7.2, 7.3_

  - [x] 15.2 Write integration tests for error scenarios
    - Test untrusted IP rejection (403)
    - Test missing email header (401)
    - Test Emby API unreachable (503)
    - Test user creation failure (500)
    - Test health check with DB down and Emby down
    - _Requirements: 1.2, 1.4, 2.4, 3.5, 14.4, 14.5_

- [x] 16. Final checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- Property tests validate universal correctness properties from the design document
- Unit tests validate specific examples and edge cases
- All code uses Go stdlib except `zombiezen.com/go/sqlite` for database and `pgregory.net/rapid` for PBT
- No retry logic on Emby API calls — failures are logged and returned immediately
- Profile image sync and policy updates are non-blocking (logged as warnings on failure)

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1"] },
    { "id": 1, "tasks": ["2.1", "3.1"] },
    { "id": 2, "tasks": ["2.2", "3.2", "4.1"] },
    { "id": 3, "tasks": ["4.2", "4.3", "5.1"] },
    { "id": 4, "tasks": ["5.2", "7.1"] },
    { "id": 5, "tasks": ["7.2", "8.1", "9.1", "10.1", "11.1"] },
    { "id": 6, "tasks": ["8.2", "10.2", "12.1"] },
    { "id": 7, "tasks": ["14.1", "15.1", "15.2"] }
  ]
}
```
