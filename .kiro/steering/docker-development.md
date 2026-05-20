---
inclusion: auto
description: Docker commands for building, testing, and running the Go service without a local toolchain.
---

# Docker Development

## Critical Rule

**NEVER run Go commands directly on the host.** Always use Docker.

## Common Commands

### Run tests
```bash
docker run --rm -v $(pwd):/app -w /app golang:1.23-alpine go test ./...
```

### Run a specific package's tests
```bash
docker run --rm -v $(pwd):/app -w /app golang:1.23-alpine go test ./internal/middleware/...
```

### Build the image
```bash
docker build -t emby-auth-bridge .
```

### Start the service
```bash
docker compose up --build -d
```

### View logs
```bash
docker compose logs -f
```

### Rebuild after code changes
```bash
docker compose up --build -d
```

### Reset database (fresh start)
```bash
docker compose down -v
docker compose up -d
```

### Add a Go dependency
```bash
docker run --rm -v $(pwd):/app -w /app golang:1.23-alpine go get <package>@<version>
docker run --rm -v $(pwd):/app -w /app golang:1.23-alpine go mod tidy
```

### Format code
```bash
docker run --rm -v $(pwd):/app -w /app golang:1.23-alpine gofmt -w .
```

### Run vet
```bash
docker run --rm -v $(pwd):/app -w /app golang:1.23-alpine go vet ./...
```

## Debugging

### Check container status
```bash
docker compose ps
```

### Read logs to a file (for inspection)
```bash
docker compose logs --tail 50 > .docker-logs.txt
```

### Inspect the running container
```bash
docker compose exec emby-bridge ls /data/
```
Note: distroless has no shell — only commands baked into the image work.

## Docker Compose Volume

The SQLite database lives in a named volume mounted at `/data`. The default `DATABASE_PATH` is `/data/users.db`.

If you need to wipe the database:
```bash
docker compose down
docker volume rm emby-web-oidc-bridge_bridge-data
docker compose up -d
```
