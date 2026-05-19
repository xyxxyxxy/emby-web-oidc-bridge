# Build stage
FROM golang:1.23-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /bridge ./cmd/bridge

# Final stage
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /bridge /bridge
EXPOSE 8080
ENTRYPOINT ["/bridge"]
