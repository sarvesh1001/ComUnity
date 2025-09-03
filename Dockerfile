# ---- Build stage ----
    FROM golang:1.24-alpine AS builder

    ARG VERSION=development
    RUN apk add --no-cache git ca-certificates
    
    WORKDIR /app
    
    COPY go.mod go.sum ./
    RUN go mod download
    
    COPY . .
    
    # Build with a different output name to avoid conflict
    RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
        go build -ldflags="-s -w -X main.version=$VERSION" \
        -o /app/server-binary ./cmd/server  # Changed from auth-service to server-binary
    
    # ---- Final stage ----
    FROM alpine:3.18
    
    RUN apk add --no-cache ca-certificates tzdata curl
    ENV TZ=Asia/Kolkata
    
    RUN adduser -D -g '' appuser
    WORKDIR /app
    
    # Copy the binary with the new name
    COPY --from=builder /app/server-binary /usr/local/bin/auth-service
    COPY --from=builder /app/config/app-config.yaml ./config/
    
    RUN chown -R appuser:appuser /app
    USER appuser
    
    EXPOSE 8443
    HEALTHCHECK --interval=30s --timeout=3s \
        CMD curl --fail https://localhost:8443/health || exit 1
    
    CMD ["/usr/local/bin/auth-service"]