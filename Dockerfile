# Build stage
FROM golang:1.24-alpine AS builder

ARG VERSION=development

RUN apk add --no-cache git ca-certificates

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w -X main.version=$VERSION" \
    -o auth-service ./cmd/server

# Final stage
FROM alpine:3.18

RUN apk add --no-cache ca-certificates tzdata curl

ENV TZ=Asia/Kolkata

RUN adduser -D -g '' appuser

WORKDIR /app

COPY --from=builder /app/auth-service .
COPY --from=builder /app/config/app-config.yaml ./config/

RUN chown -R appuser:appuser /app
USER appuser

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s \
    CMD curl --fail http://localhost:8080/health || exit 1

CMD ["./auth-service"]
