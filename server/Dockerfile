# ciotx API Server — Multi-stage build
# Stage 1: Build the Go binary
FROM golang:1.21-alpine AS builder
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /build

# Copy dependency manifests first for layer caching.
# Docker only re-runs 'go mod download' when go.mod/go.sum change, not on every source edit.
COPY go.mod go.sum* ./
RUN go mod download

# Copy source and build
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-s -w" \
    -o ciotx-server ./

# Stage 2: Minimal Alpine runtime — has wget for healthcheck
FROM alpine:3.19
# ca-certificates: required for outbound HTTPS to LLM provider
# tzdata: consistent log timestamps across timezones
# wget: used by Docker HEALTHCHECK
RUN apk add --no-cache ca-certificates tzdata wget && \
    addgroup -S ciotx && adduser -S ciotx -G ciotx

COPY --from=builder /build/ciotx-server /ciotx-server

# Run as non-root — container has no shell, no package manager, minimal attack surface
USER ciotx
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD wget -qO- http://localhost:8080/health || exit 1
ENTRYPOINT ["/ciotx-server"]
