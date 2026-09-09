# ciotx API Server — Multi-stage build
# Stage 1: Build the Go binary
FROM golang:1.21-alpine AS builder
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /build
COPY go.mod .
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-s -w" \
    -o ciotx-server ./

# Stage 2: Minimal Alpine runtime (~7MB) — has wget for healthcheck, no shell exposed
FROM alpine:3.19
# TLS root certs + timezone data only — nothing else
RUN apk add --no-cache ca-certificates tzdata wget && \
    addgroup -S ciotx && adduser -S ciotx -G ciotx
COPY --from=builder /build/ciotx-server /ciotx-server
# Run as non-root
USER ciotx
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget -qO- http://localhost:8080/health || exit 1
ENTRYPOINT ["/ciotx-server"]
