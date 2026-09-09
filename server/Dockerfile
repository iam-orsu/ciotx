# ciotx API Server
# Multi-stage build: produces a minimal ~15MB scratch image with zero attack surface

# Stage 1: Build
FROM golang:1.21-alpine AS builder
WORKDIR /build
COPY go.mod .
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-s -w" \
    -o ciotx-server ./

# Stage 2: Minimal runtime image
FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /build/ciotx-server /ciotx-server
EXPOSE 8080
ENTRYPOINT ["/ciotx-server"]
