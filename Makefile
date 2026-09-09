# ciotx Makefile
# Usage: make [target]

# ── Build metadata injected at compile time ──────────────────────────
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT      := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE  := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

# Read DOMAIN_NAME from .env if it exists, fallback to localhost for dev
-include .env
export
DOMAIN_NAME ?= localhost
API_ENDPOINT := https://$(DOMAIN_NAME)
WEBSITE_URL  := https://$(DOMAIN_NAME)

CLI_LDFLAGS := -s -w \
	-X main.Version=$(VERSION) \
	-X main.Commit=$(COMMIT) \
	-X main.BuildDate=$(BUILD_DATE) \
	-X main.APIEndpoint=$(API_ENDPOINT) \
	-X main.WebsiteURL=$(WEBSITE_URL)

CLI_DIR     := ./cli
SERVER_DIR  := ./server
DIST_DIR    := ./dist

.PHONY: all build build-cli build-server test lint clean docker-build docker-up docker-down help

## all: Build CLI for all platforms + server image
all: build

## build: Build CLI binary for current platform
build: build-cli

## build-cli: Build the ciotx CLI binary
build-cli:
	@echo "==> Building ciotx CLI ($(VERSION)) for $(shell go env GOOS)/$(shell go env GOARCH)..."
	@mkdir -p $(DIST_DIR)
	@cd $(CLI_DIR) && go build \
		-ldflags="$(CLI_LDFLAGS)" \
		-o ../$(DIST_DIR)/ciotx \
		./cmd/ciotx
	@echo "==> Binary: $(DIST_DIR)/ciotx"

## build-all: Cross-compile CLI for Linux, macOS, Windows (amd64 + arm64)
build-all:
	@echo "==> Cross-compiling ciotx CLI ($(VERSION))..."
	@mkdir -p $(DIST_DIR)
	@cd $(CLI_DIR) && \
	GOOS=linux   GOARCH=amd64  go build -ldflags="$(CLI_LDFLAGS)" -o ../$(DIST_DIR)/ciotx-linux-amd64    ./cmd/ciotx && \
	GOOS=linux   GOARCH=arm64  go build -ldflags="$(CLI_LDFLAGS)" -o ../$(DIST_DIR)/ciotx-linux-arm64    ./cmd/ciotx && \
	GOOS=darwin  GOARCH=amd64  go build -ldflags="$(CLI_LDFLAGS)" -o ../$(DIST_DIR)/ciotx-darwin-amd64   ./cmd/ciotx && \
	GOOS=darwin  GOARCH=arm64  go build -ldflags="$(CLI_LDFLAGS)" -o ../$(DIST_DIR)/ciotx-darwin-arm64   ./cmd/ciotx && \
	GOOS=windows GOARCH=amd64  go build -ldflags="$(CLI_LDFLAGS)" -o ../$(DIST_DIR)/ciotx-windows-amd64.exe ./cmd/ciotx
	@echo "==> Cross-compiled binaries in $(DIST_DIR)/"
	@ls -lh $(DIST_DIR)/

## build-server: Build the server binary only (Docker uses this)
build-server:
	@echo "==> Building ciotx server..."
	@cd $(SERVER_DIR) && go build -ldflags="-s -w" -o ../$(DIST_DIR)/ciotx-server ./
	@echo "==> Binary: $(DIST_DIR)/ciotx-server"

## test: Run all tests
test:
	@echo "==> Running CLI tests..."
	@cd $(CLI_DIR) && go test ./... -v -race -timeout 60s
	@echo "==> Running server tests..."
	@cd $(SERVER_DIR) && go test ./... -v -race -timeout 60s

## vet: Run go vet on all packages
vet:
	@echo "==> go vet (cli)..."
	@cd $(CLI_DIR) && go vet ./...
	@echo "==> go vet (server)..."
	@cd $(SERVER_DIR) && go vet ./...

## lint: Run golangci-lint (requires golangci-lint installed)
lint:
	@which golangci-lint > /dev/null || (echo "Install golangci-lint: https://golangci-lint.run/usage/install/" && exit 1)
	@cd $(CLI_DIR) && golangci-lint run ./...
	@cd $(SERVER_DIR) && golangci-lint run ./...

## docker-build: Build Docker images
docker-build:
	@echo "==> Building Docker images..."
	docker compose build

## docker-up: Start the full stack in background
docker-up:
	@echo "==> Starting ciotx stack..."
	docker compose up -d
	@echo "==> Stack started. Logs: make docker-logs"

## docker-down: Stop the stack
docker-down:
	docker compose down

## docker-logs: Follow live logs
docker-logs:
	docker compose logs -f

## clean: Remove build artifacts
clean:
	@echo "==> Cleaning build artifacts..."
	@rm -rf $(DIST_DIR)
	@echo "==> Clean."

## help: Show this help
help:
	@echo ""
	@echo "  ciotx — Build Targets"
	@echo ""
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## /  /' | column -t -s ':'
	@echo ""
