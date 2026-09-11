#!/bin/bash
# =======================================================================
#  ciotx — Update Script
#
#  Pulls latest code, rebuilds CLI binaries for all platforms,
#  rebuilds the server Docker image, and restarts all services.
#
#  Usage:
#    sudo ./scripts/update.sh
# =======================================================================

set -euo pipefail

GREEN='\033[0;32m'; BLUE='\033[0;34m'; RED='\033[0;31m'; BOLD='\033[1m'; NC='\033[0m'
info()    { echo -e "${BLUE}[*]${NC} $1"; }
success() { echo -e "${GREEN}[+]${NC} $1"; }
error()   { echo -e "${RED}[!] ERROR:${NC} $1" >&2; exit 1; }

[[ "$EUID" -ne 0 ]] && error "Run as root: sudo ./scripts/update.sh"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$REPO_ROOT"

# ── Load .env ────────────────────────────────────────────────────────
[[ ! -f .env ]] && error ".env not found."
set -a
source <(grep -v '^#' .env | grep -v '^$')
set +a
[[ -z "${DOMAIN_NAME:-}" ]] && error "DOMAIN_NAME not set in .env"

echo ""
echo -e "${BOLD}${BLUE}══════════════════════════════════════════════${NC}"
echo -e "${BOLD}  ciotx Update${NC}"
echo -e "${BOLD}${BLUE}══════════════════════════════════════════════${NC}"
echo ""

# ── Step 1: Pull latest code ─────────────────────────────────────────
info "Pulling latest code..."
git stash 2>/dev/null || true
git pull
success "Code updated to $(git rev-parse --short HEAD)."

# ── Step 2: Ensure Go is available ───────────────────────────────────
if ! command -v go &>/dev/null; then
    info "Go not found — installing Go 1.27..."
    GO_TAR="go1.27.0.linux-amd64.tar.gz"
    curl -fsSL "https://dl.google.com/go/${GO_TAR}" -o "/tmp/${GO_TAR}"
    rm -rf /usr/local/go
    tar -C /usr/local -xzf "/tmp/${GO_TAR}"
    export PATH="/usr/local/go/bin:$PATH"
    rm "/tmp/${GO_TAR}"
fi
export PATH="/usr/local/go/bin:$PATH"
success "Go $(go version | awk '{print $3}') ready."

# ── Step 3: Build CLI binaries for all platforms ─────────────────────
info "Building CLI binaries..."

mkdir -p dist data/static/releases

VERSION=$(git describe --tags --always --dirty 2>/dev/null || echo "1.0.0")
COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS="-s -w \
  -X main.APIEndpoint=https://${DOMAIN_NAME} \
  -X main.WebsiteURL=https://${DOMAIN_NAME} \
  -X main.Version=${VERSION} \
  -X main.Commit=${COMMIT} \
  -X main.BuildDate=${BUILD_DATE}"

(
  cd cli
  CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build -ldflags="${LDFLAGS}" -o "../dist/ciotx-linux-amd64"       ./cmd/ciotx && info "  [+] linux/amd64"
  CGO_ENABLED=0 GOOS=linux   GOARCH=arm64 go build -ldflags="${LDFLAGS}" -o "../dist/ciotx-linux-arm64"       ./cmd/ciotx && info "  [+] linux/arm64"
  CGO_ENABLED=0 GOOS=darwin  GOARCH=amd64 go build -ldflags="${LDFLAGS}" -o "../dist/ciotx-darwin-amd64"      ./cmd/ciotx && info "  [+] darwin/amd64"
  CGO_ENABLED=0 GOOS=darwin  GOARCH=arm64 go build -ldflags="${LDFLAGS}" -o "../dist/ciotx-darwin-arm64"      ./cmd/ciotx && info "  [+] darwin/arm64 (Apple Silicon)"
  CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="${LDFLAGS}" -o "../dist/ciotx-windows-amd64.exe" ./cmd/ciotx && info "  [+] windows/amd64"
)

cp dist/ciotx-* data/static/releases/
success "CLI binaries built and deployed to data/static/releases/."

# ── Step 4: Rebuild server and restart all services ──────────────────
info "Rebuilding server and restarting services..."
docker compose up --build -d
success "Services restarted."

# ── Step 5: Health check ─────────────────────────────────────────────
info "Waiting for API to be healthy..."
sleep 10
for attempt in $(seq 1 12); do
    HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" "https://${DOMAIN_NAME}/health" 2>/dev/null || echo "000")
    if [[ "$HTTP_CODE" == "200" ]]; then
        success "Health check passed."
        break
    fi
    info "  Attempt ${attempt}/12 — HTTP ${HTTP_CODE}, retrying..."
    sleep 5
    if [[ "$attempt" -eq 12 ]]; then
        echo ""
        docker compose logs --tail=20 api
        error "API did not come up healthy. Check logs above."
    fi
done

echo ""
echo -e "${BOLD}${GREEN}[+] Update complete — v${VERSION} (${COMMIT})${NC}"
echo -e "    API     : https://${DOMAIN_NAME}"
echo -e "    Clients : curl -fsSL https://${DOMAIN_NAME}/install.sh | sh"
echo ""
