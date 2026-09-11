#!/bin/bash
# =======================================================================
#  ciotx — Deployment Script
#
#  One script to deploy everything:
#    - Validates .env configuration
#    - Installs Docker & Compose if missing
#    - Verifies DNS
#    - Obtains SSL certificate from Let's Encrypt
#    - Builds and launches the full stack
#    - Confirms deployment is healthy
#
#  Usage:
#    cp .env.example .env && nano .env
#    chmod +x scripts/deploy.sh
#    sudo ./scripts/deploy.sh
# =======================================================================

set -euo pipefail   # -e: exit on error, -u: undefined vars are errors, -o pipefail

# ── Colors ───────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${BLUE}[*]${NC} $1"; }
success() { echo -e "${GREEN}[+]${NC} $1"; }
warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
error()   { echo -e "${RED}[!] ERROR:${NC} $1" >&2; exit 1; }
header()  {
    echo -e "\n${BOLD}${BLUE}══════════════════════════════════════════════${NC}"
    echo -e "${BOLD}  $1${NC}"
    echo -e "${BOLD}${BLUE}══════════════════════════════════════════════${NC}\n"
}

# ── Prerequisites ────────────────────────────────────────────────────
[[ "$EUID" -ne 0 ]] && error "This script must be run as root (sudo ./scripts/deploy.sh)"

# ── Lock file — prevent concurrent deployments ───────────────────────
LOCK_FILE="/tmp/ciotx-deploy.lock"
if [ -f "$LOCK_FILE" ]; then
    error "Deployment already in progress (lock: $LOCK_FILE). If this is stale, run: rm $LOCK_FILE"
fi
echo $$ > "$LOCK_FILE"
trap 'rm -f "$LOCK_FILE"; echo -e "\n${RED}[!] Deployment interrupted.${NC}"' EXIT

# ── Repo root ────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$REPO_ROOT"

# =======================================================================
# STEP 0: Load + Validate .env
# =======================================================================
header "Step 0 — Configuration"

[[ ! -f .env ]] && error ".env not found.\n  Run: cp .env.example .env && nano .env"

# Load variables (skip comments and blanks)
set -a
# shellcheck disable=SC1091
source <(grep -v '^#' .env | grep -v '^$')
set +a

REQUIRED_VARS=(DOMAIN_NAME VPS_SERVER_IP SSL_EMAIL LLM_API_KEY MASTER_LICENSE_KEY POSTGRES_PASSWORD GITHUB_APP_ID GITHUB_APP_PRIVATE_KEY_BASE64 GITHUB_WEBHOOK_SECRET)
for var in "${REQUIRED_VARS[@]}"; do
    val="${!var:-}"
    [[ -z "$val" ]] && error "$var is not set in .env\n  See DEPLOY.md for how to create and configure the GitHub App."
    echo "$val" | grep -qiE "your-|change-me|example|1\.2\.3\.4|you@" \
        && error "$var still has its placeholder value — fill it in."
done

# ADMIN_PASSWORD is optional (panel is disabled when unset), but warn if placeholder wasn't changed.
ADMIN_PW="${ADMIN_PASSWORD:-}"
if [[ -n "$ADMIN_PW" ]]; then
    echo "$ADMIN_PW" | grep -qiE "change-me" \
        && error "ADMIN_PASSWORD still has its placeholder value — set a strong password or leave it empty to disable the admin panel."
    [[ ${#ADMIN_PW} -lt 12 ]] \
        && warn "ADMIN_PASSWORD is very short — use at least 24 random characters in production."
fi

[[ "${LLM_API_KEY}" != sk-* ]] \
    && warn "LLM_API_KEY doesn't start with 'sk-' — double check it's correct."

[[ ${#MASTER_LICENSE_KEY} -lt 20 ]] \
    && warn "MASTER_LICENSE_KEY is very short — use a long random value in production."

[[ ${#POSTGRES_PASSWORD} -lt 16 ]] \
    && warn "POSTGRES_PASSWORD is very short — use at least 32 random chars in production."

[[ ${#GITHUB_WEBHOOK_SECRET} -lt 16 ]] \
    && warn "GITHUB_WEBHOOK_SECRET is very short — generate one with: openssl rand -hex 32"

success "Configuration validated:"
info "  Domain : ${DOMAIN_NAME}"
info "  VPS IP : ${VPS_SERVER_IP}"
info "  Email  : ${SSL_EMAIL}"

# =======================================================================
# STEP 1: Docker
# =======================================================================
header "Step 1 — Docker"

if ! command -v docker &>/dev/null; then
    info "Docker not found — installing..."
    curl -fsSL https://get.docker.com | sh
    systemctl enable --now docker
    success "Docker installed."
else
    success "Docker $(docker --version | awk '{print $3}' | tr -d ',') already installed."
fi

if ! docker compose version &>/dev/null; then
    info "Installing Docker Compose plugin..."
    apt-get install -y docker-compose-plugin 2>/dev/null \
        || error "Could not install Docker Compose. See: https://docs.docker.com/compose/install/"
fi
success "Docker Compose $(docker compose version --short) ready."

# =======================================================================
# STEP 2: DNS Verification
# =======================================================================
header "Step 2 — DNS Verification"

info "Checking: ${DOMAIN_NAME} → ${VPS_SERVER_IP}"

RESOLVED=""
if command -v dig &>/dev/null; then
    RESOLVED=$(dig +short "${DOMAIN_NAME}" A 2>/dev/null | grep -E '^[0-9]+\.' | tail -1 || true)
elif command -v nslookup &>/dev/null; then
    RESOLVED=$(nslookup "${DOMAIN_NAME}" 2>/dev/null | awk '/^Address:/ && !/#/ { print $2 }' | tail -1 || true)
fi

if [[ -z "$RESOLVED" ]]; then
    warn "Cannot verify DNS (dig/nslookup not available) — proceeding anyway."
elif [[ "$RESOLVED" == "${VPS_SERVER_IP}" ]]; then
    success "DNS OK: ${DOMAIN_NAME} → ${RESOLVED}"
else
    warn "DNS mismatch: ${DOMAIN_NAME} resolves to ${RESOLVED} (expected ${VPS_SERVER_IP})"
    warn "SSL certificate request will fail if DNS hasn't propagated yet."
    read -rp "  Continue anyway? [y/N]: " answer
    [[ "${answer,,}" != "y" ]] && error "Aborted. Update your DNS A record and retry."
fi

# =======================================================================
# STEP 3: SSL Certificate
# =======================================================================
header "Step 3 — SSL Certificate"

CERT_LIVE="./data/certbot/conf/live/${DOMAIN_NAME}/fullchain.pem"

if [[ -f "$CERT_LIVE" ]]; then
    success "SSL certificate already exists — skipping."
    info "  To force renewal: docker compose run --rm certbot renew --force-renewal"
else
    info "Requesting SSL certificate from Let's Encrypt..."
    mkdir -p ./data/certbot/conf/live/"${DOMAIN_NAME}" ./data/certbot/www

    # Bootstrap: create a temporary self-signed cert so nginx can start for the ACME challenge
    info "Creating temporary self-signed certificate for nginx bootstrap..."
    openssl req -x509 -nodes -newkey rsa:2048 -days 1 \
        -keyout ./data/certbot/conf/live/"${DOMAIN_NAME}"/privkey.pem \
        -out    ./data/certbot/conf/live/"${DOMAIN_NAME}"/fullchain.pem \
        -subj "/CN=localhost" 2>/dev/null
    success "Bootstrap cert created."

    # Start nginx to serve the ACME HTTP-01 challenge
    info "Starting nginx for ACME challenge..."
    docker compose up -d nginx
    sleep 8

    # Remove the bootstrap cert directory so certbot can create it fresh.
    # Nginx has already loaded the cert into memory at startup — deleting the
    # files from disk is safe; nginx keeps serving until it is reloaded.
    rm -rf ./data/certbot/conf/live/"${DOMAIN_NAME}"

    # Request the real certificate
    # --entrypoint certbot overrides the renewal-loop entrypoint in docker-compose.yml
    # so that certonly actually runs instead of being passed as a positional arg to sh.
    info "Requesting certificate (this may take 30–60 seconds)..."
    docker compose run --rm --entrypoint certbot certbot certonly \
        --webroot \
        --webroot-path /var/www/certbot \
        --email "${SSL_EMAIL}" \
        --agree-tos \
        --no-eff-email \
        --force-renewal \
        -d "${DOMAIN_NAME}"

    success "SSL certificate obtained for ${DOMAIN_NAME}!"

    # Stop the bootstrap nginx (will restart with the real cert below)
    docker compose down
fi

# =======================================================================
# STEP 4: Build CLI Binaries (domain injected from .env)
# =======================================================================
header "Step 4 — Building CLI Binaries"

# Require Go to be installed on the build machine (the VPS)
if ! command -v go &>/dev/null; then
    info "Go not found — installing Go 1.27..."
    GO_TAR="go1.27.0.linux-amd64.tar.gz"
    curl -fsSL "https://dl.google.com/go/${GO_TAR}" -o "/tmp/${GO_TAR}"
    rm -rf /usr/local/go
    tar -C /usr/local -xzf "/tmp/${GO_TAR}"
    rm "/tmp/${GO_TAR}"
    success "Go installed."
fi
# Always ensure the standard Go install location is in PATH.
export PATH="/usr/local/go/bin:$PATH"
success "Go $(go version | awk '{print $3}') ready."

DIST_DIR="./dist"
mkdir -p "$DIST_DIR"

# Variables injected into every binary — DOMAIN_NAME is the single source of truth
VERSION=$(git describe --tags --always --dirty 2>/dev/null || echo "1.0.0")
COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS="-s -w \
  -X main.APIEndpoint=https://${DOMAIN_NAME} \
  -X main.WebsiteURL=https://${DOMAIN_NAME} \
  -X main.Version=${VERSION} \
  -X main.Commit=${COMMIT} \
  -X main.BuildDate=${BUILD_DATE}"

info "Compiling ciotx CLI for all platforms..."
info "  APIEndpoint  = https://${DOMAIN_NAME}"
info "  WebsiteURL   = https://${DOMAIN_NAME}"
info "  Version      = ${VERSION}"

(
  cd cli
  CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build -ldflags="${LDFLAGS}" -o "../${DIST_DIR}/ciotx-linux-amd64"     ./cmd/ciotx && info "  [+] linux/amd64"
  CGO_ENABLED=0 GOOS=linux   GOARCH=arm64 go build -ldflags="${LDFLAGS}" -o "../${DIST_DIR}/ciotx-linux-arm64"     ./cmd/ciotx && info "  [+] linux/arm64"
  CGO_ENABLED=0 GOOS=darwin  GOARCH=amd64 go build -ldflags="${LDFLAGS}" -o "../${DIST_DIR}/ciotx-darwin-amd64"    ./cmd/ciotx && info "  [+] darwin/amd64"
  CGO_ENABLED=0 GOOS=darwin  GOARCH=arm64 go build -ldflags="${LDFLAGS}" -o "../${DIST_DIR}/ciotx-darwin-arm64"    ./cmd/ciotx && info "  [+] darwin/arm64 (Apple Silicon)"
  CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="${LDFLAGS}" -o "../${DIST_DIR}/ciotx-windows-amd64.exe" ./cmd/ciotx && info "  [+] windows/amd64"
)
success "All CLI binaries built in ${DIST_DIR}/"

# ── Generate install.sh dynamically with DOMAIN_NAME baked in ────────
info "Generating install.sh with domain: ${DOMAIN_NAME}..."
cat > ./scripts/install.sh << INSTALL_SCRIPT
#!/bin/sh
# ciotx installer — generated by deploy.sh for ${DOMAIN_NAME}
# curl -fsSL https://${DOMAIN_NAME}/install.sh | sh

set -e

CIOTX_DOMAIN="https://${DOMAIN_NAME}"
CIOTX_VERSION="${VERSION}"
INSTALL_DIR="/usr/local/bin"

echo ""
echo "  ciotx — Security Auditor v\${CIOTX_VERSION}"
echo "  Installing from \${CIOTX_DOMAIN}..."
echo ""

OS="\$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="\$(uname -m)"

case "\${ARCH}" in
  x86_64)        ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) echo "[!] Unsupported architecture: \${ARCH}"; exit 1 ;;
esac

case "\${OS}" in
  linux|darwin) ;;
  *) echo "[!] Unsupported OS: \${OS}. Windows: download from \${CIOTX_DOMAIN}/releases/"; exit 1 ;;
esac

BINARY="ciotx-\${OS}-\${ARCH}"
URL="\${CIOTX_DOMAIN}/releases/\${BINARY}"

echo "  Platform : \${OS}/\${ARCH}"
echo "  Downloading..."

TMP="\$(mktemp -d)"
trap 'rm -rf \$TMP' EXIT

curl -fsSL "\${URL}" -o "\${TMP}/ciotx" || {
  echo "[!] Download failed. Check: \${URL}"
  exit 1
}

chmod +x "\${TMP}/ciotx"

sudo mkdir -p "\${INSTALL_DIR}"
if [ -w "\${INSTALL_DIR}" ]; then
  mv "\${TMP}/ciotx" "\${INSTALL_DIR}/ciotx"
else
  sudo mv "\${TMP}/ciotx" "\${INSTALL_DIR}/ciotx"
fi

echo ""
echo "  [+] ciotx installed!"
echo ""
echo "  Next:"
echo "    ciotx auth login"
echo "    ciotx scan ."
echo ""
echo "  Get your license key at \${CIOTX_DOMAIN}"
echo ""
INSTALL_SCRIPT

chmod +x ./scripts/install.sh ./scripts/update.sh
success "install.sh generated with domain: ${DOMAIN_NAME}"

# ── Copy built binaries to nginx static dir for serving ──────────────
RELEASES_DIR="./data/static/releases"
mkdir -p "$RELEASES_DIR"
cp "${DIST_DIR}"/ciotx-* "$RELEASES_DIR/"
success "Binaries copied to ${RELEASES_DIR}/ for download"

# =======================================================================
# STEP 5: Build Docker Images + Launch
# =======================================================================
header "Step 5 — Building & Deploying"

info "Building Docker images (this takes a few minutes on first run)..."
docker compose build --no-cache

info "Starting all services..."
docker compose up -d

info "Waiting for services to initialize..."
sleep 20

# =======================================================================
# STEP 6: Health Check
# =======================================================================
header "Step 6 — Health Verification"

MAX_ATTEMPTS=12
WAIT_SECONDS=5

for attempt in $(seq 1 $MAX_ATTEMPTS); do
    HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" \
        "https://${DOMAIN_NAME}/health" 2>/dev/null || echo "000")

    if [[ "$HTTP_CODE" == "200" ]]; then
        success "Health check passed — API is live at https://${DOMAIN_NAME}"
        break
    fi

    warn "Attempt ${attempt}/${MAX_ATTEMPTS} — got HTTP ${HTTP_CODE}, retrying in ${WAIT_SECONDS}s..."
    sleep "$WAIT_SECONDS"

    if [[ "$attempt" -eq "$MAX_ATTEMPTS" ]]; then
        warn "Health check did not pass. Showing logs:"
        docker compose logs --tail=30 api
        error "Deployment may have failed. Check logs above."
    fi
done

# ── Remove lock file cleanly ─────────────────────────────────────────
rm -f "$LOCK_FILE"
trap - EXIT

# =======================================================================
# Done
# =======================================================================
echo ""
echo -e "${BOLD}${GREEN}╔══════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${GREEN}║         ciotx Deployed Successfully!         ║${NC}"
echo -e "${BOLD}${GREEN}╚══════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${BOLD}API Endpoint  ${NC}: https://${DOMAIN_NAME}"
echo -e "  ${BOLD}Health Check  ${NC}: https://${DOMAIN_NAME}/health"
echo -e "  ${BOLD}Install Script${NC}: https://${DOMAIN_NAME}/install.sh"
if [[ -n "${ADMIN_PASSWORD:-}" ]]; then
echo -e "  ${BOLD}Admin Panel   ${NC}: https://${DOMAIN_NAME}/admin"
fi
echo ""
echo -e "  ${BOLD}Your master license key:${NC} ${MASTER_LICENSE_KEY}"
echo ""
echo -e "  ${BOLD}User install command:${NC}"
echo -e "  ${BLUE}curl -fsSL https://${DOMAIN_NAME}/install.sh | sh${NC}"
echo ""
echo -e "  ${BOLD}Issue a customer license key:${NC}"
echo -e "  ${BLUE}docker compose exec api /ciotx-server license create --org \"Acme Corp\" --email user@acme.com --plan pro --scans 500${NC}"
echo ""
echo -e "  ${BOLD}List all licenses:${NC}"
echo -e "  ${BLUE}docker compose exec api /ciotx-server license list${NC}"
echo ""
echo -e "  ${BOLD}To update after pushing new code:${NC}"
echo -e "  ${BLUE}sudo ./scripts/update.sh${NC}      # pull + rebuild CLI + restart server"
echo ""
echo -e "  ${BOLD}Useful commands:${NC}"
echo -e "  ${BLUE}docker compose logs -f api${NC}    # live API logs"
echo -e "  ${BLUE}docker compose ps${NC}             # service status"
echo -e "  ${BLUE}docker compose down${NC}           # stop everything"
echo -e "  ${BLUE}docker compose up -d${NC}          # start again"
echo ""
