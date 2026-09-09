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

REQUIRED_VARS=(DOMAIN_NAME VPS_SERVER_IP SSL_EMAIL LLM_API_KEY MASTER_LICENSE_KEY)
for var in "${REQUIRED_VARS[@]}"; do
    val="${!var:-}"
    [[ -z "$val" ]] && error "$var is not set in .env"
    echo "$val" | grep -qiE "your-|change-me|example|1\.2\.3\.4|you@" \
        && error "$var still has its placeholder value — fill it in."
done

[[ "${LLM_API_KEY}" != sk-* ]] \
    && warn "LLM_API_KEY doesn't start with 'sk-' — double check it's correct."

[[ ${#MASTER_LICENSE_KEY} -lt 20 ]] \
    && warn "MASTER_LICENSE_KEY is very short — use a long random value in production."

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

    # Request the real certificate
    info "Requesting certificate (this may take 30–60 seconds)..."
    docker compose run --rm certbot certonly \
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
# STEP 4: Build + Launch
# =======================================================================
header "Step 4 — Building & Deploying"

info "Building Docker images (this takes a few minutes on first run)..."
docker compose build --no-cache

info "Starting all services..."
docker compose up -d

info "Waiting for services to initialize..."
sleep 20

# =======================================================================
# STEP 5: Health Check
# =======================================================================
header "Step 5 — Health Verification"

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
echo ""
echo -e "  ${BOLD}Your master license key:${NC} ${MASTER_LICENSE_KEY}"
echo ""
echo -e "  ${BOLD}User install command:${NC}"
echo -e "  ${BLUE}curl -fsSL https://${DOMAIN_NAME}/install.sh | sh${NC}"
echo ""
echo -e "  ${BOLD}Useful commands:${NC}"
echo -e "  ${BLUE}docker compose logs -f api${NC}    # live API logs"
echo -e "  ${BLUE}docker compose ps${NC}             # service status"
echo -e "  ${BLUE}docker compose down${NC}           # stop everything"
echo -e "  ${BLUE}docker compose up -d${NC}          # start again"
echo ""
