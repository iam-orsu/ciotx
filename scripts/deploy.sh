#!/bin/bash
# =======================================================================
#  ciotx — Full Deployment Script
#  Run this ONCE on your VPS after setting up your .env file.
#
#  What this does:
#    1. Validates your .env config
#    2. Installs Docker & Docker Compose (if not present)
#    3. Checks DNS resolves correctly
#    4. Gets your SSL certificate from Let's Encrypt
#    5. Builds and launches the full Docker stack
#    6. Verifies the deployment is healthy
#
#  Usage:
#    cp .env.example .env
#    nano .env        # fill in your values
#    chmod +x scripts/deploy.sh
#    ./scripts/deploy.sh
# =======================================================================

set -e

# ── Colour output ────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m' # No Colour

info()    { echo -e "${BLUE}[*]${NC} $1"; }
success() { echo -e "${GREEN}[+]${NC} $1"; }
warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
error()   { echo -e "${RED}[!]${NC} $1"; exit 1; }
header()  { echo -e "\n${BOLD}${BLUE}══════════════════════════════════════════${NC}"; echo -e "${BOLD}  $1${NC}"; echo -e "${BOLD}${BLUE}══════════════════════════════════════════${NC}\n"; }

# ── Must run from repo root ──────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$REPO_ROOT"

# =======================================================================
# STEP 0: Load and validate .env
# =======================================================================
header "Step 0 — Loading Configuration"

if [ ! -f .env ]; then
    error ".env not found. Run: cp .env.example .env — then fill in your values."
fi

# Load env vars (ignore comments and blank lines)
set -a
# shellcheck disable=SC1091
source .env
set +a

# Validate required fields
REQUIRED_VARS="DOMAIN_NAME VPS_SERVER_IP SSL_EMAIL LLM_API_KEY MASTER_LICENSE_KEY"
for var in $REQUIRED_VARS; do
    val="${!var}"
    if [ -z "$val" ] || [ "$val" = "your-value-here" ] || echo "$val" | grep -q "change-me\|your-api-key\|your@email\|1\.2\.3\.4"; then
        error "Missing or default value for $var in .env — please fill it in."
    fi
done

# Validate LLM_API_KEY starts with "sk-"
if ! echo "$LLM_API_KEY" | grep -q "^sk-"; then
    warn "LLM_API_KEY doesn't start with 'sk-' — double-check it is correct."
fi

success "Configuration loaded:"
info "  Domain  : $DOMAIN_NAME"
info "  VPS IP  : $VPS_SERVER_IP"
info "  Email   : $SSL_EMAIL"
info "  API Key : ${LLM_API_KEY:0:8}... (redacted)"

# =======================================================================
# STEP 1: Install Docker & Docker Compose
# =======================================================================
header "Step 1 — Docker"

install_docker() {
    info "Installing Docker..."
    curl -fsSL https://get.docker.com | sh
    systemctl enable docker
    systemctl start docker
    success "Docker installed."
}

if ! command -v docker &>/dev/null; then
    install_docker
else
    DOCKER_VER=$(docker --version | awk '{print $3}' | tr -d ',')
    success "Docker already installed (v$DOCKER_VER)"
fi

if ! docker compose version &>/dev/null; then
    info "Installing Docker Compose plugin..."
    apt-get install -y docker-compose-plugin 2>/dev/null || \
        pip3 install docker-compose 2>/dev/null || \
        error "Could not install Docker Compose. Install it manually: https://docs.docker.com/compose/install/"
fi

COMPOSE_VER=$(docker compose version --short 2>/dev/null || echo "unknown")
success "Docker Compose ready (v$COMPOSE_VER)"

# =======================================================================
# STEP 2: Check DNS
# =======================================================================
header "Step 2 — DNS Verification"

info "Checking DNS: $DOMAIN_NAME → $VPS_SERVER_IP"

if command -v dig &>/dev/null; then
    RESOLVED=$(dig +short "$DOMAIN_NAME" A | tail -1)
elif command -v nslookup &>/dev/null; then
    RESOLVED=$(nslookup "$DOMAIN_NAME" 2>/dev/null | awk '/^Address: / { print $2 }' | tail -1)
else
    RESOLVED=""
    warn "Neither dig nor nslookup found — skipping DNS check."
fi

if [ -n "$RESOLVED" ] && [ "$RESOLVED" != "$VPS_SERVER_IP" ]; then
    warn "DNS mismatch: $DOMAIN_NAME resolves to $RESOLVED (expected $VPS_SERVER_IP)"
    warn "SSL certificate request may fail if DNS hasn't propagated yet."
    echo -n "  Continue anyway? [y/N]: "
    read -r answer
    if [ "$answer" != "y" ] && [ "$answer" != "Y" ]; then
        error "Aborted. Update your DNS A record and re-run this script."
    fi
elif [ -n "$RESOLVED" ]; then
    success "DNS OK: $DOMAIN_NAME → $RESOLVED"
fi

# =======================================================================
# STEP 3: SSL Certificate (Let's Encrypt)
# =======================================================================
header "Step 3 — SSL Certificate"

CERT_PATH="./data/certbot/conf/live/$DOMAIN_NAME/fullchain.pem"

if [ -f "$CERT_PATH" ]; then
    success "SSL certificate already exists for $DOMAIN_NAME — skipping."
else
    info "Requesting SSL certificate from Let's Encrypt..."
    info "Domain: $DOMAIN_NAME"
    info "Email : $SSL_EMAIL"

    # Create directories
    mkdir -p ./data/certbot/conf ./data/certbot/www

    # Start nginx in HTTP-only mode for ACME challenge
    info "Starting nginx for ACME challenge..."
    # Temporarily use a self-signed cert placeholder so nginx starts
    if [ ! -f ./data/certbot/conf/live/$DOMAIN_NAME/fullchain.pem ]; then
        mkdir -p ./data/certbot/conf/live/$DOMAIN_NAME
        openssl req -x509 -nodes -newkey rsa:4096 -days 1 \
            -keyout ./data/certbot/conf/live/$DOMAIN_NAME/privkey.pem \
            -out    ./data/certbot/conf/live/$DOMAIN_NAME/fullchain.pem \
            -subj '/CN=localhost' 2>/dev/null
        success "Temporary self-signed cert created for nginx bootstrap."
    fi

    # Start just nginx (needs port 80 for ACME challenge)
    docker compose up -d nginx

    # Wait for nginx to be ready
    sleep 5

    # Request the real certificate
    info "Running certbot..."
    docker compose run --rm certbot certonly \
        --webroot \
        --webroot-path /var/www/certbot \
        --email "$SSL_EMAIL" \
        --agree-tos \
        --no-eff-email \
        --force-renewal \
        -d "$DOMAIN_NAME"

    # Stop nginx (will be restarted with real cert below)
    docker compose down

    success "SSL certificate obtained for $DOMAIN_NAME"
fi

# =======================================================================
# STEP 4: Build and Launch Full Stack
# =======================================================================
header "Step 4 — Deploying ciotx"

info "Building Docker images..."
docker compose build --no-cache

info "Starting all services..."
docker compose up -d

# Wait for services to initialise
info "Waiting for services to start..."
sleep 15

# =======================================================================
# STEP 5: Verify Deployment
# =======================================================================
header "Step 5 — Health Check"

MAX_ATTEMPTS=10
attempt=1
while [ $attempt -le $MAX_ATTEMPTS ]; do
    HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" "https://$DOMAIN_NAME/health" 2>/dev/null || echo "000")
    if [ "$HTTP_CODE" = "200" ]; then
        success "Health check passed (HTTPS → $DOMAIN_NAME → API server)"
        break
    fi
    warn "Attempt $attempt/$MAX_ATTEMPTS — health check returned HTTP $HTTP_CODE, retrying in 5s..."
    sleep 5
    attempt=$((attempt + 1))
done

if [ $attempt -gt $MAX_ATTEMPTS ]; then
    warn "Health check did not pass after $MAX_ATTEMPTS attempts."
    warn "Check logs with: docker compose logs api"
    warn "Check logs with: docker compose logs nginx"
else
    # Final summary
    echo ""
    echo -e "${BOLD}${GREEN}══════════════════════════════════════════${NC}"
    echo -e "${BOLD}${GREEN}  ciotx Deployed Successfully!${NC}"
    echo -e "${BOLD}${GREEN}══════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${BOLD}API Endpoint${NC}  : https://$DOMAIN_NAME"
    echo -e "  ${BOLD}Install Script${NC}: https://$DOMAIN_NAME/install.sh"
    echo -e "  ${BOLD}Health Check${NC}  : https://$DOMAIN_NAME/health"
    echo ""
    echo -e "  ${BOLD}User install command:${NC}"
    echo -e "  ${BLUE}curl -fsSL https://$DOMAIN_NAME/install.sh | sh${NC}"
    echo ""
    echo -e "  ${BOLD}Your test license key:${NC}"
    echo -e "  ${BLUE}$MASTER_LICENSE_KEY${NC}"
    echo ""
    echo -e "  ${BOLD}Useful commands:${NC}"
    echo -e "  docker compose logs -f api       # live server logs"
    echo -e "  docker compose logs -f nginx     # nginx logs"
    echo -e "  docker compose ps                # service status"
    echo -e "  docker compose down              # stop everything"
    echo ""
fi
