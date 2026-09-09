#!/bin/bash
# init-letsencrypt.sh
# Run this ONCE on your VPS before starting the full stack.
# It gets your initial SSL certificate from Let's Encrypt.
#
# Usage:
#   chmod +x scripts/init-letsencrypt.sh
#   ./scripts/init-letsencrypt.sh

set -e

# Load environment variables from .env
if [ ! -f .env ]; then
    echo "[!] .env file not found. Copy .env.example to .env and fill in your values."
    exit 1
fi
export $(grep -v '^#' .env | xargs)

echo "=================================================="
echo "  ciotx — Let's Encrypt SSL Initialization"
echo "=================================================="
echo "  Domain    : ${DOMAIN_NAME}"
echo "  Email     : ${SSL_EMAIL}"
echo "  Server IP : ${VPS_SERVER_IP}"
echo "=================================================="
echo ""

# Ensure certbot directories exist
mkdir -p ./data/certbot/conf
mkdir -p ./data/certbot/www

# Check DNS resolves to this server
echo "[1/3] Checking DNS for ${DOMAIN_NAME}..."
RESOLVED_IP=$(dig +short "${DOMAIN_NAME}" | tail -1)
if [ "$RESOLVED_IP" != "$VPS_SERVER_IP" ]; then
    echo ""
    echo "[!] Warning: ${DOMAIN_NAME} resolves to ${RESOLVED_IP}"
    echo "    Expected : ${VPS_SERVER_IP}"
    echo "    DNS may not have propagated yet. Continue anyway? (y/N)"
    read -r answer
    if [ "$answer" != "y" ] && [ "$answer" != "Y" ]; then
        echo "Aborted. Update your DNS A record and try again."
        exit 1
    fi
fi

# Start nginx in HTTP-only mode temporarily for ACME challenge
echo "[2/3] Starting nginx for ACME challenge..."
docker compose up -d nginx

sleep 3

# Request certificate
echo "[3/3] Requesting SSL certificate from Let's Encrypt..."
docker compose run --rm certbot certonly \
    --webroot \
    --webroot-path /var/www/certbot \
    --email "${SSL_EMAIL}" \
    --agree-tos \
    --no-eff-email \
    -d "${DOMAIN_NAME}"

echo ""
echo "=================================================="
echo "  [+] SSL certificate obtained successfully!"
echo "  Now run: docker compose up -d --build"
echo "=================================================="
