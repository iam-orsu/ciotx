#!/bin/sh
set -e

# Substitute DOMAIN_NAME (and other env vars) into the nginx config template
envsubst '${DOMAIN_NAME}' < /etc/nginx/templates/nginx.conf.template \
    > /etc/nginx/conf.d/default.conf

echo "[nginx] Config generated for domain: ${DOMAIN_NAME}"

# Start nginx in foreground
exec nginx -g 'daemon off;'
