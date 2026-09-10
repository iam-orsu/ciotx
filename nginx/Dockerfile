FROM nginx:1.27-alpine

# Install envsubst (from gettext) for dynamic config generation at runtime
RUN apk add --no-cache gettext

# Copy the nginx config template
COPY nginx.conf.template /etc/nginx/templates/nginx.conf.template

# Rate limiting zones (defined in http{} context via conf.d include).
# api:      10r/m — for /v1/ scan endpoints (one scan = one long-running request)
# api_admin: 60r/m — for /admin panel; dashboard refreshes every 60s across ~3 endpoints
RUN printf 'limit_req_zone $binary_remote_addr zone=api:10m rate=10r/m;\nlimit_req_zone $binary_remote_addr zone=api_admin:5m rate=60r/m;\n' \
    > /etc/nginx/conf.d/rate_limit.conf

# Startup script: substitutes DOMAIN_NAME into config then starts nginx
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

EXPOSE 80 443
ENTRYPOINT ["/docker-entrypoint.sh"]
