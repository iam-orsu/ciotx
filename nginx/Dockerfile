FROM nginx:1.27-alpine

# Install envsubst (from gettext) for dynamic config generation at runtime
RUN apk add --no-cache gettext

# Copy the nginx config template
COPY nginx.conf.template /etc/nginx/templates/nginx.conf.template

# Rate limiting zone (defined in http{} context via conf.d include)
# 10r/m = ~1 request per 6 seconds per IP — generous for a scan tool (one scan = one request)
# The burst=10 in nginx.conf.template allows short bursts (e.g. auth + scan back-to-back)
RUN echo 'limit_req_zone $binary_remote_addr zone=api:10m rate=10r/m;' \
    > /etc/nginx/conf.d/rate_limit.conf

# Startup script: substitutes DOMAIN_NAME into config then starts nginx
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

EXPOSE 80 443
ENTRYPOINT ["/docker-entrypoint.sh"]
