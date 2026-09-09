FROM nginx:alpine

# Install envsubst (part of gettext) for dynamic config generation
RUN apk add --no-cache gettext

# Copy the template
COPY nginx.conf.template /etc/nginx/templates/nginx.conf.template

# Rate limiting zone defined in http block
RUN echo 'limit_req_zone $binary_remote_addr zone=api:10m rate=30r/m;' \
    > /etc/nginx/conf.d/rate_limit.conf

# Startup script: substitute env vars into nginx config then start nginx
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

EXPOSE 80 443
ENTRYPOINT ["/docker-entrypoint.sh"]
