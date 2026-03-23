# ──────────────────────────────────────
# ISE ACME Certificate Manager — Web UI
# Multi-stage build: no Node.js needed at runtime
# ──────────────────────────────────────

FROM nginx:1.25-alpine

LABEL maintainer="your-email@yourdomain.com"
LABEL description="ISE ACME Certificate Manager — Web Interface"

# Remove default nginx config
RUN rm /etc/nginx/conf.d/default.conf

# Copy nginx configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Copy static web files
COPY src/ /usr/share/nginx/html/

# Create non-root user for nginx
RUN chown -R nginx:nginx /usr/share/nginx/html && \
    chown -R nginx:nginx /var/cache/nginx && \
    chown -R nginx:nginx /var/log/nginx && \
    chown -R nginx:nginx /etc/nginx/conf.d && \
    touch /var/run/nginx.pid && \
    chown -R nginx:nginx /var/run/nginx.pid

# Health check
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD wget -qO- http://localhost:8080/ || exit 1

EXPOSE 8080

USER nginx

CMD ["nginx", "-g", "daemon off;"]
