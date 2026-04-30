# SECURITY: nginx base image audited per AAP §0.5.2 Strategy F / R6
# Trivy scan against `nginx:alpine` reported zero Critical/High OS-layer CVEs.
# Per AAP §0.1.2 Minimal Change Clause: base image not upgraded; audit-only.
FROM nginx:alpine

# Remove default config
RUN rm /etc/nginx/conf.d/default.conf

# Copy our config
COPY nginx.conf /etc/nginx/nginx.conf

# Create directories for generated files
RUN mkdir -p /var/www/generated/python \
             /var/www/generated/java \
             /var/www/generated/r

EXPOSE 80 443
