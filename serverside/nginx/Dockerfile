# SECURITY: pinned base image to remove implicit latest drift
FROM nginx:1.27-alpine

# Remove default config
RUN rm /etc/nginx/conf.d/default.conf

# Copy our config
COPY nginx.conf /etc/nginx/nginx.conf

# Create directories for generated files
RUN mkdir -p /var/www/generated/python \
             /var/www/generated/java \
             /var/www/generated/r

EXPOSE 80 443
