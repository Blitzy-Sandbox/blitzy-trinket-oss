FROM node:18-slim
# SECURITY: pygame manager base image audited per AAP §0.5.2 Strategy F / R6 - node:18-slim Debian-slim variant verified against Trivy CRITICAL/HIGH OS-layer CVEs

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm install --production

# Copy application code
COPY manager.js ./
COPY config/ ./config/

# Create generated files directory
RUN mkdir -p /tmp/pygame-generated

# Environment
ENV NODE_ENV=production
ENV NODE_CONFIG_DIR=/app/config

# Expose port
EXPOSE 8100

CMD ["node", "manager.js"]
