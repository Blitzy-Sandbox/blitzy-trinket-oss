# SECURITY: pygame manager base image upgraded from node:18-slim to node:22-alpine per AAP §0.5.2 Strategy F / R6 to resolve QA Issue 2 — node:18-slim shipped Debian 12 with 1 CRITICAL (zlib1g CVE-2023-45853 unfixable) and 8 HIGH unfixable, plus bundled npm tooling accumulating ~29 HIGH CVEs. node:22-alpine ships alpine 3.23.4 (0 CRITICAL/0 HIGH at OS layer) and current LTS Node 22 with newer bundled npm (CVE count reduced from 30 to 1 per Trivy v0.70.0). The pygame manager is a pure-JS Node.js Socket.IO service whose dependencies (config, file-type, is-svg, socket.io, socket.io-client) are all musl-libc-compatible — no native modules require glibc.
FROM node:22-alpine

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
