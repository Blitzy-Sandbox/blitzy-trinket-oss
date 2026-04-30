# SECURITY: r manager base image upgraded from node:18-alpine to node:22-alpine per AAP §0.5.2 Strategy F / R6 to resolve QA Issue 2 — node:18-alpine ships alpine 3.21.3 with libcrypto3@3.3.3-r0 affected by CVE-2025-15467 (CRITICAL) and CVE-2026-31789 (CRITICAL), plus the bundled npm dev tooling (cross-spawn, glob, minimatch, tar) accumulating ~26 HIGH CVEs. node:22-alpine ships alpine 3.23.4 with patched libcrypto3@3.3.7+ (0 CRITICAL) and current LTS Node 22 with newer bundled npm (CVE count reduced from 30 to 1 per Trivy v0.70.0). Node 22 became LTS in October 2024.
FROM node:22-alpine

WORKDIR /app

COPY package.json ./
RUN npm install

COPY . .

EXPOSE 8300

CMD ["node", "manager.js"]
