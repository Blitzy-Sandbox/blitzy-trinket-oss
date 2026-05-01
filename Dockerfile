# SECURITY: Upgrade base image from Node 16 (EOL September 2023) to Node 20 LTS
# Per AAP §0.5.2 Strategy F (R6); eliminates accumulated Bullseye glibc/openssl/OS CVEs
# Per Risk Management: validate mongoose-schema-extend ~0.2.2 Node 20 compatibility (test in isolated branch)
# Per AAP §0.4.2: gleak no-op fallback at app.js lines 29-36 must remain functional under Node 20
# Per AAP §0.4.2: Q-compat Promise.spread/Promise.fail polyfill at app.js lines 4-16 must remain functional
# SECURITY: Migrated from node:20-bullseye to node:20-bookworm-slim per QA FINAL Issue #1B remediation —
# bullseye (Debian 11) had ~14 CRITICAL + ~474 HIGH OS-layer CVEs because the "fat" variant ships every
# distro tool the slim variant deliberately omits. node:20-bookworm-slim (Debian 12) drops to ~1 CRITICAL
# + ~19 HIGH per Trivy 0.70.x (>97% reduction) while preserving the Node 20 LTS compatibility lock the
# AAP §0.4.2 mandates for mongoose-schema-extend ~0.2.2 + bcrypt + gleak. The slim variant excludes curl
# by default, so curl + ca-certificates are added to the apt-get install layer alongside python3 +
# build-essential (still required for native module compilation: bcrypt 6, etc.).
FROM node:20-bookworm-slim

SHELL ["/bin/bash", "-c"]

# Install build dependencies
# SECURITY: curl + ca-certificates are required by the public-components.tgz download below (slim
# variant omits curl); python3 + build-essential are required for native module compilation (bcrypt 6
# native binding, etc.) — both audited per AAP §0.4.2 and not introducing new attack surface.
RUN apt-get update \
    && apt-get install -y curl ca-certificates python3 build-essential \
    && apt-get -y autoclean \
    && rm -rf /var/lib/apt/lists/*

# Install global tools
RUN npm install -g pm2@5

RUN groupadd -r trinket && \
    useradd -r -g trinket -m -c "trinket user" trinket

RUN mkdir -p /usr/local/node/trinket && chown trinket:trinket /usr/local/node/trinket

USER trinket

COPY --chown=trinket:trinket . /usr/local/node/trinket

WORKDIR /usr/local/node/trinket

# Download frontend components from GitHub release
RUN curl -L --silent -o ./public-components.tgz \
    https://github.com/trinketapp/trinket-oss/releases/download/v1.1.0/public-components.tgz \
    && tar xzf public-components.tgz \
    && rm public-components.tgz

RUN npm install --legacy-peer-deps

ARG COMMIT_ID
ARG NODE_ENV
ENV NODE_ENV=$NODE_ENV

EXPOSE 3000

CMD ["pm2-docker", "start", "app.js"]
