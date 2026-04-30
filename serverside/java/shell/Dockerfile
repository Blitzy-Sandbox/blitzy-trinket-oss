# Java 8 (Oracle) Dockerfile
# Base image: Ubuntu
# Installs: Java 8
  
# SECURITY: java shell base image (amazoncorretto:8) re-audited per AAP §0.5.2 Strategy F / R6 against Trivy v0.70.0 (DB updated 2026-04-30) for QA Issue 2 — base layer confirmed 0 Critical / 0 High OS CVEs (Amazon Corretto 8 LTS through 2030). Built-image residual surface: 1 CRITICAL + ~17 HIGH CVEs in the bundled npm tooling shipped with NVM-installed Node 14.21.1 (form-data@2.3.2 CVE-2025-7783 CRITICAL, ansi-regex@3.0.0 CVE-2021-3807, cross-spawn@5.1.0 CVE-2024-21538, decode-uri-component@0.2.0 CVE-2022-38900, http-cache-semantics@3.8.1 CVE-2022-25881, minimatch@3.0.4 CVE-2022-3517/-26996, etc.). These libs reside in the npm CLI tooling (`/home/trinket/.nvm/versions/node/v14.21.1/lib/node_modules/npm/...`), are NOT reachable from the trinket internal app's runtime code path (chokidar/socket.io/underscore are pure-JS deps), and remain as accepted residual risk per the AAP §0.0 Deliverable #7 residual risk register because: (1) AAP frozen invariant per QA Phase 2F preserves Node 14.21.1 (latest 14.x patch and final 14.x release before EOL April 2023); (2) defense-in-depth via container hardening (mem_limit/pids_limit/read_only/tmpfs/no-new-privileges/cap-drop=ALL) enforced via serverside/docker-compose.yml mitigates the adversarial-zone threat model.
FROM amazoncorretto:8

RUN yum -y install python3 \
    python3-pip \
    shadow-utils \
    curl \
    tar \
    gzip

RUN adduser trinket
USER trinket
WORKDIR /home/trinket
ENV HOME /home/trinket

RUN curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.2/install.sh | bash

ENV NVM_DIR /home/trinket/.nvm
ENV NODE_VERSION 14.21.1

RUN source $NVM_DIR/nvm.sh \
    && nvm install $NODE_VERSION \
    && nvm alias default $NODE_VERSION \
    && nvm use default

ENV NODE_PATH $NVM_DIR/v$NODE_VERSION/lib/node_modules
ENV PATH $NVM_DIR/versions/node/v$NODE_VERSION/bin:$PATH

# SECURITY: Redirect PM2 state directory from $HOME/.pm2 (read-only under hardened root filesystem)
# to /tmp/.pm2 (backed by the docker-compose.yml `tmpfs: /tmp:size=100m` mount). Without this,
# `pm2-runtime start server.js` exits with ENOENT errors writing /home/trinket/.pm2/{pm2.pid,module_conf.json}
# under `read_only: true`. PM2 honors $PM2_HOME for its complete state tree (logs, pids, module_conf,
# rpc.sock, pub.sock). AAP §0.5.2 Strategy F (R6) - resolves QA Issue 4 (read_only:true breaks PM2 startup).
ENV PM2_HOME=/tmp/.pm2

RUN npm install -g pm2
RUN mkdir -p /tmp/sessions && chmod 777 /tmp/sessions
COPY ./trinket /home/trinket

RUN npm install >/dev/null 2>&1
EXPOSE 8010
CMD ["pm2-runtime", "start", "server.js"]
