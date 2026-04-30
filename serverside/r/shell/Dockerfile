# SECURITY: r shell base image audited per AAP §0.5.2 Strategy F / R6 — no Critical/High OS CVEs identified at audit time
FROM r-base:4.4.2

# Install build dependencies including those needed for R graphics packages
RUN apt-get update && apt-get install -y \
    build-essential curl procps apt-utils r-recommended \
    libfontconfig1-dev libfreetype6-dev libcairo2-dev \
    libharfbuzz-dev libfribidi-dev libpng-dev libjpeg-dev

RUN apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

COPY ./install.r /usr/local/bin/
COPY ./packages.txt /tmp/
RUN r /usr/local/bin/install.r $(cat /tmp/packages.txt | xargs)

RUN useradd -m trinket
USER trinket
WORKDIR /home/trinket
ENV HOME /home/trinket

RUN curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash

ENV NVM_DIR /home/trinket/.nvm
ENV NODE_VERSION 18.20.5

SHELL ["/bin/bash", "-c"]

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

ENV R_DEFAULT_DEVICE png
ENV R_LIBS_USER /usr/local/lib/R/site-library

EXPOSE 8010
CMD ["pm2-runtime", "start", "server.js"]
