# Use Node 20 LTS (Active LTS, OpenSSL 3.x)
# SECURITY: upgraded from node:16-bullseye to address Node 16 EOL exposure (CWE-1104)
FROM node:20-bookworm-slim

SHELL ["/bin/bash", "-c"]

# Install build dependencies
# SECURITY: curl is required by the `RUN curl -L ... public-components.tgz`
# step below; it is provided by the legacy `node:16-bullseye` image but is
# absent from the `node:20-bookworm-slim` image we adopted to remediate the
# Node 16 EOL exposure (CWE-1104). Adding curl to the apt-get install list
# closes the resulting build regression. QA finding #2.
RUN apt-get update \
    && apt-get install -y python3 build-essential curl \
    && apt-get -y autoclean

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
