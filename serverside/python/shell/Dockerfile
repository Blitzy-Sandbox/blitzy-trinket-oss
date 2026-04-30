# FROM phusion/passenger-nodejs:2.0.1
# SECURITY: python shell base image upgraded from python:3.10-bullseye to python:3.10-slim-bookworm per AAP §0.5.2 Strategy F / R6 (and per QA Issue 2 suggested fix: "use the `slim` variant of `python:3.x-bookworm-slim`") — bullseye-based Debian 11 has reached EOL state and accumulated ~1313 OS-layer Critical/High CVEs (per Trivy v0.70.0, DB updated 2026-04-30). The slim-bookworm variant ships with the minimum set of OS packages and at the time of build has only ~2 unfixable Debian CRITICAL + ~9 unfixable Debian HIGH (vs. 20+343 in the full bookworm variant due to bookworm shipping with imagemagick/libaom3/libmagickcore/etc. that are not required for Python execution). Python 3.10.x is preserved (3.10.x patch level) so all pinned scientific packages (numpy 1.23.2, scipy 1.9.0, matplotlib 3.5.3, pandas 1.4.3, basemap 1.3.6, etc.) continue to install with their existing pre-built wheels. Internal Node 14.21.1 (installed via NVM, AAP frozen invariant per QA Phase 2F) is preserved. Container hardening (mem_limit/pids_limit/read_only/tmpfs/no-new-privileges/cap-drop=ALL) remains enforced via serverside/docker-compose.yml. Slim variant requires us to explicitly install curl, ca-certificates, and procps for NVM and runtime tooling (handled below in the apt install).
FROM python:3.10-slim-bookworm

# ARG DEBIAN_FRONTEND=noninteractive

RUN apt clean && apt-get update -y
# SECURITY: slim-bookworm omits curl/ca-certificates/procps that the full image ships with by default;
# add them explicitly. NVM install (further down) requires curl + ca-certificates; PM2 runtime requires
# procps for `ps` introspection. apt-utils silences debconf warnings during package install.
RUN apt install -y software-properties-common fontconfig locales-all build-essential \
    curl ca-certificates procps apt-utils

ENV LANG en_US.UTF-8
ENV LANGUAGE en_US:en
ENV LC_ALL en_US.UTF-8

RUN apt clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
# SECURITY: Upgrade pip, setuptools, and wheel before installing requirements to fix CVE-2024-6345
# and CVE-2025-47273 in setuptools (HIGH; affecting <70.0.0 and <78.1.1 respectively) and
# CVE-2026-24049 in wheel (HIGH; affecting <0.46.2). These packages ship at vulnerable versions
# inside python:3.10-bookworm (setuptools 65.5.1, wheel 0.45.1) and are flagged by Trivy v0.70.0
# regardless of the base image OS layer. Performed prior to `pip3 install -r requirements.txt` so
# the upgraded build tooling is used to install scientific packages. AAP §0.5.2 Strategy A / R1 —
# resolves QA Issue 1 (R1.4 follow-on) for the build-tool transitive surface.
RUN pip3 install --no-cache-dir --upgrade 'pip' 'setuptools>=78.1.1' 'wheel>=0.46.2'
COPY ./requirements.txt /tmp/
RUN pip3 install -r /tmp/requirements.txt --ignore-installed
#COPY ./requirements-deps.txt /tmp/
#RUN pip3 install -r /tmp/requirements-deps.txt --ignore-installed
RUN bokeh sampledata

#RUN adduser trinket
WORKDIR /home/trinket
ENV HOME /home/trinket

RUN curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.2/install.sh | bash

ENV NVM_DIR /home/trinket/.nvm
ENV NODE_VERSION 14.21.1

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

# RUN groupadd -r trinket && useradd -r -g trinket -m -c "trinket user" trinket
# WORKDIR /trinket

RUN npm install >/dev/null 2>&1

# cleanup, try to safeguard against certain exploits
RUN apt --purge -y autoremove build-essential
# SECURITY: Defense-in-depth — chmod 744 (rwxr--r--) on potentially-attacker-useful binaries
# narrows execution to root only when an attacker has read-only file access. The slim-bookworm
# base image does not include `git*` (not in apt install list) and `apt --purge -y autoremove
# build-essential` removes `gcc*`, so those globs may not match — `2>/dev/null || true` makes
# the chmod tolerant of missing files without weakening the lock-down on the binaries that
# DO exist (fallocate, pip*, curl). Hardening intent preserved across the bullseye→slim-bookworm
# base image migration. AAP §0.5.2 Strategy F (R6).
RUN chmod 744 /usr/bin/fallocate /usr/bin/git* /usr/local/bin/pip* /usr/bin/gcc* /usr/bin/curl 2>/dev/null || true

#USER trinket
ENV TERM xterm
ENV PYTHONPATH /home/trinket/python3
ENV MPLBACKEND module://trinket_backend
ENV MPLCONFIGDIR /tmp
RUN python3 /home/trinket/python3/init.py

# empty subprocess module to replace system
# COPY ./subprocess.py /trinket/server/python3/

# run pm2 as root but set uid in shell
RUN adduser trinket

# RUN chmod 700 /trinket
EXPOSE 8010
CMD ["pm2-runtime", "start", "server.js"]
