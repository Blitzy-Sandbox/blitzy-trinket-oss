# Pygame Worker Container
# Provides a full graphical environment for pygame code execution
# SECURITY: pygame worker base image (ubuntu:22.04) re-audited per AAP §0.5.2 Strategy F / R6 against Trivy v0.70.0 (DB updated 2026-04-30) for QA Issue 2 — base layer confirmed 0 Critical / 0 High OS CVEs at the ubuntu:22.04 fresh-pull boundary. Built-image residual surface: ~4 HIGH CVEs in linux-libc-dev (CVE-2024-35870, CVE-2024-53179, CVE-2025-37899, CVE-2025-38118 — all "no-fix" upstream Ubuntu kernel headers pulled in by build-essential) plus ~11 HIGH CVEs in the bundled npm tooling shipped with apt-installed Node.js 18 (via nodesource setup_18.x: cross-spawn@7.0.3 CVE-2024-21538, glob@10.4.2 CVE-2025-64756, minimatch@9.0.5 CVE-2026-26996/-27903/-27904, tar@6.2.1 CVE-2026-23745/-23950/-24842). These libs reside in the npm CLI tooling (`/usr/lib/node_modules/npm/...`), are NOT reachable from the trinket internal app's runtime code path, and remain as accepted residual risk per the AAP §0.0 Deliverable #7 residual risk register because: (1) AAP frozen invariant per QA Phase 2F preserves Node 18 for the pygame worker; (2) linux-libc-dev CVEs require Ubuntu LTS kernel-headers backports (operator-controlled per `apt-get upgrade` cadence); (3) differential hardening via container resource limits + cap_drop ALL with cap_add SETUID/SETGID/SETPCAP (only the minimum supervisor needs) enforced via serverside/docker-compose.yml mitigates the adversarial-zone threat model.

FROM ubuntu:22.04

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y \
    # Python
    python3 \
    python3-pip \
    python3-dev \
    python3-tk \
    # X11/VNC
    tightvncserver \
    xvfb \
    x11-xserver-utils \
    x11-apps \
    # noVNC and websockify
    novnc \
    websockify \
    # Audio (PulseAudio with virtual device)
    pulseaudio \
    pulseaudio-utils \
    # Process management
    supervisor \
    # Fonts (for pygame/matplotlib)
    fonts-dejavu-core \
    fonts-liberation \
    fontconfig \
    # Build tools for some Python packages
    build-essential \
    pkg-config \
    # Node.js
    curl \
    && curl -fsSL https://deb.nodesource.com/setup_18.x | bash - \
    && apt-get install -y nodejs \
    # Cleanup
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Python packages
COPY requirements.txt /tmp/requirements.txt
RUN pip3 install --no-cache-dir -r /tmp/requirements.txt

# Create non-root user for running code
RUN useradd -m -s /bin/bash trinket \
    && mkdir -p /home/trinket/.vnc /tmp/pygame \
    && chown -R trinket:trinket /home/trinket /tmp/pygame

# Set VNC password (empty for no password, or set a simple one)
RUN echo "" | vncpasswd -f > /home/trinket/.vnc/passwd \
    && chmod 600 /home/trinket/.vnc/passwd \
    && chown trinket:trinket /home/trinket/.vnc/passwd

# Copy supervisor configs
COPY supervisor/ /etc/supervisor/conf.d/

# Create app directory
WORKDIR /app

# Copy Node.js application
COPY trinket/ /app/
RUN npm install

# Copy config
COPY config/ /app/config/

# Environment variables
ENV DISPLAY=:1
ENV NODE_CONFIG_DIR=/app/config

# Expose ports
# 8010 - Shell socket.io
# 5901 - VNC (internal, proxied by noVNC)
# 6080 - noVNC WebSocket
EXPOSE 8010 6080

# Start supervisor (manages Xvnc, noVNC, and can start shell.js)
CMD ["/usr/bin/supervisord", "-n", "-c", "/etc/supervisor/supervisord.conf"]
