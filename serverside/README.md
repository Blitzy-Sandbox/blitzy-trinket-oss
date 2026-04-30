# Server-side Trinket Types

This directory contains the backend services for server-side trinket types (Python 3, Java, R, Pygame). These run actual language interpreters in Docker containers, allowing execution of code that can't run in the browser.

## Architecture

```
                                    ┌─────────────────┐
                                    │  python3-shell  │
                                    │   (Container)   │
                                    │  Python Process │
                                    └────────▲────────┘
                                             │ WebSocket
┌─────────┐      ┌─────────┐      ┌──────────┴────────┐
│ Browser │─────►│  nginx  │─────►│  python3-manager  │
│         │ WS   │  :8080  │      │    (Container)    │
└─────────┘      └────┬────┘      └───────────────────┘
                      │
                      │           ┌─────────────────┐
                      │           │    java-shell   │
                      │           │   (Container)   │
                      │           │   Java Process  │
                      │           └────────▲────────┘
                      │                    │ WebSocket
                      │           ┌────────┴──────────┐
                      └──────────►│   java-manager    │
                      │           │    (Container)    │
                      │           └───────────────────┘
                      │
                      │           ┌─────────────────┐
                      │           │     r-shell     │
                      │           │   (Container)   │
                      │           │    R Process    │
                      │           └────────▲────────┘
                      │                    │ WebSocket
                      │           ┌────────┴──────────┐
                      └──────────►│    r-manager      │
                                  │    (Container)    │
                                  └───────────────────┘
```

**Components:**

- **nginx**: Reverse proxy that routes WebSocket connections and serves generated files (images, HTML)
- **Manager**: Node.js process that accepts browser connections and routes to shells
- **Shell**: Docker container running the language interpreter

> **Note:** Pygame uses a different architecture with VNC for graphical output. See the [Pygame](#pygame) section below.

## Quick Start

```bash
cd serverside

# Start Python 3 only
docker compose --profile python3 up --build

# Start Python 3 and Java
docker compose --profile python3 --profile java up --build

# Start all languages
docker compose --profile python3 --profile java --profile r --profile pygame up --build
```

The services will be available at `http://localhost:8080`.

## How It Works

1. Browser loads a trinket embed page (e.g., `/embed/python3/{trinketId}`)
2. The main app injects the WebSocket URL into the page (`http://localhost:8080/python3`)
3. Frontend JavaScript connects via Socket.io through nginx
4. nginx proxies the WebSocket to the appropriate manager
5. Manager connects to an available shell container
6. Shell spawns the language process, executes code, and streams output back
7. If code generates files (e.g., matplotlib images), the shell sends them to the manager
8. Manager writes files to a shared volume, nginx serves them to the browser

## Configuration

### Main App (`config/default.yaml`)

Enable the trinket types you want to support:

```yaml
features:
  trinkets:
    python3: true   # Enable Python 3
    java: false     # Disable Java
    R: false        # Disable R

app:
  serverside:
    python3:
      api:
        default: 'http://localhost:8080/python3'
    java8:
      api:
        default: 'http://localhost:8080/java'
    r3:
      api:
        default: 'http://localhost:8080/r'
```

### Manager Configuration

Each manager reads from `{language}/manager/config/`. The `node-config` library merges files:

- `default.json` - Base configuration (local development)
- `production.json` - Docker/production overrides
- `custom-environment-variables.json` - Environment variable mappings

**Environment Variables:**

| Variable | Description | Example |
|----------|-------------|---------|
| `GENERATED_URL` | Base URL for generated files | `https://code.example.com/python3-generated` |
| `CORS_ORIGINS` | Allowed CORS origins (JSON array) | `["https://example.com"]` |

### Scaling Shells

To handle more concurrent users, run multiple shell containers and list them in the manager's `shells` array:

```json
{
  "shells": [
    "http://python3-shell-1:8010",
    "http://python3-shell-2:8010",
    "http://python3-shell-3:8010"
  ]
}
```

The manager randomly selects a shell for each connection.

## Production Deployment

> **Security Posture (per AAP §0.5.2 Strategy F / R6):** The serverside execution
> platform now ships with **default-on container hardening** for shell containers
> running untrusted learner code. See the [Security Hardening](#security-hardening)
> subsection below for the active defaults, the threat each directive mitigates,
> and granular [Operator Opt-Out](#operator-opt-out) guidance. Operators upgrading
> from a pre-1.1.0 deployment do **not** need to take any action to enable
> hardening — the defaults apply automatically.

### SSL/TLS Setup

For production, you should enable HTTPS. Two options:

#### Option 1: Self-signed certificate (development/testing)

```bash
# Generate self-signed certificate
mkdir -p nginx/ssl
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout nginx/ssl/key.pem \
  -out nginx/ssl/cert.pem \
  -subj "/CN=localhost"
```

#### Option 2: Let's Encrypt (production)

Use certbot or your preferred ACME client to obtain certificates, then mount them:

```bash
# In docker-compose.yml, uncomment:
volumes:
  - /etc/letsencrypt/live/your-domain/fullchain.pem:/etc/nginx/ssl/cert.pem:ro
  - /etc/letsencrypt/live/your-domain/privkey.pem:/etc/nginx/ssl/key.pem:ro
```

Then update nginx to use the SSL config:

```dockerfile
# In nginx/Dockerfile, change:
COPY nginx-ssl.conf /etc/nginx/nginx.conf
```

And in docker-compose.yml:

```yaml
nginx:
  ports:
    - "443:443"
    - "80:80"  # For redirect
```

### Security Hardening

The shell containers run untrusted user code. Per the AAP §6.4.5 zone definitions,
shell containers are classified as the **Code Execution Zone — Adversarial**, and
the educational platform's threat model requires hardening as the **default
posture** (rather than an operator opt-in). As of this release, every shell
hardening directive in `docker-compose.yml` is **enabled by default**; operators
may opt out (see [Operator Opt-Out](#operator-opt-out) below) on a
directive-by-directive basis if their environment requires it.

#### Docker Compose (default-on hardening)

The directives below are **already active** in `docker-compose.yml` for every
shell service (`python3-shell`, `java-shell`, `r-shell`, `pygame-worker`). No
operator action is required to enable them. The table documents what each
directive defends against and what trade-off opting out incurs.

##### Text shells (`python3-shell`, `java-shell`, `r-shell`)

```yaml
# SECURITY: Hardening defaults are now ENABLED for adversarial-zone shell containers
python3-shell:
  mem_limit: 500m              # SECURITY: Hard memory cap (mitigates memory exhaustion / OOM DoS)
  mem_reservation: 375m        # SECURITY: Soft memory limit for scheduling
  cpus: 1.0                    # SECURITY: CPU bound (mitigates CPU exhaustion)
  cpu_shares: 512              # SECURITY: Relative CPU weight (limits scheduling priority)
  pids_limit: 50               # SECURITY: PID limit (mitigates fork bombs)
  read_only: true              # SECURITY: Read-only root filesystem (prevents tamper / persistence)
  tmpfs:
    - /tmp:size=100m           # SECURITY: Writable /tmp with size cap (limits scratch space abuse)
  security_opt:
    - no-new-privileges:true   # SECURITY: Block setuid privilege escalation
  cap_drop:
    - ALL                      # SECURITY: Drop all Linux capabilities (least privilege)
```

| Directive | Threat mitigated | Default | Trade-off when relaxed |
|-----------|-----------------|---------|------------------------|
| `mem_limit` | Memory-exhaustion DoS, OOM kill of the host | `500m` | Larger learner workloads (e.g., NumPy datasets) may OOM-kill at 500 MB; relax to `1g` or higher |
| `mem_reservation` | Scheduling priority for the shell | `375m` | None — informational soft limit |
| `cpus` | CPU-exhaustion DoS | `1.0` | Compute-heavy coursework (e.g., scipy regressions) runs slower; relax to `2.0` |
| `cpu_shares` | Relative scheduling weight | `512` | Lower priority under contention; raise to `1024` for parity with system processes |
| `pids_limit` | Fork bombs, process-exhaustion DoS | `50` | Multiprocessing-heavy code (e.g., Python `multiprocessing.Pool(n)` for n>40) may hit the cap; relax to `100` or `200` |
| `read_only` | Persistence of malicious payloads, runtime tampering of installed packages | `true` | Code that writes outside `/tmp` (e.g., R `~/.cache`, Python `~/.matplotlib`) returns `EROFS`; remove this directive **or** add an additional `tmpfs:` mount for the affected path |
| `tmpfs /tmp:size=100m` | Scratch-space exhaustion | `100m` | Code generating large temp files (>100 MB matplotlib plots, large CSV scratch) hits `ENOSPC`; raise the size or remove and rely on the named-volume mount at `/tmp/sessions` |
| `security_opt: no-new-privileges` | setuid privilege escalation, ptrace exploits | enabled | None known for trinket workloads — opting out is **strongly discouraged** |
| `cap_drop: ALL` | Linux capability abuse (e.g., `CAP_NET_RAW` raw sockets, `CAP_SYS_ADMIN` mount/unshare) | enabled | Code requiring network capabilities (e.g., raw ICMP) fails; add specific capabilities back via `cap_add: [NET_RAW]` rather than removing the drop |

##### Pygame worker (`pygame-worker`) — differential hardening

The pygame worker runs Xvfb + TightVNC + noVNC + websockify + Supervisor as a
graphical execution environment. Two hardening directives are **intentionally
omitted** for this service because they conflict with the graphical stack's
runtime write requirements:

```yaml
# SECURITY: Differential hardening — read_only/tmpfs OMITTED (graphical stack writes)
pygame-worker:
  mem_limit: 1g                # SECURITY: Hard memory cap for graphical environment
  mem_reservation: 750m        # SECURITY: Soft memory limit for scheduling
  cpus: 2.0                    # SECURITY: Higher CPU bound for Xvfb + Pygame rendering
  cpu_shares: 512              # SECURITY: Relative CPU weight (limits scheduling priority)
  pids_limit: 100              # SECURITY: Higher PID cap for Supervisor + child processes
  security_opt:
    - no-new-privileges:true   # SECURITY: Block setuid privilege escalation (no graphical conflict)
  cap_drop:
    - ALL                      # SECURITY: Drop all Linux capabilities (no graphical conflict)
  # NOTE: read_only and tmpfs are intentionally OMITTED for the pygame-worker
  #       because the graphical stack (Xvfb, TightVNC, Supervisor, noVNC) writes
  #       to multiple paths (/tmp/.X11-unix, ~/.vnc, /var/run/supervisor, etc.)
```

`read_only: true` and `tmpfs: /tmp:size=100m` are omitted because:

- **Xvfb** writes to `/tmp/.X11-unix/` (X11 socket directory)
- **TightVNC** writes to `~/.vnc/` (VNC password and PID files)
- **Supervisor** writes to `/var/run/supervisor/` and `/var/log/supervisor/` (state and logs)
- **noVNC websockify** writes log files

These multi-path writes conflict with strict read-only root + a single small
`/tmp` tmpfs. Capability drop and resource limits remain to provide layered
defense per AAP §0.8.3 — the pygame worker still cannot escalate privileges,
fork-bomb the host, or exhaust memory. Future hardening of the pygame worker
will require either narrower writable mounts for each subsystem path **or** a
larger tmpfs that covers all four subsystems' write requirements.

#### Operator Opt-Out

To relax a single directive (for example, to allow more memory for compute-heavy
coursework), edit `docker-compose.yml` and **remove or comment** the directive
on the affected service. The remaining directives stay in effect:

```yaml
# Example: remove the 500 MB cap on python3-shell while keeping all other defenses.
python3-shell:
  build: ./python/shell
  profiles: ["python3"]
  expose:
    - "8010"
  volumes:
    - python-sessions:/tmp/sessions
  # mem_limit: 500m              # ← OPT-OUT: removed to allow unbounded memory
  mem_reservation: 375m
  cpus: 1.0
  cpu_shares: 512
  pids_limit: 50
  read_only: true
  tmpfs:
    - /tmp:size=100m
  security_opt:
    - no-new-privileges:true
  cap_drop:
    - ALL
```

To relax `read_only: true` (for example, if R packages need `~/.cache` writes
at runtime and you do not want to add a granular tmpfs mount):

```yaml
r-shell:
  # ... other directives ...
  # read_only: true              # ← OPT-OUT: removed to allow root-fs writes
  tmpfs:
    - /tmp:size=100m
  # ... remaining hardening intact ...
```

Per AAP §0.5.2 Strategy F (R6) and the user directive *"operators can opt out
but hardening must be the default posture for an educational platform executing
untrusted learner code"*, the opt-out is granular and preserved — operators are
not forced into an all-or-nothing choice.

#### Production Docker Run (non-Compose deployments)

> **Note:** This section applies only to operators **NOT** using Docker Compose.
> If you use `docker-compose.yml`, the defaults documented above already include
> these flags by default — see [Docker Compose (default-on hardening)](#docker-compose-default-on-hardening)
> above. The flags below are the equivalent `docker run` invocations for
> non-Compose deployments and are included for parity.

For production deployments outside compose, apply the equivalent flags directly
to `docker run`:

```bash
# SECURITY: docker run flags equivalent to the docker-compose.yml default-on
# hardening (mem_limit, mem_reservation, cpus, cpu_shares, pids_limit,
# read_only, tmpfs, no-new-privileges, cap_drop ALL). Each flag below mitigates
# the same threat its docker-compose.yml counterpart does — see the directive
# table above for the per-flag threat model and opt-out trade-offs.
docker run -d \
  -p 8010:8010 \
  --restart unless-stopped \
  --memory="500m" \
  --memory-reservation="375m" \
  --cpus="1.0" \
  --cpu-shares="512" \
  --pids-limit=50 \
  --read-only \
  --tmpfs /tmp:size=100m \
  --security-opt=no-new-privileges \
  --cap-drop=ALL \
  trinket/python3-shell:latest
```

For the `pygame-worker` image, omit `--read-only` and `--tmpfs /tmp:size=100m`
to match the differential hardening profile, and raise `--memory`, `--cpus`,
and `--pids-limit` per the table above.

#### Network Isolation

Consider running shells in an isolated network with no external access:

```yaml
networks:
  shell-internal:
    internal: true  # No external connectivity

services:
  python3-shell:
    networks:
      - shell-internal
```

#### Historical: pre-1.1.0 opt-IN model

Prior to release 1.1.0, the directives above shipped as commented-out examples
in `docker-compose.yml` and operators were instructed to "uncomment the security
options" to enable hardening. That opt-IN model was superseded by the default-on
posture documented in this section. Operators upgrading from a pre-1.1.0
deployment do **not** need to take any action to gain hardening — the new
defaults apply automatically. Operators who previously left the directives
commented and intentionally relied on un-hardened shell containers should
review the [Operator Opt-Out](#operator-opt-out) section to selectively relax
limits where needed.

### Environment-specific Configuration

For production, override the generated URL to match your domain:

```yaml
# docker-compose.override.yml
services:
  python3-manager:
    environment:
      - GENERATED_URL=https://code.example.com/python3-generated
      - CORS_ORIGINS=["https://example.com","https://www.example.com"]
```

## Directory Structure

```
serverside/
├── docker-compose.yml       # Main compose file
├── nginx/
│   ├── Dockerfile
│   ├── nginx.conf           # HTTP config
│   └── nginx-ssl.conf       # HTTPS config
├── python/
│   ├── manager/
│   │   ├── Dockerfile
│   │   ├── manager.js
│   │   ├── package.json
│   │   └── config/
│   │       ├── default.json
│   │       ├── production.json
│   │       └── custom-environment-variables.json
│   └── shell/
│       ├── Dockerfile
│       ├── requirements.txt
│       └── trinket/
│           ├── server.js
│           └── package.json
├── java/
│   ├── manager/
│   └── shell/
├── r/
│   ├── manager/
│   └── shell/
└── pygame/
    ├── manager/
    └── worker/          # Uses 'worker' (not 'shell') due to VNC components
```

## Ports (Internal)

These ports are internal to the Docker network. Only nginx port 8080 is exposed externally.

| Service | Internal Port | Purpose |
|---------|--------------|---------|
| nginx | 80 (external: 8080) | Reverse proxy |
| python3-manager | 8100 | WebSocket routing |
| python3-shell | 8010 | Code execution |
| java-manager | 8200 | WebSocket routing |
| java-shell | 8010 | Code execution |
| r-manager | 8300 | WebSocket routing |
| r-shell | 8010 | Code execution |
| pygame-manager | 8400 | WebSocket routing |
| pygame-worker | 8010, 6080 | Code execution + VNC |

## Troubleshooting

### Check service status

```bash
docker compose --profile python3 ps
docker compose --profile python3 logs -f
```

### Test nginx routing

```bash
# Health check
curl http://localhost:8080/health

# Check WebSocket upgrade headers
curl -v -H "Upgrade: websocket" -H "Connection: upgrade" \
  http://localhost:8080/python3/socket.io/
```

### Debug manager connections

```bash
# View manager logs
docker compose --profile python3 logs -f python3-manager

# Check shell connectivity
docker compose --profile python3 exec python3-manager \
  wget -qO- http://python3-shell:8010 || echo "Shell not responding"
```

### Generated files not loading

1. Check the volume is mounted correctly:
   ```bash
   docker compose exec nginx ls -la /var/www/generated/python/
   ```

2. Verify the manager's `generatedUrl` config matches nginx routing

3. Check browser console for CORS errors

## Generated File Cleanup

When users run code that produces files (matplotlib plots, R graphics, etc.), these files are stored in Docker volumes and served via nginx. To prevent disk space exhaustion, each manager automatically cleans up old generated files.

### How It Works

- Cleanup runs on manager startup and then periodically (default: every 60 minutes)
- Files older than `maxAgeHours` (default: 24 hours) are deleted
- Cleanup is based on directory modification time (each generated file gets its own subdirectory)

### Configuration

Each manager's cleanup is configured in its `config/default.json`:

```json
{
  "manager": {
    "cleanup": {
      "enabled": true,
      "maxAgeHours": 24,
      "intervalMinutes": 60
    }
  }
}
```

| Option | Default | Description |
|--------|---------|-------------|
| `enabled` | `true` | Enable/disable automatic cleanup |
| `maxAgeHours` | `24` | Delete files older than this many hours |
| `intervalMinutes` | `60` | How often to run cleanup (in minutes) |

### Monitoring

Cleanup progress is logged to the manager's stdout:

```
[Cleanup] Starting cleanup of files older than 24 hours in /tmp/python-generated
[Cleanup] Complete. Deleted 15 directories, 0 errors.
```

### Manual Cleanup

To manually clear all generated files:

```bash
# Clear all Python generated files
docker compose exec python3-manager rm -rf /tmp/python-generated/*

# Or from the host (if volumes are named)
docker volume rm serverside_python-generated
docker volume rm serverside_java-generated
docker volume rm serverside_r-generated
```

Note: Removing volumes requires restarting the containers.

### Shell timeouts

Python shells have a 60-second timeout. For long-running computations:

1. Increase timeout in `shell/trinket/server.js`
2. Consider breaking code into smaller chunks
3. Use async patterns where possible

## Development (without Docker)

For local development, you can run services directly:

**Shell** (requires language runtime):
```bash
cd python/shell/trinket
npm install
node server.js  # Listens on port 8010
```

**Manager**:
```bash
cd python/manager
npm install
node manager.js  # Listens on port 8100, connects to shell
```

Update `config/default.json` shell URLs to match your local setup.

## Pygame

Pygame has a different architecture than other languages because it needs a graphical display for game windows.

### How It Works

```
┌─────────┐      ┌─────────┐      ┌─────────────────┐      ┌─────────────────────┐
│ Browser │─────►│  nginx  │─────►│  pygame-manager │─────►│    pygame-worker    │
│         │      │         │      │                 │      │  ┌───────────────┐  │
│ noVNC   │◄─────│         │◄─────│                 │◄─────│  │    Xvfb       │  │
│ Client  │ WS   │         │ WS   │                 │      │  │  (Virtual X)  │  │
└─────────┘      └─────────┘      └─────────────────┘      │  └───────┬───────┘  │
                                                           │          │          │
                                                           │  ┌───────▼───────┐  │
                                                           │  │    pygame     │  │
                                                           │  │    process    │  │
                                                           │  └───────────────┘  │
                                                           │          │          │
                                                           │  ┌───────▼───────┐  │
                                                           │  │ TightVNC +    │  │
                                                           │  │ noVNC server  │──┼──► VNC stream
                                                           │  └───────────────┘  │
                                                           └─────────────────────┘
```

The worker container runs:
- **Xvfb**: Virtual X11 framebuffer (headless display)
- **TightVNC**: VNC server capturing the display
- **noVNC + websockify**: WebSocket-to-VNC proxy for browser access
- **Supervisor**: Process manager coordinating all services

### Quick Start

```bash
docker compose --profile pygame up --build
```

### Configuration

Enable pygame in the main app:

```yaml
features:
  trinkets:
    pygame: true

app:
  serverside:
    pygame:
      api:
        default: 'http://localhost:8080/pygame'
```

### Resource Requirements

Pygame workers need more resources than text-based languages due to the graphical environment:

```yaml
pygame-worker:
  mem_limit: 1g
  cpus: 2.0
```

### Production Scaling (Not Yet Included)

The current pygame setup runs a single worker container, suitable for development and small deployments.

For production with many concurrent users, Trinket used a dynamic scaling system that:
- Spins up cloud VM instances (AWS EC2 or GCP) on demand
- Uses Redis to coordinate instance state across the scaler and workers
- Workers "phone home" on startup to register with the scaler
- Automatically scales down idle instances to reduce costs

This infrastructure (scaler, stats server, worker images, phone-home scripts) is not yet included in the OSS release. Contributions welcome.
