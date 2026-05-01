# Trinket

An open source, browser-based coding environment designed for education.

Trinket lets students and educators write and run code directly in the browser, supporting multiple programming languages including Python, HTML, Java, R, and more.

## Features

- **Browser-based code editor** - Write and run code without installing anything
- **Multiple language support** - Python, HTML/CSS/JS, Java, R, GlowScript, and more
- **Embeddable trinkets** - Embed interactive code examples in any webpage
- **Course creation** - Build interactive coding courses and tutorials
- **Code sharing** - Share and remix code with others

## Prerequisites

- Docker and Docker Compose
- Node.js 20 LTS (for local development without Docker)
- MongoDB 5.0+
- Redis (optional - falls back to in-memory)

## Quick Start (Docker)

1. Clone the repository:
   ```bash
   git clone https://github.com/trinketapp/trinket-oss.git
   cd trinket-oss
   ```

2. Copy the example config and add your settings:
   ```bash
   cp config/local.example.yaml config/local.yaml
   ```

3. Start the services:
   ```bash
   docker compose up
   ```

4. Visit http://localhost:3000 in your browser.

## Configuration

Configuration is managed through YAML files in the `config/` directory:

- `default.yaml` - Base configuration (committed to repo)
- `local.yaml` - Local overrides and secrets (not committed)
- `production.yaml` - Production overrides (not committed)

Copy `config/local.example.yaml` to `config/local.yaml` and fill in the required values.

### Required Configuration

| Setting | Description |
|---------|-------------|
| `app.plugins.session.cookieOptions.password` | Session cookie secret (min 32 chars) |
| `app.mail.secret` | JWT email token secret (min 32 chars; boot guard enforces) |

### Optional Integrations

| Setting | Description |
|---------|-------------|
| `app.mail.*` | SMTP settings for email (password reset, notifications) |
| `aws.*` | S3 storage for user-uploaded assets |
| `app.auth.google.*` | Google OAuth login |
| `app.recaptcha.*` | reCAPTCHA spam protection |

See [GETTING_STARTED.md](GETTING_STARTED.md) for detailed setup of optional features.

## Development

### Running without Docker

1. Install dependencies:
   ```bash
   npm install
   ```

2. Start MongoDB locally (Redis is optional)

3. Run the application:
   ```bash
   node app.js
   ```

### Running Tests

```bash
npm test
```

## Architecture

- **Backend**: Node.js 20 LTS with Hapi framework
- **Database**: MongoDB with Mongoose ODM
- **Cache/Sessions**: Redis (optional)
- **Frontend**: AngularJS 1.x
- **Code Execution**: Skulpt (Python in browser), server-side containers for other languages

## Security

Trinket maintains a defense-in-depth security posture across the application stack. The full policy, threat model, supported versions, and disclosure process are documented in [SECURITY.md](SECURITY.md).

### Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.** Follow the private disclosure process described in [SECURITY.md](SECURITY.md). For self-hosted deployments, operators may substitute their own maintainer-controlled contact channel.

### Security Controls

Out of the box, Trinket implements the following controls:

- **Authentication & sessions**: Session-based authentication with sliding 24-hour TTL, sealed iron-encrypted session cookies, and bcrypt password hashing
- **HTTP security headers**: `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`, and `X-Frame-Options: deny` on sensitive paths (including `/admin/*`)
- **CSRF protection**: Synchronizer-token CSRF protection on highest-risk mutating endpoints (`/api/exports`, password/email change, `/api/admin/*`) via [`@hapi/crumb`](https://hapi.dev/module/crumb/), plus `SameSite=Lax` session cookies as a baseline mitigation on remaining endpoints
- **Input validation**: Joi schemas on all routes; Mongoose schema typing on all queries; Nunjucks auto-escape on all server-rendered templates
- **Cryptography**: SHA-256 for invitation tokens, bcrypt for passwords, JWT (HS256) for email verification tokens with boot-time secret entropy validation
- **Container hardening for untrusted code execution**: Server-side shell containers ship with hardening enabled by default (operators may opt out per [serverside/README.md](serverside/README.md)):
  - **Text shells** (`python3-shell`, `java-shell`, `r-shell`): full hardening — `mem_limit`, `mem_reservation`, `cpus`, `cpu_shares`, `pids_limit`, `read_only` rootfs, `tmpfs` for `/tmp`, `no-new-privileges`, and `cap_drop: [ALL]`
  - **Pygame worker** (`pygame-worker`): differential hardening — `mem_limit`, `mem_reservation`, `cpus`, `cpu_shares`, `pids_limit`, `no-new-privileges`, and `cap_drop: [ALL]`; `read_only` and `tmpfs` are intentionally omitted because Xvfb, TightVNC, Supervisor, and noVNC websockify each write to multiple paths that conflict with a strict read-only root
- **Network isolation**: nginx gateway with `server_tokens off`, separate Docker networks for the main application zone and the adversarial code execution zone

### Security Updates

Security-relevant changes are recorded in [CHANGELOG.md](CHANGELOG.md). When upgrading from an earlier release, please review the changelog for any deployment-side adjustments that may be required (for example, ensuring `app.mail.secret` is at least 32 characters before boot).

## Contributing

Contributions are welcome! Please read our [Contributing Guidelines](CONTRIBUTING.md) before submitting a pull request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is released under CC0 1.0 Universal (Public Domain Dedication). See the [LICENSE](LICENSE) file for details.

## History

Trinket was originally created by Elliott Hauser and Brian Marks to make coding education accessible to everyone. It is now open source and maintained by the community.
