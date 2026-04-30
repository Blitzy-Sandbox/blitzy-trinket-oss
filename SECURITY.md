# Security Policy

The Trinket team takes security seriously. This document describes how to report security vulnerabilities, our supported versions, the disclosure process we follow, and the security controls already in place.

Trinket OSS is an educational platform that executes untrusted learner code on behalf of authenticated users (often minors) while hosting educator-authored courseware. Our threat model treats the shell execution tier as **adversarial** and the main application zone as **defended-in-depth**. Security findings that bear on either zone are taken seriously and triaged accordingly.

If you are a researcher reporting a vulnerability, thank you — coordinated disclosure helps everyone.

## Reporting Security Vulnerabilities

**Please do NOT report security vulnerabilities through public GitHub issues, pull requests, or discussion threads.**

Instead, please report them privately by emailing:

> **security@trinket.io**

Operators who self-host Trinket OSS may substitute their own maintainer-controlled contact channel; in that case, the contact address documented in their deployment supersedes the address above.

If email is not an option, you may also open a [GitHub Security Advisory](https://github.com/trinketapp/trinket-oss/security/advisories/new) on this repository, which keeps the discussion private until coordinated disclosure.

### What to Include in Your Report

To help us triage and resolve the issue quickly, please include as much of the following as you can:

- **Type of vulnerability** — for example, XSS, NoSQL operator injection, IDOR, CSRF, RCE, authentication bypass, privilege escalation, broken access control, cryptographic weakness, container escape, prototype pollution, SSRF, or session fixation
- **Affected component(s)** — full path(s) of the source file(s) where the vulnerability manifests (for example, `lib/controllers/users.js`, `app.js`, `serverside/python/manager/manager.js`)
- **Affected version** — tag, branch, or commit hash (or a direct URL into the repository)
- **Reproduction steps** — step-by-step instructions, including any special configuration required (for example, reCAPTCHA absent, S3 absent, Redis absent, custom `local.yaml` overrides)
- **Proof-of-concept** — a minimal exploit, payload, or script demonstrating the issue, where it is safe and feasible to provide one
- **Impact** — what an attacker can achieve (read another user's data, modify resources, escalate to admin, escape the shell sandbox, deny service, leak credentials, etc.)
- **Suggested mitigation** — optional, but appreciated if you have ideas

This information helps us reproduce the issue, assess severity using CVSS v3.1, and prioritize remediation against our success criteria.

### Response Time Commitments

We aim to:

| Milestone | Target |
| --- | --- |
| Acknowledge receipt of report | Within **3 business days** |
| Initial severity assessment and reproduction | Within **7 business days** |
| Fix or mitigation released for Critical / High severity findings | Within **30 days** |
| Fix or mitigation released for Medium severity findings | Within **90 days** |
| Coordinated public disclosure | Coordinated with reporter; default 90 days from acknowledgment |

Our remediation prioritization follows these targets:

- **100%** of Critical (CVSS ≥ 9.0) vulnerabilities remediated
- **100%** of High (CVSS 7.0 – 8.9) vulnerabilities remediated
- **≥ 80%** of Medium (CVSS 4.0 – 6.9) vulnerabilities remediated
- Low (CVSS < 4.0) findings are documented in the residual risk register and remediated when they enable a Critical or High finding

If a report's severity warrants emergency action (active exploitation in the wild, trivial unauthenticated RCE, or similar), we will work to release a fix as quickly as possible and notify operators via release channels.

## Supported Versions

Security updates are applied to the latest minor release line of Trinket OSS. Older release lines are not maintained.

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |
| < 1.0   | :x:                |

When a security release is published, the version is documented in [CHANGELOG.md](CHANGELOG.md) with cross-references to advisories or CVE numbers, and a corresponding [GitHub Security Advisory](https://github.com/trinketapp/trinket-oss/security/advisories) is opened where appropriate.

Operators self-hosting Trinket OSS are strongly encouraged to track the latest tagged release and apply security updates promptly.

## Disclosure Process

We follow a **coordinated disclosure** model:

1. **Receipt** — Reporter submits the vulnerability via the security email channel or a private GitHub Security Advisory. Public issues are not used for security reports.
2. **Acknowledgment** — Maintainer team confirms receipt within 3 business days and assigns an internal tracking identifier.
3. **Triage** — We reproduce the issue, assess severity using CVSS v3.1, identify all affected components and versions, and determine whether the issue is in scope (see [Out of Scope](#out-of-scope) below).
4. **Remediation** — We develop and test a fix in a private branch. All security fixes follow our atomic commit pattern: one CVE or vulnerability class per commit, with the message format `security: [severity] fix [description] in [file]`, and `// SECURITY: [threat addressed]` annotations on every changed line for retroactive audit. A pre-remediation git tag and `package-lock.baseline.json` snapshot are maintained for instant rollback.
5. **Coordinated Release** — We coordinate a release date with the reporter. The patch, advisory, and (where eligible) CVE assignment are released together. Operators receive notice via the [CHANGELOG.md](CHANGELOG.md) entry and the GitHub Security Advisory.
6. **Public Disclosure** — Full technical details, affected versions, mitigation guidance, and credit (where the reporter has consented) are published in [CHANGELOG.md](CHANGELOG.md) and via the GitHub Security Advisory.

We respectfully ask that researchers do not publicly disclose the vulnerability until a fix is released, or until **90 days** have passed since acknowledgment, whichever comes first. If you need to publish on a different timeline (for example, due to a coordinated industry-wide disclosure), please let us know in your initial report so we can plan accordingly.

### Safe Harbor

We will not pursue legal action against, or initiate law-enforcement investigation of, security researchers who:

- Make a good-faith effort to avoid privacy violations, destruction of data, and interruption or degradation of our service
- Do not exploit a discovered vulnerability beyond the minimum necessary to confirm its presence
- Do not access, modify, or exfiltrate data belonging to other users (including learner submissions, educator courseware, or personally identifiable information)
- Report the vulnerability to us privately, through the channels described above, and give us reasonable time to remediate before any public disclosure
- Comply with all applicable laws

If in doubt, ask us before testing.

## Security Controls

Trinket OSS implements **defense-in-depth** across seven concentric layers. Researchers should consider these controls when assessing a finding's exploitability and impact.

### 1. Authentication & Session Management

- Session-based authentication via [`@hapi/yar`](https://hapi.dev/module/yar/) with a sliding 24-hour TTL backed by a custom Catbox engine over MongoDB
- Password hashing with **bcrypt** (cost factor 10)
- Session-fixation defense via `yar.reset()` on successful login (session ID rotated)
- **Two-tier disabled-account enforcement**: Passport `deserializeUser` rejects, and the custom session auth scheme additionally rejects, so a previously authenticated session cannot survive an account being disabled
- Optional Google OAuth via Passport (with CSRF state-parameter validation when enabled)
- Optional reCAPTCHA v2 on signup, password reset, and email verification (fail-open with an explicit operator warning logged at boot when unconfigured, per the operator-driven graceful-degradation model)
- Boot-time entropy guard refuses to start the application when the session cookie password is shorter than 32 characters
- Boot-time entropy guard refuses to start when `app.mail.secret` (used to sign JWT email tokens) is shorter than 32 characters

### 2. Authorization

- `isAdmin(user)` pre-handler enforced on every `/api/admin/*` route
- `canEdit(<resource>, user)` pre-handler enforced on every resource-mutating endpoint
- **Strict ownership comparison** (`===` after explicit `.toString()` coercion) on bulk export downloads to prevent IDOR
- Role-based permission evaluation via the Mongoose `roles` plugin in `lib/models/plugins/roles.js`
- Admin impersonation (`loginAs` / `logoutAs`) is gated by `isAdmin` and the `_realUserId` shadow identity is never serialized to API responses or rendered templates

### 3. Cryptographic Controls

- **SHA-256** for course invitation tokens (replacing the previous MD5 implementation)
- AES role-payload encryption via `lib/util/roles.js` (interface frozen and audited)
- **SHA-1** is used only as a deterministic identifier hash (trinket short codes, file content hashes, export filenames) and is annotated inline as non-confidential per OWASP A02 guidance
- All confidentiality-bearing primitives prefer authenticated, modern algorithms; legacy primitives are explicitly annotated where retained for backward-compatibility of identifier surfaces

### 4. HTTP Security Headers

The main application emits the following headers on every response (with appropriate scoping for embed and sandbox routes that intentionally relax some restrictions):

- `Content-Security-Policy` — restrictive policy on main app pages; embed and sandbox routes use a separate, intentionally permissive policy because the sandbox is the untrusted-code execution surface
- `X-Content-Type-Options: nosniff`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `X-Frame-Options: deny` — applied to authentication, signup, contact, educator, admin, and the home page (any path covered by `app.xframeDeny`)
- `Cache-Control`, `Pragma`, and `Expires` — applied to authenticated and sensitive responses to prevent caching of personalized data

The nginx gateway in `serverside/nginx/nginx.conf` additionally sets `server_tokens off` and `X-Content-Type-Options: nosniff` on generated-asset and WebSocket-proxy responses.

### 5. CSRF Protection

- `SameSite=Lax` on session cookies as the primary mitigation (with `SameSite=None; Secure` post-processing for HTTPS deployments)
- `@hapi/crumb` synchronizer-token CSRF protection on the highest-risk mutating endpoints (`/api/exports`, password and email change in `/api/users`, and `/api/admin/*`)
- API consumers other than the bundled SPA must include the CSRF token cookie/header pair on requests to protected endpoints

### 6. Input Validation and Output Encoding

- Joi schema validation on every Hapi route, with explicit rejection of MongoDB operator-prefixed keys (`$where`, `$regex`, `$gt`, etc.) on mutating routes
- Mongoose schema typing applied uniformly to user-controlled values, providing a strong baseline against NoSQL operator injection
- Nunjucks **auto-escape** is enabled globally for all server-rendered templates; the `| safe` filter is restricted to known-safe contexts and audited inline
- Route-level payload size caps (`payload.maxBytes`) enforced for upload endpoints
- Filename normalization applied in `lib/util/file.js` to defend against path traversal in user-supplied names

### 7. Container Hardening (Adversarial Code Execution Tier)

The shell containers (`python3-shell`, `java-shell`, `r-shell`, `pygame-worker`) execute untrusted learner code. They ship with the following hardening directives **enabled by default** in `serverside/docker-compose.yml`; operators may opt out by removing the relevant directive:

- `mem_limit: 500m` and `mem_reservation: 375m` to bound memory exhaustion
- `cpus: 1.0` and `cpu_shares: 512` to bound CPU consumption
- `pids_limit: 50` to mitigate fork-bomb attacks
- `read_only: true` root filesystem with `tmpfs: /tmp:size=100m` for ephemeral writes
- `security_opt: [no-new-privileges:true]` to block setuid escalation
- `cap_drop: [ALL]` to remove the entire Linux capability surface

The reverse proxy (nginx) further isolates the shell tier from direct internet exposure.

### Automated Security Testing

We run the following automated security scans:

- `npm audit --audit-level=high` against the root `package.json` (Node 16/20 main app dependency tree)
- `npm audit --audit-level=high` against each `serverside/*/manager/package.json` (Node 18 manager dependency tree, scanned independently)
- **Trivy** image scans against the main application and shell container images for OS-layer and language-package CVEs
- **ESLint** with [`eslint-plugin-security`](https://www.npmjs.com/package/eslint-plugin-security) for SAST coverage on `lib/`, `config/`, and `serverside/*/manager/` (vendored frontend assets are intentionally excluded)
- A Mocha-based security regression suite under `test/security/` covering authentication, access control, injection, session, and upload attack scenarios
- Optional weekly OWASP ZAP baseline scan against staging deployments

The CI pipeline configuration is in [`.github/workflows/security-scan.yml`](.github/workflows/security-scan.yml).

## Out of Scope

The following items are **operator-controlled** or **explicitly deferred** and are not in scope for this disclosure policy. Reports falling exclusively into one of these categories will be acknowledged but may be closed without remediation in this repository:

- **Infrastructure TLS termination** — Trinket does not terminate TLS in-process; HTTPS is operator responsibility (typically via a reverse proxy in front of the application)
- **MongoDB at-rest encryption / volume-level encryption** — operator infrastructure responsibility
- **Multi-Factor Authentication (MFA)** — no TOTP, WebAuthn, or SMS second factor is provided; reCAPTCHA v2 remains as the closest in-application approximation, and operators are encouraged to layer MFA at their identity provider (Google OAuth, SSO, etc.)
- **CDN dependency pinning** — runtime references to `cdnjs.cloudflare.com`, `ajax.googleapis.com`, and similar CDNs are not pinned to subresource-integrity hashes in this release; operators wishing for SRI must layer it themselves
- **Operator-deployed compliance regimes** — SOC 2, PCI-DSS, HIPAA, FERPA, COPPA, and GDPR controls (DPAs, parental-consent flows, retention schedules, SIEM forwarding, audit-log retention, breach-notification workflows) are layered by operators in their deployment context; this repository provides the technical baseline but does not commit to a specific regime
- **AngularJS 1.3.20 frontend** — frozen per ADR-5 (no framework migration); CVEs are documented and assessed for exploitability within the iframe `sandbox` attribute configuration; reports of theoretical AngularJS vulnerabilities that are not exploitable in Trinket's sandbox configuration will be documented but not actively remediated in the framework itself
- **CDN-loaded vendored frontend assets** — jQuery 2.2.4, Ace Editor, Foundation 5, jq-console, and similar; these are assessed for sandbox-context exploitability and upgraded only where exploitable
- **The `mongoose-schema-extend` legacy dependency** — flagged as ADR-8 tech debt; documented as residual risk; will be revisited if a Critical/High CVE forces resolution
- **Findings below Medium severity** — documented in the residual risk register but not actively remediated unless they enable a Critical or High issue (per discovery-discipline guidance)
- **Vulnerabilities in third-party services** (Google OAuth, Google reCAPTCHA, AWS S3, MongoDB Atlas, etc.) — please report these to the relevant vendor
- **Self-XSS, MIME sniffing on routes that already set `nosniff`, missing best-practice headers on routes intentionally configured to relax them, and findings that require physical access to the server** are typically not in scope

If you are unsure whether a finding is in scope, **please report it anyway** — we would rather see a borderline report than miss a real issue.

## Security Updates

Security advisories and release notes are published in:

- [CHANGELOG.md](CHANGELOG.md) — version-tagged security release entries with CVE cross-references
- [GitHub Security Advisories](https://github.com/trinketapp/trinket-oss/security/advisories) on this repository
- The release notes for each tagged version on the [Releases](https://github.com/trinketapp/trinket-oss/releases) page

Operators are strongly encouraged to subscribe to repository releases (via GitHub's "Watch → Custom → Releases" option) and review [CHANGELOG.md](CHANGELOG.md) regularly.

### Recent Security Remediation

The most recent comprehensive security remediation addressed:

- **Dependency CVEs** — Critical and High severity npm package vulnerabilities resolved across the root `package.json` and each `serverside/*/manager/package.json`; the deprecated `request` package was replaced at its single use site
- **Cryptographic hardening** — MD5 → SHA-256 in course invitation tokens; boot-time entropy guard added for `app.mail.secret`; SHA-1 identifier uses annotated inline as non-confidential per OWASP A02
- **reCAPTCHA fail-closed posture** — explicit operator warning logged when reCAPTCHA is unconfigured (fail-open behavior preserved per the graceful-degradation contract, but no longer silent)
- **HTTP security headers** — `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, and `Referrer-Policy: strict-origin-when-cross-origin` added to main application responses; `X-Frame-Options: deny` extended to admin paths
- **CSRF synchronizer tokens** — `@hapi/crumb` registered and applied to the highest-risk mutating endpoints (`/api/exports`, password/email change in `/api/users`, `/api/admin/*`)
- **Container hardening** — shell-tier hardening directives (`mem_limit`, `pids_limit`, `read_only`, `tmpfs`, `no-new-privileges`, `cap_drop: [ALL]`) promoted from operator-opt-in to default-on in `serverside/docker-compose.yml`
- **EOL runtime** — main application Docker base image upgraded from `node:16-bullseye` (EOL September 2023) to `node:20-bullseye` LTS
- **nginx hardening** — `server_tokens off` and `X-Content-Type-Options: nosniff` added to the gateway configuration in `serverside/nginx/nginx.conf`
- **Automated security testing** — new Mocha-based regression suite under `test/security/` (auth, access control, injection, session, upload) and a CI pipeline integrating `npm audit`, Trivy, and ESLint security plugin

See [CHANGELOG.md](CHANGELOG.md) for full version-tagged details and CVE cross-references.

## Acknowledgments

We thank the security researchers who have responsibly disclosed vulnerabilities to us. As reports are remediated, contributors who consent to public credit will be listed below.

*(Hall of Fame — placeholder; populated as researchers report findings and consent to acknowledgment.)*

Contributions to security testing, hardening, and disclosure best practices are also welcomed via the standard contribution process documented in [CONTRIBUTING.md](CONTRIBUTING.md). Please use the private security channel above for vulnerability reports rather than the public contribution flow.

---

*This policy is reviewed and updated alongside each major security remediation cycle. Last reviewed: see the most recent commit modifying this file.*
